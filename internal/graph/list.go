package graph

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/lcleveland/microsoft-directory-mcp/internal/paging"
)

// Params are a list's OData options, from a tool's filter, query, sort and
// fields arguments.
type Params struct {
	Filter string   `json:"filter,omitempty"` // $filter, passed through
	Query  string   `json:"query,omitempty"`  // $search on displayName and mail
	Sort   string   `json:"sort,omitempty"`   // $orderby
	Fields []string `json:"fields,omitempty"` // $select
	Expand string   `json:"-"`                // $expand, fixed by the action
	// Shape, if set, cuts each item before the page caps count it: for
	// collections that refuse $select.
	Shape func(map[string]any) map[string]any `json:"-"`
}

var (
	literal = regexp.MustCompile(`'(?:[^']|'')*'`)
	// Filter operators that need advanced query parameters.
	advancedOp = regexp.MustCompile(`(?i)\b(?:ne|not)\b|\bendswith\s*\(|/\$count\b`)
)

// encode returns the query parameters and whether ConsistencyLevel:
// eventual must go with them. ne, not, endsWith, /$count, and $filter with
// $orderby need the header and $count=true; $search needs only the header.
func (p Params) encode() (url.Values, bool) {
	q := url.Values{}
	for k, v := range map[string]string{"$filter": p.Filter, "$orderby": p.Sort, "$select": strings.Join(p.Fields, ","), "$expand": p.Expand} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if p.Query != "" {
		s := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p.Query)
		q.Set("$search", `"displayName:`+s+`" OR "mail:`+s+`"`)
	}
	advanced := advancedOp.MatchString(literal.ReplaceAllString(p.Filter, "''")) || p.Filter != "" && p.Sort != ""
	if advanced {
		q.Set("$count", "true")
	}
	return q, advanced || p.Query != ""
}

// url appends p's query to path, and says whether ConsistencyLevel:
// eventual goes with it: when p needs it, or path counts.
func (p Params) url(path string) (string, bool) {
	q, eventual := p.encode()
	if len(q) > 0 {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		// Encode writes spaces as +; OData wants %20.
		path += sep + strings.ReplaceAll(q.Encode(), "+", "%20")
	}
	return path, eventual || strings.Contains(path, "$count")
}

// Object GETs the object at path with p's $select and $expand into out.
func (c *Client) Object(ctx context.Context, path string, p Params, out any) error {
	u, eventual := p.url(c.graphURL + path)
	b, err := c.send(ctx, http.MethodGet, u, eventual, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Page is one page of a list, shaped like an AD search page.
type Page struct {
	Results    []map[string]any   `json:"results"`
	NextCursor string             `json:"next_cursor,omitempty"`
	Truncation *paging.Truncation `json:"_truncation,omitempty"`
}

// cursor is where the next page starts: a page URL (the first, or an
// @odata.nextLink verbatim), how many of its items were already returned,
// and whether the ConsistencyLevel header goes with it. Key binds it to
// the list that returned it.
type cursor struct {
	URL      string `json:"u"`
	Skip     int    `json:"s,omitempty"`
	Eventual bool   `json:"e,omitempty"`
	Key      string `json:"k"`
}

func listKey(path string, p Params) string {
	b, _ := json.Marshal([]any{path, p})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// encodeCursor signs cur with the process's cursor key, so a caller can't
// forge one that points at another Graph path. Cursors die on restart.
func (c *Client) encodeCursor(cur cursor) string {
	b, _ := json.Marshal(cur)
	mac := hmac.New(sha256.New, c.cursorKey)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// decodeCursor checks s's signature, that it belongs to key, and that its
// URL is on the Graph host, so a cursor can't send the token elsewhere.
func (c *Client) decodeCursor(s, key string) (cursor, error) {
	var cur cursor
	body, sig, _ := strings.Cut(s, ".")
	b, err := base64.RawURLEncoding.DecodeString(body)
	got, err2 := base64.RawURLEncoding.DecodeString(sig)
	mac := hmac.New(sha256.New, c.cursorKey)
	mac.Write(b)
	if err != nil || err2 != nil || !hmac.Equal(got, mac.Sum(nil)) || json.Unmarshal(b, &cur) != nil || cur.Key != key || cur.Skip < 0 {
		return cur, paging.ErrForeignCursor
	}
	u, err := url.Parse(cur.URL)
	g, _ := url.Parse(c.graphURL)
	if err != nil || u.Scheme != g.Scheme || u.Host != g.Host {
		return cur, errors.New("cursor does not point at the Graph host; pass next_cursor unchanged")
	}
	return cur, nil
}

// List returns one page of the collection at path (e.g. "/v1.0/users"): the
// first when cursor is "", else the page that cursor names. Pages are
// capped at paging.Size items and paging.Bytes. A Graph page larger than
// that is returned in parts, its URL re-fetched for each.
// ponytail: re-fetches an over-large Graph page per part; pass $top in path where the API allows it.
func (c *Client) List(ctx context.Context, path string, p Params, cursorIn string) (*Page, error) {
	page, _, err := c.Fetch(ctx, path, p, cursorIn)
	return page, err
}

// Fetch is List for a path that may not be a collection: a reply without a
// value array of objects comes back whole as obj, with page nil.
func (c *Client) Fetch(ctx context.Context, path string, p Params, cursorIn string) (page *Page, obj any, err error) {
	key := listKey(path, p)
	cur := cursor{Key: key}
	if cursorIn != "" {
		if cur, err = c.decodeCursor(cursorIn, key); err != nil {
			return nil, nil, err
		}
	} else {
		cur.URL, cur.Eventual = p.url(c.graphURL + path)
	}
	b, err := c.send(ctx, http.MethodGet, cur.URL, cur.Eventual, nil)
	if err != nil {
		return nil, nil, err
	}
	var body struct {
		Value    json.RawMessage `json:"value"`
		NextLink string          `json:"@odata.nextLink"`
	}
	var items []map[string]any
	if json.Unmarshal(b, &body) != nil || json.Unmarshal(body.Value, &items) != nil || items == nil {
		err = json.Unmarshal(b, &obj)
		return nil, obj, err
	}
	rest := items[min(cur.Skip, len(items)):]
	if p.Shape != nil {
		for i, r := range rest {
			rest[i] = p.Shape(r)
		}
	}
	kept, trunc := paging.Trim(rest[:min(len(rest), paging.Size)])
	page = &Page{Results: append([]map[string]any{}, rest[:kept]...), Truncation: trunc}
	switch {
	case kept < len(rest):
		cur.Skip += kept
		page.NextCursor = c.encodeCursor(cur)
	case body.NextLink != "":
		cur.URL, cur.Skip = body.NextLink, 0
		page.NextCursor = c.encodeCursor(cur)
	}
	return page, nil, nil
}
