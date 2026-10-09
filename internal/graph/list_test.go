package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// graphStub serves the token endpoint and hands every Graph call to h.
// Waits are recorded, not slept.
func graphStub(t *testing.T, h http.HandlerFunc) (*Client, *[]time.Duration) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+tenant+"/oauth2/v2.0/token" {
			io.WriteString(w, `{"expires_in":3599,"access_token":"tok"}`)
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	c := newClient(t, ts.URL, ts.URL)
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	return c, &waits
}

func TestAdvancedQueryRules(t *testing.T) {
	for _, tc := range []struct {
		p               Params
		eventual        bool
		count           bool
		search, select_ string
	}{
		{p: Params{}},
		{p: Params{Filter: "accountEnabled eq true"}},
		{p: Params{Filter: "startsWith(displayName,'a')", Fields: []string{"id", "mail"}}, select_: "id,mail"},
		{p: Params{Sort: "displayName"}},
		{p: Params{Filter: "accountEnabled ne true"}, eventual: true, count: true},
		{p: Params{Filter: "not(accountEnabled eq true)"}, eventual: true, count: true},
		{p: Params{Filter: "endsWith(mail,'@example.com')"}, eventual: true, count: true},
		{p: Params{Filter: "assignedLicenses/$count eq 0"}, eventual: true, count: true},
		{p: Params{Filter: "accountEnabled eq true", Sort: "displayName"}, eventual: true, count: true},
		// Operators inside a string literal don't count.
		{p: Params{Filter: "displayName eq 'not ne endsWith(x) it''s'"}},
		{p: Params{Filter: "notes eq 'x'"}},
		// $search needs only the header.
		{p: Params{Query: `ada "x"`}, eventual: true, search: `"displayName:ada \"x\"" OR "mail:ada \"x\""`},
	} {
		q, ev := tc.p.encode()
		if ev != tc.eventual || (q.Get("$count") == "true") != tc.count || q.Get("$search") != tc.search || q.Get("$select") != tc.select_ {
			t.Errorf("%+v: eventual %v query %v", tc.p, ev, q)
		}
		if q.Get("$filter") != tc.p.Filter || q.Get("$orderby") != tc.p.Sort {
			t.Errorf("%+v: not passed through: %v", tc.p, q)
		}
	}
}

func TestListFollowsNextLinkWithHeader(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var c *Client
	c, _ = graphStub(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("ConsistencyLevel")+" "+r.URL.RawQuery)
		mu.Unlock()
		if r.URL.Query().Get("$skiptoken") == "" {
			fmt.Fprintf(w, `{"value":[{"id":"1"},{"id":"2"}],"@odata.nextLink":"http://%s/v1.0/users?$skiptoken=p2"}`, r.Host)
			return
		}
		io.WriteString(w, `{"value":[{"id":"3"}]}`)
	})
	p := Params{Query: "ada", Fields: []string{"id"}}
	first, err := c.List(context.Background(), "/v1.0/users", p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Results) != 2 || first.NextCursor == "" {
		t.Fatalf("first page %+v", first)
	}
	second, err := c.List(context.Background(), "/v1.0/users", p, first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Results) != 1 || second.Results[0]["id"] != "3" || second.NextCursor != "" {
		t.Errorf("second page %+v", second)
	}
	for _, s := range seen {
		if !strings.HasPrefix(s, "eventual ") {
			t.Errorf("ConsistencyLevel not re-sent: %q", s)
		}
	}
	if !strings.Contains(seen[0], "%20OR%20") {
		t.Errorf("spaces not %%20-encoded: %s", seen[0])
	}

	// Other arguments with this cursor are refused.
	if _, err := c.List(context.Background(), "/v1.0/groups", p, first.NextCursor); err == nil {
		t.Error("cursor accepted for another path")
	}
}

func TestCursorHostTamperingRejected(t *testing.T) {
	calls := 0
	c, _ := graphStub(t, func(w http.ResponseWriter, r *http.Request) { calls++ })
	key := listKey("/v1.0/users", Params{})
	for _, u := range []string{"https://evil.example.com/v1.0/users?$skiptoken=x", "ftp://" + strings.TrimPrefix(c.graphURL, "http://") + "/v1.0/users"} {
		_, err := c.List(context.Background(), "/v1.0/users", Params{}, c.encodeCursor(cursor{URL: u, Key: key}))
		if err == nil || !strings.Contains(err.Error(), "host") {
			t.Errorf("%s: %v", u, err)
		}
	}
	if _, err := c.List(context.Background(), "/v1.0/users", Params{}, "not a cursor"); err == nil {
		t.Error("garbage cursor accepted")
	}
	if _, err := c.List(context.Background(), "/v1.0/users", Params{}, c.encodeCursor(cursor{URL: c.graphURL + "/v1.0/users", Skip: -1, Key: key})); err == nil {
		t.Error("negative skip accepted")
	}
	// An unsigned or re-signed cursor to another path is refused.
	b, _ := json.Marshal(cursor{URL: c.graphURL + "/v1.0/applications", Key: key})
	for _, forged := range []string{base64.RawURLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b) + ".AAAA"} {
		if _, err := c.List(context.Background(), "/v1.0/users", Params{}, forged); err == nil {
			t.Errorf("forged cursor %s accepted", forged)
		}
	}
	if calls != 0 {
		t.Errorf("%d calls to Graph", calls)
	}
}

func TestListCapsPageAndResumesWithinIt(t *testing.T) {
	var raw []string
	c, _ := graphStub(t, func(w http.ResponseWriter, r *http.Request) {
		raw = append(raw, r.URL.RawQuery)
		if r.URL.Query().Get("$skiptoken") != "" {
			io.WriteString(w, `{"value":[{"id":"last"}]}`)
			return
		}
		items := make([]string, 250)
		for i := range items {
			items[i] = fmt.Sprintf(`{"id":"%d"}`, i)
		}
		fmt.Fprintf(w, `{"value":[%s],"@odata.nextLink":"http://%s/v1.0/users?$skiptoken=p2"}`, strings.Join(items, ","), r.Host)
	})
	var ids []any
	cur := ""
	for range 3 {
		p, err := c.List(context.Background(), "/v1.0/users", Params{}, cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range p.Results {
			ids = append(ids, r["id"])
		}
		if cur = p.NextCursor; cur == "" {
			break
		}
	}
	if len(ids) != 251 || ids[0] != "0" || ids[200] != "200" || ids[250] != "last" || cur != "" {
		t.Errorf("%d ids, cursor %q", len(ids), cur)
	}
	if len(raw) != 3 || raw[0] != raw[1] {
		t.Errorf("requests %v", raw)
	}
}

func TestGetWaitsOut429(t *testing.T) {
	var urls []string
	c, waits := graphStub(t, func(w http.ResponseWriter, r *http.Request) {
		urls = append(urls, r.URL.String())
		if len(urls) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":{"code":"TooManyRequests","message":"slow down"}}`)
			return
		}
		io.WriteString(w, `{"value":[{"id":"1"}]}`)
	})
	p, err := c.List(context.Background(), "/v1.0/users", Params{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Results) != 1 || len(urls) != 2 || urls[0] != urls[1] || len(*waits) != 1 || (*waits)[0] != time.Second {
		t.Errorf("results %v urls %v waits %v", p.Results, urls, *waits)
	}
}

func Test429BeyondDeadlineOrCapNotWaited(t *testing.T) {
	after := "30"
	c, waits := graphStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", after)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ae *APIError
	if err := c.Get(ctx, "/v1.0/users", new(any)); !errors.As(err, &ae) || ae.Status != 503 || len(*waits) != 0 {
		t.Errorf("deadline: err %v waits %v", err, *waits)
	}
	after = "120"
	if err := c.Get(context.Background(), "/v1.0/users", new(any)); !errors.As(err, &ae) || ae.Status != 503 || len(*waits) != 0 {
		t.Errorf("cap: err %v waits %v", err, *waits)
	}
}

func TestWriteOn429NotRetried(t *testing.T) {
	calls := 0
	var body, ctype string
	c, waits := graphStub(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		body, ctype = string(b), r.Header.Get("Content-Type")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"code":"TooManyRequests","message":"slow down","innerError":{"request-id":"rid-1"}}}`)
	})
	err := c.Do(context.Background(), http.MethodPost, "/v1.0/users", map[string]bool{"accountEnabled": false}, nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 429 || ae.Code != "TooManyRequests" || ae.Message != "slow down" || !strings.Contains(err.Error(), "rid-1") {
		t.Errorf("err %v", err)
	}
	if calls != 1 || len(*waits) != 0 || body != `{"accountEnabled":false}` || ctype != "application/json" {
		t.Errorf("calls %d waits %v body %q type %q", calls, *waits, body, ctype)
	}
}
