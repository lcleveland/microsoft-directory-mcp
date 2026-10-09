// Package paging holds the page caps and cursor rules both sides share.
package paging

import (
	"encoding/json"
	"errors"
)

// Size and Bytes cap one page of results.
const (
	Size  = 200
	Bytes = 60 << 10
)

// ErrForeignCursor is a cursor passed with arguments other than those that returned it.
var ErrForeignCursor = errors.New("cursor does not belong to this query; pass next_cursor only with the same arguments that returned it")

// Truncation says a page was cut to fit Bytes.
type Truncation struct {
	Returned int    `json:"returned"`
	Of       int    `json:"of"`
	Note     string `json:"note"`
}

// Trim returns how many leading results fit in Bytes (at least one),
// and the _truncation note when that is fewer than all.
func Trim(rs []map[string]any) (int, *Truncation) {
	if kept := fit(rs); kept < len(rs) {
		return kept, &Truncation{kept, len(rs), "page cut to fit 60 KiB; the rest come with next_cursor (pass fields for smaller entries)"}
	}
	return len(rs), nil
}

func fit(rs []map[string]any) int {
	total := 2 // []
	for i, r := range rs {
		b, _ := json.Marshal(r)
		if total += len(b) + 1; total > Bytes {
			return max(i, 1)
		}
	}
	return len(rs)
}
