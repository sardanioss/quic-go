package http3

import (
	"strings"
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/http/httptest"
)

// fieldsInOrder encodes a request and returns its non-pseudo fields in wire
// order as "name: value" strings. encodeHeaders builds the qlog field list from
// the same enumeration it hands to the QPACK encoder, so the list is the wire
// order.
func fieldsInOrder(t *testing.T, header http.Header, order []string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header = header
	req.Header[http.HeaderOrderKey] = order

	hfs, err := newRequestWriter().encodeHeaders(req, false, "", 0, true)
	if err != nil {
		t.Fatalf("encodeHeaders: %v", err)
	}
	var got []string
	for _, hf := range hfs {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		got = append(got, hf.Name+": "+hf.Value)
	}
	return got
}

func wantFields(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("fields =\n  %v\nwant\n  %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fields =\n  %v\nwant\n  %v", got, want)
		}
	}
}

// A map cannot hold position, so the order list is what carries it. One slot
// per name meant a repeated name emitted all of its values at its first slot,
// which hoists the second cookie up next to the first and loses the accept that
// sat between them in the capture being replayed.
func TestH3RepeatedNameGetsOneSlotPerValue(t *testing.T) {
	got := fieldsInOrder(t,
		http.Header{"cookie": {"a=1", "b=2"}, "accept": {"*/*"}, "user-agent": {"ua"}},
		[]string{"cookie", "accept", "cookie", "user-agent"})
	wantFields(t, got, []string{"cookie: a=1", "accept: */*", "cookie: b=2", "user-agent: ua"})
}

// The single-slot form has to keep emitting every value, because that is what
// every ordinary caller produces: a preset's order list is deduplicated, so a
// name never appears twice on that path.
func TestH3OneSlotStillEmitsEveryValue(t *testing.T) {
	got := fieldsInOrder(t,
		http.Header{"cookie": {"a=1", "b=2"}, "accept": {"*/*"}, "user-agent": {"ua"}},
		[]string{"cookie", "accept", "user-agent"})
	wantFields(t, got, []string{"cookie: a=1", "cookie: b=2", "accept: */*", "user-agent: ua"})
}

// Fewer slots than values must not drop one. The last slot takes the rest.
func TestH3LastSlotTakesTheRemainder(t *testing.T) {
	got := fieldsInOrder(t,
		http.Header{"x-a": {"1", "2", "3"}, "x-b": {"z"}, "user-agent": {"ua"}},
		[]string{"x-a", "x-b", "x-a", "user-agent"})
	wantFields(t, got, []string{"x-a: 1", "x-b: z", "x-a: 2", "x-a: 3", "user-agent: ua"})
}

// More slots than values emits nothing for the surplus rather than repeating
// the last value or panicking on the index.
func TestH3SurplusSlotsEmitNothing(t *testing.T) {
	got := fieldsInOrder(t,
		http.Header{"x-a": {"1"}, "x-b": {"z"}, "user-agent": {"ua"}},
		[]string{"x-a", "x-b", "x-a", "user-agent"})
	wantFields(t, got, []string{"x-a: 1", "x-b: z", "user-agent: ua"})
}

// Two casings of one name are two map entries. Resolving canonical-first, or by
// fold alone over a randomised map iteration, pointed both slots at one entry.
func TestH3TwoCasingsResolveToTheirOwnEntries(t *testing.T) {
	for i := 0; i < 20; i++ {
		got := fieldsInOrder(t,
			http.Header{"Cookie": {"upper"}, "cookie": {"lower"}, "user-agent": {"ua"}},
			[]string{"cookie", "Cookie", "user-agent"})
		wantFields(t, got, []string{"cookie: lower", "cookie: upper", "user-agent: ua"})
	}
}
