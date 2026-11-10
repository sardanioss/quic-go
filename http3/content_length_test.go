package http3

import (
	"slices"
	"strings"
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/http/httptest"
)

// headerNames encodes a request and returns its non-pseudo field names in wire
// order, with the content-length field written as "content-length=<value>".
func headerNames(t *testing.T, rw *requestWriter, method string, header http.Header, order []string, contentLength int64) []string {
	t.Helper()
	req := httptest.NewRequest(method, "https://example.com/", nil)
	req.Header = header
	if order != nil {
		req.Header[http.HeaderOrderKey] = order
	}
	hfs, err := rw.encodeHeaders(req, false, "", contentLength, true)
	if err != nil {
		t.Fatalf("encodeHeaders: %v", err)
	}
	var got []string
	for _, hf := range hfs {
		switch {
		case strings.HasPrefix(hf.Name, ":"):
		case hf.Name == "content-length":
			got = append(got, "content-length="+hf.Value)
		default:
			got = append(got, hf.Name)
		}
	}
	return got
}

// Browsers do not put content-length last: Chrome sends it before every other
// header and Safari after sec-fetch-dest. The order list names its slot, as it
// does on HTTP/2; the value is the body's length, whatever the caller set.
func TestContentLengthTakesItsSlotInTheHeaderOrder(t *testing.T) {
	header := func() http.Header {
		return http.Header{"user-agent": {"ua"}, "accept": {"*/*"}, "content-type": {"application/json"}}
	}
	for _, tc := range []struct {
		name   string
		header http.Header
		order  []string
		want   []string
	}{
		{"first", header(), []string{"content-length", "user-agent", "accept", "content-type"}, []string{"content-length=7", "user-agent", "accept", "content-type"}},
		{"between", header(), []string{"user-agent", "Content-Length", "accept", "content-type"}, []string{"user-agent", "content-length=7", "accept", "content-type"}},
		{"not named", header(), []string{"user-agent", "accept", "content-type"}, []string{"user-agent", "accept", "content-type", "content-length=7"}},
		{"named twice", header(), []string{"content-length", "user-agent", "content-length", "accept", "content-type"}, []string{"content-length=7", "user-agent", "accept", "content-type"}},
		{"no order", header(), nil, []string{"accept", "content-type", "user-agent", "content-length=7"}},
		{
			"the caller's is not sent",
			http.Header{"user-agent": {"ua"}, "Content-Length": {"99"}},
			[]string{"content-length", "user-agent"},
			[]string{"content-length=7", "user-agent"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := headerNames(t, newRequestWriter(), http.MethodPost, tc.header, tc.order, 7)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("fields = %v, want %v", got, tc.want)
			}
		})
	}

	// A slot is not a promise: a request that declares no length leaves it empty.
	got := headerNames(t, newRequestWriter(), http.MethodGet, http.Header{"user-agent": {"ua"}}, []string{"content-length", "user-agent"}, 0)
	if want := []string{"user-agent"}; !slices.Equal(got, want) {
		t.Fatalf("GET fields = %v, want %v", got, want)
	}
}

// Which methods say "content-length: 0" with no body is the transport's to
// choose: net/http's three unless it names its own.
func TestZeroContentLengthMethods(t *testing.T) {
	methods := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	for _, tc := range []struct {
		name string
		zero []string
		want []string
	}{
		{"net/http's, when unset", nil, []string{"POST", "PUT", "PATCH"}},
		{"Chrome's", []string{"POST", "PUT"}, []string{"POST", "PUT"}},
		{"Safari's", []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}},
		{"none", []string{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := newRequestWriter()
			rw.zeroContentLengthMethods = tc.zero
			var declared []string
			for _, method := range methods {
				if slices.Contains(headerNames(t, rw, method, http.Header{"user-agent": {"ua"}}, nil, 0), "content-length=0") {
					declared = append(declared, method)
				}
			}
			if !slices.Equal(declared, tc.want) {
				t.Fatalf("methods declaring an empty body = %v, want %v", declared, tc.want)
			}
			// A body of known length is declared on any method, and one of
			// unknown length on none.
			for _, method := range methods {
				if got := headerNames(t, rw, method, http.Header{"user-agent": {"ua"}}, nil, 3); !slices.Contains(got, "content-length=3") {
					t.Fatalf("%s with a 3-byte body: fields = %v", method, got)
				}
				if got := headerNames(t, rw, method, http.Header{"user-agent": {"ua"}}, nil, -1); len(got) != 1 {
					t.Fatalf("%s with a body of unknown length: fields = %v", method, got)
				}
			}
		})
	}
}
