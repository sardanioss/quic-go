package http3

import (
	"encoding/hex"
	"testing"
)

// The QPACK encoder and decoder streams have to carry more than their type
// byte.
//
// A server tests the encoder stream by advertising any non-zero
// SETTINGS_QPACK_MAX_TABLE_CAPACITY and reading what comes back: a real client
// answers with Set Dynamic Table Capacity, because quiche wires the setting
// into SetDynamicTableCapacity, which calls SendSetDynamicTableCapacity
// unconditionally. It tests the decoder stream by pushing one Insert With
// Literal Name and serving one response: a real client emits an Insert Count
// Increment even without referencing the entry, because quiche sends it
// outside the required-insert-count guard.
//
// Both streams used to carry their type byte and then not one further byte for
// the life of the connection. Measured total payload after the type byte: 0.

func TestQPACKPrefixedIntEncoding(t *testing.T) {
	for _, tc := range []struct {
		name       string
		prefixBits uint8
		pattern    byte
		value      uint64
		want       string
	}{
		// Set Dynamic Table Capacity: 001xxxxx, 5-bit prefix.
		{"capacity 0", 5, 0x20, 0, "20"},
		{"capacity 30", 5, 0x20, 30, "3e"},
		{"capacity 31 needs a continuation", 5, 0x20, 31, "3f00"},
		{"capacity 4096", 5, 0x20, 4096, "3fe11f"},
		{"capacity 65536", 5, 0x20, 65536, "3fe1ff03"},
		// Insert Count Increment: 00xxxxxx, 6-bit prefix.
		{"increment 1", 6, 0x00, 1, "01"},
		{"increment 62", 6, 0x00, 62, "3e"},
		{"increment 63 needs a continuation", 6, 0x00, 63, "3f00"},
		{"increment 200", 6, 0x00, 200, "3f89 01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ""
			for _, r := range tc.want {
				if r != ' ' {
					want += string(r)
				}
			}
			got := hex.EncodeToString(appendQPACKPrefixedInt(nil, tc.prefixBits, tc.pattern, tc.value))
			if got != want {
				t.Fatalf("appendQPACKPrefixedInt(%d bits, %#02x, %d) = %s, want %s",
					tc.prefixBits, tc.pattern, tc.value, got, want)
			}
		})
	}
}

// The high bits identify the instruction, and getting them wrong turns a
// capacity update into something else entirely on the wire.
func TestQPACKInstructionPatterns(t *testing.T) {
	capacity := appendQPACKPrefixedInt(nil, 5, 0x20, 4096)
	if capacity[0]&0xe0 != 0x20 {
		t.Errorf("Set Dynamic Table Capacity starts %#02x; RFC 9204 4.3.1 requires 001xxxxx", capacity[0])
	}
	increment := appendQPACKPrefixedInt(nil, 6, 0x00, 3)
	if increment[0]&0xc0 != 0x00 {
		t.Errorf("Insert Count Increment starts %#02x; RFC 9204 4.4.3 requires 00xxxxxx", increment[0])
	}
	// Neither may be mistaken for a Section Acknowledgment (1xxxxxxx) or a
	// Stream Cancellation (01xxxxxx).
	if increment[0]&0x80 != 0 || increment[0]&0x40 != 0 {
		t.Errorf("Insert Count Increment %#02x collides with another decoder instruction", increment[0])
	}
}

// The capacity we answer with is bounded however much the peer offers.
func TestQPACKTableCapacityIsBounded(t *testing.T) {
	if maxQPACKEncoderTableCapacity != 64<<10 {
		t.Fatalf("maxQPACKEncoderTableCapacity = %d, want 65536", maxQPACKEncoderTableCapacity)
	}
}
