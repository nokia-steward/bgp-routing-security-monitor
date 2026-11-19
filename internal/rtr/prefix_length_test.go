package rtr

import (
	"encoding/binary"
	"testing"
)

func TestPrefixPDULengthBounds(t *testing.T) {
	for _, tc := range []struct {
		name              string
		ipv6              bool
		prefixLen, maxLen byte
		withdraw, wantErr bool
	}{
		{"IPv4 default", false, 0, 32, false, false},
		{"IPv4 host", false, 32, 32, false, false},
		{"IPv4 normal", false, 24, 28, false, false},
		{"IPv4 withdrawal", false, 24, 24, true, false},
		{"IPv4 prefix too long", false, 33, 33, false, true},
		{"IPv4 max too long", false, 24, 33, false, true},
		{"IPv4 max below prefix", false, 24, 16, false, true},
		{"IPv4 invalid withdrawal", false, 33, 33, true, true},
		{"IPv6 default", true, 0, 128, false, false},
		{"IPv6 host", true, 128, 128, false, false},
		{"IPv6 length 33 is valid", true, 33, 64, false, false},
		{"IPv6 withdrawal", true, 64, 64, true, false},
		{"IPv6 prefix too long", true, 129, 129, false, true},
		{"IPv6 max too long", true, 64, 129, false, true},
		{"IPv6 max below prefix", true, 64, 32, false, true},
		{"IPv6 invalid withdrawal", true, 129, 129, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := 12
			if tc.ipv6 {
				n = 24
			}
			payload := make([]byte, n)
			if !tc.withdraw {
				payload[0] = 1
			}
			payload[1], payload[2] = tc.prefixLen, tc.maxLen
			binary.BigEndian.PutUint32(payload[n-4:], 64500)
			c := new(Client)
			if tc.ipv6 {
				vrp, withdraw, err := c.parseIPv6Prefix(payload)
				if (err != nil) != tc.wantErr {
					t.Fatalf("error=%v, wantErr=%v", err, tc.wantErr)
				}
				if !tc.wantErr && (!vrp.Prefix.IsValid() || vrp.Prefix.Bits() != int(tc.prefixLen) || vrp.MaxLength != tc.maxLen || vrp.ASN != 64500 || withdraw != tc.withdraw) {
					t.Fatalf("unexpected result: %+v, withdraw=%v", vrp, withdraw)
				}
			} else {
				vrp, withdraw, err := c.parseIPv4Prefix(payload)
				if (err != nil) != tc.wantErr {
					t.Fatalf("error=%v, wantErr=%v", err, tc.wantErr)
				}
				if !tc.wantErr && (!vrp.Prefix.IsValid() || vrp.Prefix.Bits() != int(tc.prefixLen) || vrp.MaxLength != tc.maxLen || vrp.ASN != 64500 || withdraw != tc.withdraw) {
					t.Fatalf("unexpected result: %+v, withdraw=%v", vrp, withdraw)
				}
			}
		})
	}
}
