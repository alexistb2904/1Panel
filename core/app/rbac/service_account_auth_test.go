package rbac

import "testing"

func TestSplitServiceToken(t *testing.T) {
	keyID, secret, ok := splitServiceToken("1ps_0123456789abcdef_0123456789abcdef0123456789abcdef")
	if !ok {
		t.Fatal("expected valid service token")
	}
	if keyID != "0123456789abcdef" || secret != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected token split: %s / %s", keyID, secret)
	}
	if _, _, ok := splitServiceToken("1ps_short_secret"); ok {
		t.Fatal("short token must be rejected")
	}
}

func TestServiceAccountIPAllowed(t *testing.T) {
	cases := []struct {
		ip, allow string
		want      bool
	}{
		{"203.0.113.8", "", true},
		{"203.0.113.8", "203.0.113.8", true},
		{"203.0.113.8", "203.0.113.0/24", true},
		{"203.0.114.8", "203.0.113.0/24", false},
		{"10.0.0.8", "192.0.2.10, 10.0.0.0/8", true},
	}
	for _, tc := range cases {
		if got := serviceAccountIPAllowed(tc.ip, tc.allow); got != tc.want {
			t.Fatalf("ip=%s allow=%q got=%v want=%v", tc.ip, tc.allow, got, tc.want)
		}
	}
}
