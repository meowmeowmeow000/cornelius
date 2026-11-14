package scanner

import (
	"reflect"
	"testing"
)

func TestExpandCIDRIncludesIPv4NetworkAndBroadcast(t *testing.T) {
	got, err := ExpandCIDR("192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandCIDR() = %v, want %v", got, want)
	}
}

func TestExpandCIDRIPv6(t *testing.T) {
	got, err := ExpandCIDR("2001:db8::/126")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExpandCIDR() = %v, want %v", got, want)
	}
}

func TestExpandCIDRRejectsOversizedRange(t *testing.T) {
	if _, err := ExpandCIDR("192.0.2.0/23"); err == nil {
		t.Fatal("expected oversized CIDR to be rejected")
	}
}

func TestExpandCIDRHandlesSingleAddressRanges(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		want []string
	}{
		{"192.0.2.10/32", []string{"192.0.2.10"}},
		{"2001:db8::1/128", []string{"2001:db8::1"}},
		{"192.0.2.0/31", []string{"192.0.2.0", "192.0.2.1"}},
	} {
		got, err := ExpandCIDR(tc.cidr)
		if err != nil {
			t.Fatalf("ExpandCIDR(%q) returned error: %v", tc.cidr, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("ExpandCIDR(%q) = %v, want %v", tc.cidr, got, tc.want)
		}
	}
}
