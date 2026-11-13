package proxy

import "testing"

func TestSupportsNoAuth(t *testing.T) {
	tests := []struct {
		name    string
		methods []byte
		want    bool
	}{
		{name: "offered", methods: []byte{0x02, 0x00}, want: true},
		{name: "not offered", methods: []byte{0x02}, want: false},
		{name: "empty", methods: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := supportsNoAuth(tt.methods); got != tt.want {
				t.Fatalf("supportsNoAuth(%v) = %t, want %t", tt.methods, got, tt.want)
			}
		})
	}
}
