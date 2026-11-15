package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLastGoodRingRecordDedupesAndCaps(t *testing.T) {
	ring := &LastGoodRing{Carrier: CarrierWorkerWS}
	for i := 0; i < 10; i++ {
		ring.Record("203.0.113." + string(rune('0'+i)))
	}
	if len(ring.Peers) != LastGoodCap {
		t.Fatalf("ring has %d peers, want cap %d", len(ring.Peers), LastGoodCap)
	}
	// Newest first.
	if ring.Peers[0] != "203.0.113.9" {
		t.Errorf("newest peer = %q, want 203.0.113.9", ring.Peers[0])
	}
	// Re-recording an old peer moves it to the front without duplicating.
	ring.Record("203.0.113.2")
	if ring.Peers[0] != "203.0.113.2" {
		t.Errorf("re-recorded peer = %q, want it first", ring.Peers[0])
	}
	if len(ring.Peers) != LastGoodCap {
		t.Errorf("ring has %d peers after re-record, want still %d", len(ring.Peers), LastGoodCap)
	}
	seen := map[string]bool{}
	for _, p := range ring.Peers {
		if seen[p] {
			t.Errorf("duplicate peer %q in ring", p)
		}
		seen[p] = true
	}
	ring.Record("")
	if len(ring.Peers) != LastGoodCap {
		t.Errorf("empty record changed the ring")
	}
}

func TestLastGoodSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lastgood.json")
	ring := &LastGoodRing{Carrier: CarrierWorkerWS}
	ring.Record("198.51.100.1")
	ring.Record("198.51.100.2")
	if err := ring.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded := LoadLastGood(path)
	if !reflect.DeepEqual(loaded.Peers, []string{"198.51.100.2", "198.51.100.1"}) {
		t.Fatalf("loaded peers = %v, want [198.51.100.2 198.51.100.1]", loaded.Peers)
	}
	if loaded.Carrier != CarrierWorkerWS {
		t.Fatalf("loaded carrier = %q, want %q", loaded.Carrier, CarrierWorkerWS)
	}
}

func TestLoadLastGoodToleratesBadFiles(t *testing.T) {
	// Missing file → empty ring, no error.
	if ring := LoadLastGood(filepath.Join(t.TempDir(), "nope.json")); len(ring.Peers) != 0 {
		t.Errorf("missing file gave %d peers, want 0", len(ring.Peers))
	}
	// Corrupt file → empty ring, no error.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if ring := LoadLastGood(bad); len(ring.Peers) != 0 {
		t.Errorf("corrupt file gave %d peers, want 0", len(ring.Peers))
	}
	// Wrong carrier → empty ring (gateways proved on one carrier are
	// never reused on another).
	other := filepath.Join(dir, "other.json")
	if err := os.WriteFile(other, []byte(`{"carrier":"vps-direct","peers":["198.51.100.1"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if ring := LoadLastGood(other); len(ring.Peers) != 0 {
		t.Errorf("wrong-carrier file gave %v, want empty", ring.Peers)
	}
	// Empty path → empty ring.
	if ring := LoadLastGood(""); len(ring.Peers) != 0 {
		t.Errorf("empty path gave %d peers, want 0", len(ring.Peers))
	}
}

func TestLastGoodPath(t *testing.T) {
	if got := LastGoodPath("configs/combat.profile"); got != filepath.Join("configs", "lastgood.json") {
		t.Errorf("LastGoodPath = %q", got)
	}
	if got := LastGoodPath(""); got != "" {
		t.Errorf("LastGoodPath(\"\") = %q, want \"\"", got)
	}
}

func TestSeedTargets(t *testing.T) {
	ring := &LastGoodRing{Carrier: CarrierWorkerWS, Peers: []string{"198.51.100.1", "198.51.100.2"}}
	got := SeedTargets(ring, []string{"198.51.100.2", "198.51.100.3", "198.51.100.4"})
	want := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SeedTargets = %v, want %v", got, want)
	}
	// Nil ring → targets unchanged.
	if got := SeedTargets(nil, []string{"198.51.100.9"}); !reflect.DeepEqual(got, []string{"198.51.100.9"}) {
		t.Fatalf("SeedTargets(nil) = %v", got)
	}
}
