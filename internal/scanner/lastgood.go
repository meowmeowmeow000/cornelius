package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// The last-good ring remembers the gateways that worked, so the next scan
// tries them first instead of sweeping cold. Borrowed from Aether's
// lastconn ring (aether/src/lastconn.rs): cap 8, newest first, deduped,
// carrier-scoped — gateways proved on one carrier are never reused on
// another. Aether keeps no timestamps; reuse is by recency order, not
// age. Ours is JSON (the profile next door is JSON too); the file lives
// beside the combat.profile it seeds.
//
// Carrier is "worker-ws-smux": the WebSocket + SMUX tunnel to a
// Cloudflare Worker. If Cornelius ever gains another carrier (VPS,
// direct), it gets its own ring.
const (
	CarrierWorkerWS = "worker-ws-smux"
	LastGoodCap     = 8
	lastGoodFile    = "lastgood.json"
)

// LastGoodRing is the persisted ring. Peers are IP strings, newest first.
type LastGoodRing struct {
	Carrier string   `json:"carrier"`
	Peers   []string `json:"peers"`
}

// LastGoodPath returns the ring file path beside a combat.profile path,
// or "" when the profile path is empty.
func LastGoodPath(profilePath string) string {
	if profilePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(profilePath), lastGoodFile)
}

// LoadLastGood reads the ring. A missing or corrupt file, or a carrier
// mismatch, yields an empty ring — never an error. A stale cache must
// never break a scan.
func LoadLastGood(path string) *LastGoodRing {
	ring := &LastGoodRing{Carrier: CarrierWorkerWS}
	if path == "" {
		return ring
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ring
	}
	var loaded LastGoodRing
	if err := json.Unmarshal(data, &loaded); err != nil {
		return ring
	}
	if loaded.Carrier != CarrierWorkerWS {
		return ring
	}
	ring.Peers = dedupePeers(loaded.Peers)
	return ring
}

// Record prepends a peer to the ring (moving it to the front if already
// present) and caps the ring at LastGoodCap.
func (r *LastGoodRing) Record(peer string) {
	if peer == "" {
		return
	}
	if r.Carrier == "" {
		r.Carrier = CarrierWorkerWS
	}
	peers := []string{peer}
	for _, p := range r.Peers {
		if p != peer {
			peers = append(peers, p)
		}
	}
	if len(peers) > LastGoodCap {
		peers = peers[:LastGoodCap]
	}
	r.Peers = peers
}

// Save writes the ring as JSON, mode 0600 like the profile. The ring is
// a cache; callers ignore the error.
func (r *LastGoodRing) Save(path string) error {
	if path == "" {
		return nil
	}
	if r.Carrier == "" {
		r.Carrier = CarrierWorkerWS
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// SeedTargets returns ring peers first, then the given targets, deduped
// in order. The ring is tried before the cold sweep.
func SeedTargets(ring *LastGoodRing, targets []string) []string {
	if ring == nil {
		return targets
	}
	out := make([]string, 0, len(ring.Peers)+len(targets))
	seen := make(map[string]struct{})
	for _, p := range append(append([]string{}, ring.Peers...), targets...) {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func dedupePeers(peers []string) []string {
	out := make([]string, 0, len(peers))
	seen := make(map[string]struct{})
	for _, p := range peers {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) > LastGoodCap {
		out = out[:LastGoodCap]
	}
	return out
}
