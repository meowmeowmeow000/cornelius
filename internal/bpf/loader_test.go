package bpf

import "testing"

// TestEmbeddedProgramLoads is the regression guard for the empty-artifact
// bug: the committed .o files were once 0 bytes, so a fresh clone had no
// XDP program at all and the daemon could not start with -i. This test
// parses the embedded program without touching the kernel (no privileges
// needed) and fails loudly if the artifacts are ever empty or stale
// again. Run `make ebpf` to regenerate them.
func TestEmbeddedProgramLoads(t *testing.T) {
	if err := ValidateEmbeddedProgram(); err != nil {
		t.Fatalf("embedded XDP program is unusable: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}
	if spec.Programs["filter_dpi_rst"] == nil {
		t.Fatal("embedded program has no 'filter_dpi_rst' program")
	}
	for _, name := range []string{"server_ttl_map", "server_ttl_v6_map", "rst_drop_counter", "xdp_config_map"} {
		if spec.Maps[name] == nil {
			t.Fatalf("embedded program is missing map %q", name)
		}
	}
}
