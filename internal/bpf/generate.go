package bpf

// bpf2go is a build-time tool, not a runtime dependency, so it is not in
// vendor/ (only the packages the daemon imports are). With a vendor
// directory present Go defaults to -mod=vendor and `go run` of the tool
// fails with "cannot find module providing package ...bpf2go", so
// `make ebpf` / the CI "eBPF objects match source" job never got as far as
// regenerating. -mod=mod resolves the tool from go.mod's pinned
// github.com/cilium/ebpf version (go.sum already holds its hashes, so
// go.mod and go.sum are left untouched); it needs network access.
//go:generate go run -mod=mod github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/bpf" bpf xdp_filter.c
