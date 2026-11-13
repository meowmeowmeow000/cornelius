package bpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"cornelius/internal/telemetry"
)

const (
	cfgIdxExpectedTTL  uint32 = 0
	cfgIdxTTLTolerance uint32 = 1
	cfgIdxLockdownMode uint32 = 2
	cfgIdxTargetPort   uint32 = 3
)

var (
	filterMu     sync.RWMutex
	ActiveFilter *XDPFilter
)

type XDPFilter struct {
	objs       *bpfObjects
	link       link.Link
	syncCancel context.CancelFunc
}

type flowKeyV4 struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

type flowKeyV6 struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
}

func AttachXDP(interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("lookup network iface %q: %w", interfaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.FilterDpiRst,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach XDP program: %w", err)
	}

	syncCtx, syncCancel := context.WithCancel(context.Background())

	filterMu.Lock()
	ActiveFilter = &XDPFilter{
		objs:       &objs,
		link:       l,
		syncCancel: syncCancel,
	}
	filterMu.Unlock()

	_ = UpdateXDPConfig(0, 4, false, 443)
	telemetry.RecordEvent("XDP", "info", fmt.Sprintf("Attached filter_dpi_rst on %s", interfaceName))

	go syncDropTelemetry(syncCtx)
	return nil
}

func syncDropTelemetry(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var last uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := GetDropCount()
			telemetry.XDPDroppedRSTs.Store(cur)
			if cur > last {
				telemetry.RecordEvent("XDP", "warn", fmt.Sprintf("Dropped +%d forged DPI RST/FIN packets", cur-last))
				last = cur
			}
		}
	}
}

func CloseXDP() {
	filterMu.Lock()
	f := ActiveFilter
	ActiveFilter = nil
	filterMu.Unlock()

	if f == nil {
		return
	}
	if f.syncCancel != nil {
		f.syncCancel()
	}
	if f.link != nil {
		_ = f.link.Close()
	}
	if f.objs != nil {
		_ = f.objs.Close()
	}
}

func UpdateXDPConfig(expectedTTL uint8, tolerance uint8, lockdown bool, targetPort ...uint16) error {
	filterMu.RLock()
	f := ActiveFilter
	filterMu.RUnlock()

	ttl32 := uint32(expectedTTL)
	tol32 := uint32(tolerance) + 1
	lock32 := uint32(0)
	if lockdown {
		lock32 = 1
	}
	port32 := uint32(443)
	if len(targetPort) > 0 && targetPort[0] > 0 {
		port32 = uint32(targetPort[0])
	}

	telemetry.CurrentExpectedTTL.Store(ttl32)
	telemetry.CurrentTTLTolerance.Store(uint32(tolerance))
	telemetry.CurrentLockdownMode.Store(lock32)

	if f == nil || f.objs == nil {
		return fmt.Errorf("XDP shield not attached; telemetry updated only")
	}

	if err := f.objs.XdpConfigMap.Update(cfgIdxExpectedTTL, &ttl32, 0); err != nil {
		return fmt.Errorf("update ExpectedTTL: %w", err)
	}
	if err := f.objs.XdpConfigMap.Update(cfgIdxTTLTolerance, &tol32, 0); err != nil {
		return fmt.Errorf("update TTLTolerance: %w", err)
	}
	if err := f.objs.XdpConfigMap.Update(cfgIdxLockdownMode, &lock32, 0); err != nil {
		return fmt.Errorf("update Lockdown: %w", err)
	}
	if err := f.objs.XdpConfigMap.Update(cfgIdxTargetPort, &port32, 0); err != nil {
		return fmt.Errorf("update TargetPort: %w", err)
	}
	return nil
}

func GetDropCount() uint64 {
	filterMu.RLock()
	f := ActiveFilter
	filterMu.RUnlock()

	if f == nil || f.objs == nil {
		return 0
	}

	numCPU, err := ebpf.PossibleCPU()
	if err != nil || numCPU <= 0 {
		return 0
	}

	perCPU := make([]uint64, numCPU)
	if err := f.objs.RstDropCounter.Lookup(uint32(0), &perCPU); err != nil {
		return 0
	}

	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

func LookupFlowTTL(localAddr, remoteAddr net.Addr) uint8 {
	filterMu.RLock()
	f := ActiveFilter
	filterMu.RUnlock()

	if f == nil || f.objs == nil {
		return 0
	}

	lTCP, ok1 := localAddr.(*net.TCPAddr)
	rTCP, ok2 := remoteAddr.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return 0
	}

	if r4 := rTCP.IP.To4(); r4 != nil {
		l4 := lTCP.IP.To4()
		if l4 == nil {
			return 0
		}
		key := flowKeyV4{
			SrcIP:   binary.NativeEndian.Uint32(r4),
			DstIP:   binary.NativeEndian.Uint32(l4),
			SrcPort: htons(uint16(rTCP.Port)),
			DstPort: htons(uint16(lTCP.Port)),
		}
		var ttl uint8
		if err := f.objs.ServerTtlMap.Lookup(&key, &ttl); err == nil {
			return ttl
		}
		return 0
	}

	r16 := rTCP.IP.To16()
	l16 := lTCP.IP.To16()
	if r16 == nil || l16 == nil {
		return 0
	}
	var key6 flowKeyV6
	copy(key6.SrcIP[:], r16)
	copy(key6.DstIP[:], l16)
	key6.SrcPort = htons(uint16(rTCP.Port))
	key6.DstPort = htons(uint16(lTCP.Port))

	var ttl uint8
	if err := f.objs.ServerTtlV6Map.Lookup(&key6, &ttl); err == nil {
		return ttl
	}
	return 0
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
