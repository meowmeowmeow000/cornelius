package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type tickMsg time.Time

var (
	pulseFrames = []string{"◉", "◎", "●", "◎"}
	radarFrames = []string{"◜", "◠", "◝", "◞", "◡", "◟"}
)

func tickCmd() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type modalMode int

const (
	modalNone modalMode = iota
	modalInject
	modalScan
	modalHelp
)

type Model struct {
	sockPath      string
	width         int
	height        int
	themeIdx      int
	frameIdx      int
	pollMod       int
	startedAt     time.Time
	connected     bool
	lastErr       string
	pendingAction string

	snap           VitalSnapshot
	prevTxKB       uint64
	prevRxKB       uint64
	prevDrops      uint64
	hasPrev        bool
	lastSampleTime time.Time

	txHist   *RingBuffer
	rxHist   *RingBuffer
	dropHist *RingBuffer

	selectedRoute int

	modal      modalMode
	modalFocus int
	inputIP    string
	inputSpoof string
	inputSNI   string
	inputCIDR  string
}

func initialModel(sockPath string) Model {
	return Model{
		sockPath:  sockPath,
		width:     122,
		height:    30,
		startedAt: time.Now(),
		txHist:    NewRingBuffer(260),
		rxHist:    NewRingBuffer(260),
		dropHist:  NewRingBuffer(260),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), fetchStatusCmd(m.sockPath))
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.frameIdx++
		m.pollMod = (m.pollMod + 1) % 2
		if m.pollMod == 0 {
			return m, tea.Batch(tickCmd(), fetchStatusCmd(m.sockPath))
		}
		return m, tickCmd()

	case statusMsg:
		if msg.err != nil {
			m.connected = false
			m.lastErr = msg.err.Error()
			m.txHist.Push(0)
			m.rxHist.Push(0)
			m.dropHist.Push(0)
			return m, nil
		}

		m.connected = true
		m.lastErr = ""
		s := *msg.snap

		if m.hasPrev {
			dt := msg.at.Sub(m.lastSampleTime).Seconds()
			if dt <= 0.05 {
				dt = 0.4
			}
			var dTx, dRx, dDrops float64
			if s.TxKB >= m.prevTxKB {
				dTx = float64(s.TxKB-m.prevTxKB) / dt
			}
			if s.RxKB >= m.prevRxKB {
				dRx = float64(s.RxKB-m.prevRxKB) / dt
			}
			if s.XDPDroppedPkts >= m.prevDrops {
				dDrops = float64(s.XDPDroppedPkts-m.prevDrops) / dt
			}
			m.txHist.Push(dTx)
			m.rxHist.Push(dRx)
			m.dropHist.Push(dDrops)
		}

		m.snap = s
		if m.selectedRoute >= len(m.snap.FailoverRoutes) {
			m.selectedRoute = 0
		}
		m.prevTxKB = s.TxKB
		m.prevRxKB = s.RxKB
		m.prevDrops = s.XDPDroppedPkts
		m.lastSampleTime = msg.at
		m.hasPrev = true
		return m, nil

	case actionResultMsg:
		m.pendingAction = ""
		if msg.err != nil {
			m.lastErr = fmt.Sprintf("%s: %v", msg.label, msg.err)
		} else {
			m.lastErr = ""
		}
		return m, fetchStatusCmd(m.sockPath)

	case tea.KeyPressMsg:
		if m.modal == modalHelp {
			m.modal = modalNone
			return m, nil
		}
		if m.modal == modalInject {
			return m.handleInjectKey(msg)
		}
		if m.modal == modalScan {
			return m.handleScanKey(msg)
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "?":
			m.modal = modalHelp
			return m, nil

		case "m":
			m.themeIdx = (m.themeIdx + 1) % len(themes)
			return m, nil

		case "j", "down":
			if len(m.snap.FailoverRoutes) > 0 {
				m.selectedRoute = (m.selectedRoute + 1) % len(m.snap.FailoverRoutes)
			}
			return m, nil

		case "k", "up":
			if len(m.snap.FailoverRoutes) > 0 {
				m.selectedRoute = (m.selectedRoute - 1 + len(m.snap.FailoverRoutes)) % len(m.snap.FailoverRoutes)
			}
			return m, nil

		case "enter":
			if len(m.snap.FailoverRoutes) > 0 && m.selectedRoute < len(m.snap.FailoverRoutes) {
				chosen := m.snap.FailoverRoutes[m.selectedRoute]
				if chosen.TargetIP != "" && chosen.TargetIP != m.snap.ActiveRouteIP {
					m.pendingAction = fmt.Sprintf("Hot-swapping -> %s...", chosen.TargetIP)
					return m, dispatchControlCmd(m.sockPath, "inject_route", IPCCommand{
						Action:       "inject_route",
						Route:        chosen,
						TTLTolerance: uint8(m.snap.TTLTolerance),
						Lockdown:     m.snap.XDPLockdown,
					})
				}
			}
			return m, nil

		case "r":
			m.pendingAction = "Syncing..."
			return m, fetchStatusCmd(m.sockPath)

		case "e":
			nextMode, delay, jitter := nextStealthMode(m.snap.ActiveStealth)
			m.pendingAction = fmt.Sprintf("Stealth -> %s...", nextMode)
			return m, dispatchControlCmd(m.sockPath, "escalate_stealth", IPCCommand{
				Action:      "escalate_stealth",
				StealthMode: nextMode,
				FragDelayMs: delay,
				JitterMs:    jitter,
			})

		case "f":
			nextDir := "fronting"
			if m.snap.SNISPFDirection == "fronting" {
				nextDir = "legacy"
			}
			m.pendingAction = fmt.Sprintf("SNISPF -> %s...", nextDir)
			return m, dispatchControlCmd(m.sockPath, "set_snispf", IPCCommand{
				Action:          "set_snispf",
				SNISPFDirection: nextDir,
				SpoofSNI:        m.snap.ActiveSpoofSNI,
			})

		case "l":
			nextLock := !m.snap.XDPLockdown
			ttl := uint8(m.snap.ExpectedTTL)
			tol := uint8(m.snap.TTLTolerance)
			if tol == 0 {
				tol = 4
			}
			m.pendingAction = fmt.Sprintf("XDP lockdown=%v...", nextLock)
			return m, dispatchControlCmd(m.sockPath, "lockdown_xdp", IPCCommand{
				Action:       "lockdown_xdp",
				ExpectedTTL:  ttl,
				TTLTolerance: tol,
				Lockdown:     nextLock,
			})

		case "t":
			m.pendingAction = "Launching DPI hop radar..."
			return m, dispatchControlCmd(m.sockPath, "echolocate", IPCCommand{
				Action: "echolocate",
			})

		case "s":
			m.modal = modalScan
			m.modalFocus = 0
			m.inputCIDR = "104.18.2.0/28"
			m.inputSpoof = m.snap.ActiveSpoofSNI
			return m, nil

		case "i":
			m.modal = modalInject
			m.modalFocus = 0
			m.inputIP = m.snap.ActiveRouteIP
			m.inputSpoof = m.snap.ActiveSpoofSNI
			m.inputSNI = m.snap.ActiveSNI
			return m, nil
		}
	}

	return m, nil
}

func (m Model) handleInjectKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.modal = modalNone
		return m, nil
	case "tab", "down":
		m.modalFocus = (m.modalFocus + 1) % 3
		return m, nil
	case "up":
		m.modalFocus = (m.modalFocus + 2) % 3
		return m, nil
	case "backspace":
		switch m.modalFocus {
		case 0:
			if len(m.inputIP) > 0 {
				m.inputIP = m.inputIP[:len(m.inputIP)-1]
			}
		case 1:
			if len(m.inputSpoof) > 0 {
				m.inputSpoof = m.inputSpoof[:len(m.inputSpoof)-1]
			}
		case 2:
			if len(m.inputSNI) > 0 {
				m.inputSNI = m.inputSNI[:len(m.inputSNI)-1]
			}
		}
		return m, nil
	case "enter":
		ipStr := strings.TrimSpace(m.inputIP)
		spoofStr := strings.TrimSpace(m.inputSpoof)
		sniStr := strings.TrimSpace(m.inputSNI)
		if net.ParseIP(ipStr) == nil {
			m.lastErr = "invalid IP address"
			return m, nil
		}
		mode := m.snap.ActiveStealth
		if mode == "" {
			mode = "tls_micro_frag"
		}
		dir := m.snap.SNISPFDirection
		if dir == "" {
			if spoofStr != "" && spoofStr != sniStr {
				dir = "fronting"
			} else {
				dir = "legacy"
			}
		}
		m.modal = modalNone
		m.pendingAction = fmt.Sprintf("Injecting %s (%s)...", ipStr, dir)
		return m, dispatchControlCmd(m.sockPath, "inject_route", IPCCommand{
			Action: "inject_route",
			Route: RouteCandidate{
				TargetIP:        ipStr,
				SNISPFDirection: dir,
				SpoofSNI:        spoofStr,
				CleanSNI:        sniStr,
				StealthMode:     mode,
				ExpectedTTL:     uint8(m.snap.ExpectedTTL),
			},
			TTLTolerance: uint8(m.snap.TTLTolerance),
			Lockdown:     m.snap.XDPLockdown,
		})
	default:
		key := msg.String()
		if len(key) == 1 {
			switch m.modalFocus {
			case 0:
				m.inputIP += key
			case 1:
				m.inputSpoof += key
			case 2:
				m.inputSNI += key
			}
		}
		return m, nil
	}
}

func (m Model) handleScanKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.modal = modalNone
		return m, nil
	case "tab", "down", "up":
		m.modalFocus = (m.modalFocus + 1) % 2
		return m, nil
	case "backspace":
		if m.modalFocus == 0 && len(m.inputCIDR) > 0 {
			m.inputCIDR = m.inputCIDR[:len(m.inputCIDR)-1]
		} else if m.modalFocus == 1 && len(m.inputSpoof) > 0 {
			m.inputSpoof = m.inputSpoof[:len(m.inputSpoof)-1]
		}
		return m, nil
	case "enter":
		cidr := strings.TrimSpace(m.inputCIDR)
		spoof := strings.TrimSpace(m.inputSpoof)
		if cidr == "" {
			m.lastErr = "CIDR or IP list required"
			return m, nil
		}
		m.modal = modalNone
		m.pendingAction = fmt.Sprintf("Scanning %s...", cidr)
		return m, dispatchControlCmd(m.sockPath, "scan_cidr", IPCCommand{
			Action:   "scan_cidr",
			CIDR:     cidr,
			SpoofSNI: spoof,
		})
	default:
		key := msg.String()
		if len(key) == 1 {
			if m.modalFocus == 0 {
				m.inputCIDR += key
			} else {
				m.inputSpoof += key
			}
		}
		return m, nil
	}
}

func nextStealthMode(current string) (string, int, int) {
	switch current {
	case "tls_frag":
		return "tls_micro_frag", 3, 3
	case "tls_micro_frag":
		return "tls_disorder", 4, 4
	default:
		return "tls_frag", 1, 2
	}
}

func (m Model) View() tea.View {
	th := themes[m.themeIdx]
	w := m.width
	if w < 54 {
		w = 54
	}

	sTitle := lipgloss.NewStyle().Bold(true).Foreground(th.Accent)
	sLabel := lipgloss.NewStyle().Foreground(th.Muted)
	sVal := lipgloss.NewStyle().Bold(true).Foreground(th.Text)
	sKey := lipgloss.NewStyle().Bold(true).Foreground(th.Secondary)

	badgeOK := lipgloss.NewStyle().Bold(true).Foreground(th.BadgeText).Background(th.Accent).Padding(0, 1)
	badgeSec := lipgloss.NewStyle().Bold(true).Foreground(th.BadgeText).Background(th.Secondary).Padding(0, 1)
	badgeWarn := lipgloss.NewStyle().Bold(true).Foreground(th.BadgeText).Background(th.Warn).Padding(0, 1)
	badgeCrit := lipgloss.NewStyle().Bold(true).Foreground(th.BadgeText).Background(th.Crit).Padding(0, 1)

	// 1. Tactical HUD Top Banner
	pulse := pulseFrames[m.frameIdx%len(pulseFrames)]
	connBadge := badgeCrit.Render("◌ OFFLINE")
	if m.connected {
		connBadge = badgeOK.Render(pulse + " ONLINE")
	}

	xdpBadge := badgeWarn.Render("XDP: ADAPTIVE")
	if m.snap.XDPLockdown {
		xdpBadge = badgeCrit.Render("XDP: LOCKDOWN")
	}

	dirLabel := strings.ToUpper(m.snap.SNISPFDirection)
	if dirLabel == "" {
		dirLabel = "LEGACY"
	}
	dirBadge := badgeWarn.Render("DIR: " + dirLabel)
	if dirLabel == "FRONTING" {
		dirBadge = badgeSec.Render("DIR: FRONTING")
	}

	routeIP := m.snap.ActiveRouteIP
	if routeIP == "" {
		routeIP = "unassigned"
	}
	stealth := m.snap.ActiveStealth
	if stealth == "" {
		stealth = "none"
	}
	spoofDisplay := m.snap.ActiveSpoofSNI
	if spoofDisplay == "" {
		spoofDisplay = "(none)"
	} else if dirLabel == "LEGACY" {
		spoofDisplay = spoofDisplay + " (decoy)"
	}

	poolCap := m.snap.PoolCapacity
	if poolCap == 0 {
		poolCap = 3
	}
	poolGauge := renderBlockGauge(m.snap.WarmPipes, poolCap, 5, th.Accent, th.BorderDim)

	uptime := time.Since(m.startedAt).Truncate(time.Second)

	hdr1 := fmt.Sprintf(" %s  %s  %s %-15s  %s %-14s  %s %s  %s %d (±%d)  %s",
		sTitle.Render("◆ CORNELIUS v1.3"),
		connBadge,
		sLabel.Render("EDGE:"),
		sVal.Render(truncateText(routeIP, 15)),
		sLabel.Render("STEALTH:"),
		sVal.Render(truncateText(stealth, 14)),
		sLabel.Render("POOL:"),
		poolGauge,
		sLabel.Render("TTL:"),
		m.snap.ExpectedTTL,
		m.snap.TTLTolerance,
		xdpBadge,
	)
	hdr2 := fmt.Sprintf(" %s  %s %-22s  %s %-22s  %s %-15s  %s %s",
		dirBadge,
		sLabel.Render("OUTER SPOOF:"),
		sVal.Render(truncateText(spoofDisplay, 22)),
		sLabel.Render("INNER WORKER:"),
		sVal.Render(truncateText(m.snap.ActiveSNI, 22)),
		sLabel.Render("PALETTE:"),
		sVal.Render(truncateText(th.Name, 15)),
		sLabel.Render("UP:"),
		sVal.Render(uptime.String()),
	)
	headerPanel := renderPanel("TACTICAL CONTROL PLANE", truncateText(m.sockPath, 26), []string{hdr1, hdr2}, w, th.BorderGlow, th.Accent)

	// 2. Responsive Split-Grid Layout
	wide := w >= 112
	leftW := w
	rightW := w
	if wide {
		leftW = w / 2
		rightW = w - leftW
	}

	halfH := 3
	if m.height >= 33 {
		halfH = 4
	}
	mirrorRows, txPeak, rxPeak := RenderMirroredThroughputGraph(m.txHist, m.rxHist, leftW-4, halfH, th)
	txHeader := fmt.Sprintf(" %s %-9s (%s)   %s %-9s (%s)",
		lipgloss.NewStyle().Bold(true).Foreground(th.Accent).Render("▲ TX:"),
		fmt.Sprintf("%.1f KB/s", m.txHist.Current()),
		formatBytesKB(m.snap.TxKB),
		lipgloss.NewStyle().Bold(true).Foreground(th.Secondary).Render("▼ RX:"),
		fmt.Sprintf("%.1f KB/s", m.rxHist.Current()),
		formatBytesKB(m.snap.RxKB),
	)
	netLines := append([]string{txHeader}, mirrorRows...)
	netPanel := renderPanel(
		fmt.Sprintf("THROUGHPUT OSCILLOSCOPE // Peak %.0f/%.0f KB/s", txPeak, rxPeak),
		"EMA 2x4",
		netLines, leftW, th.Secondary, th.Secondary,
	)

	dropH := halfH * 2
	if dropH < 4 {
		dropH = 4
	}
	dropRows, dropPeak := RenderGradientBrailleGraph(m.dropHist, rightW-4, dropH-1, 5.0, th.DropStops)
	radarLine := m.renderEchoRadarLine(rightW-4, th)
	xdpLines := append(dropRows, radarLine)
	xdpPanel := renderPanel(
		fmt.Sprintf("XDP KERNEL SHIELD // DROPPED: %d", m.snap.XDPDroppedPkts),
		fmt.Sprintf("Peak: %.1f pkt/s", dropPeak),
		xdpLines, rightW, th.Crit, th.Crit,
	)

	routeLines := m.renderRouteTable(leftW-4, th)
	routePanel := renderPanel(
		"EDGE ROUTE MATRIX // [j/k] Select  [Enter] Hot-Swap",
		fmt.Sprintf("%d routes", len(m.snap.FailoverRoutes)),
		routeLines, leftW, th.Accent, th.Accent,
	)

	rightBottomLines := m.renderVitalsAndEvents(rightW-4, len(routeLines), th)
	eventsPanel := renderPanel(
		"STRATEGIST & KERNEL EVENT STREAM",
		"LIVE",
		rightBottomLines, rightW, th.Warn, th.Warn,
	)

	var body string
	if wide {
		topGrid := lipgloss.JoinHorizontal(lipgloss.Top, netPanel, xdpPanel)
		botGrid := lipgloss.JoinHorizontal(lipgloss.Top, routePanel, eventsPanel)
		body = lipgloss.JoinVertical(lipgloss.Left, headerPanel, topGrid, botGrid)
	} else {
		body = lipgloss.JoinVertical(lipgloss.Left, headerPanel, netPanel, xdpPanel, routePanel, eventsPanel)
	}

	footer := m.renderFooter(w, th, sKey, sLabel, badgeWarn, badgeCrit)
	full := lipgloss.JoinVertical(lipgloss.Left, body, footer)

	v := tea.NewView(full)
	v.AltScreen = true
	v.WindowTitle = "Cornelius v1.3.0 // Tactical Control Plane"
	return v
}

func (m Model) renderEchoRadarLine(innerW int, th Theme) string {
	sLabel := lipgloss.NewStyle().Bold(true).Foreground(th.Warn)
	sDim := lipgloss.NewStyle().Foreground(th.Muted)
	sHit := lipgloss.NewStyle().Bold(true).Foreground(th.Crit)
	sOK := lipgloss.NewStyle().Bold(true).Foreground(th.Accent)
	spin := radarFrames[m.frameIdx%len(radarFrames)]

	if m.snap.EchoBusy {
		return sLabel.Render(" RADAR: ") + sOK.Render(spin+" Sweeping TTL hops -> "+m.snap.ActiveRouteIP+"...")
	}
	e := m.snap.Echo
	if e == nil {
		return sLabel.Render(" RADAR: ") + sDim.Render("Press [t] to echolocate DPI hop distance & calibrate DecoyTTL")
	}
	if e.DPIIntercepted {
		trail := fmt.Sprintf("[HOST]─1..%d─▶ [DPI RST @ HOP %d] ✕  (DecoyTTL=%d)",
			maxInt(1, e.DPIDistanceHops-1), e.DPIDistanceHops, e.RecommendedDecoyTTL)
		return sLabel.Render(" RADAR: ") + sHit.Render(truncateText(trail, innerW-9))
	}
	trail := fmt.Sprintf("[HOST]─1..%d─▶ [EDGE %s] ✓  (DecoyTTL=%d)",
		e.ServerDistanceHops, e.TargetIP, e.RecommendedDecoyTTL)
	return sLabel.Render(" RADAR: ") + sOK.Render(truncateText(trail, innerW-9))
}

func (m Model) renderRouteTable(innerW int, th Theme) []string {
	sHdr := lipgloss.NewStyle().Bold(true).Foreground(th.Muted)
	sActive := lipgloss.NewStyle().Bold(true).Foreground(th.Accent)
	sSel := lipgloss.NewStyle().Bold(true).Foreground(th.BadgeText).Background(th.Secondary)
	sNorm := lipgloss.NewStyle().Foreground(th.Text)
	sAlt := lipgloss.NewStyle().Foreground(th.Text).Background(th.RowAlt)

	header := sHdr.Render(" ST  EDGE IP          DIR       STEALTH         RTT     SCORE")
	lines := []string{header}

	maxRows := 5
	if len(m.snap.FailoverRoutes) == 0 {
		lines = append(lines, sNorm.Render("  No routes loaded. Press [s] to scan CIDR or [i] to inject."))
		for len(lines) < maxRows+1 {
			lines = append(lines, "")
		}
		return lines
	}

	for i, r := range m.snap.FailoverRoutes {
		if i >= maxRows {
			break
		}
		marker := "  "
		if r.TargetIP == m.snap.ActiveRouteIP {
			marker = "★ "
		} else if i == m.selectedRoute {
			marker = "▶ "
		}

		dir := strings.ToUpper(r.SNISPFDirection)
		if dir == "" {
			dir = "LEGACY"
		}
		rttStr := fmt.Sprintf("%3dms", r.TLSHandshakeMs)
		if r.TLSHandshakeMs <= 0 {
			rttStr = "  -  "
		}
		scoreStr := renderScoreBar(r.Score, th)

		rowRaw := fmt.Sprintf(" %s%-15s  %-8s  %-14s  %-5s  %s",
			marker,
			truncateText(r.TargetIP, 15),
			truncateText(dir, 8),
			truncateText(r.StealthMode, 14),
			rttStr,
			scoreStr,
		)

		switch {
		case i == m.selectedRoute:
			lines = append(lines, sSel.Width(innerW).Render(rowRaw))
		case r.TargetIP == m.snap.ActiveRouteIP:
			lines = append(lines, sActive.Render(rowRaw))
		case i%2 == 1:
			lines = append(lines, sAlt.Width(innerW).Render(rowRaw))
		default:
			lines = append(lines, sNorm.Render(rowRaw))
		}
	}

	for len(lines) < maxRows+1 {
		lines = append(lines, "")
	}
	return lines
}

func (m Model) renderVitalsAndEvents(innerW, targetRows int, th Theme) []string {
	sLbl := lipgloss.NewStyle().Foreground(th.Muted)
	sVal := lipgloss.NewStyle().Bold(true).Foreground(th.Text)

	v1 := fmt.Sprintf(" %s %-5d  %s %-5d  %s %-5d  %s %-5d",
		sLbl.Render("STREAMS:"), m.snap.ActiveStreams,
		sLbl.Render("ROTATIONS:"), m.snap.RouteRotations,
		sLbl.Render("ESCALATE:"), m.snap.ModeEscalations,
		sLbl.Render("FAILS:"), m.snap.DialFailures,
	)
	div := lipgloss.NewStyle().Foreground(th.BorderDim).Render(strings.Repeat("─", innerW))
	lines := []string{v1, div}

	events := m.snap.RecentEvents
	if len(events) == 0 {
		lines = append(lines, sLbl.Render(" Awaiting daemon telemetry events..."))
	} else {
		slots := targetRows - 2
		if slots < 1 {
			slots = 1
		}
		start := 0
		if len(events) > slots {
			start = len(events) - slots
		}
		for _, ev := range events[start:] {
			srcCol := th.Secondary
			switch ev.Level {
			case "crit":
				srcCol = th.Crit
			case "warn":
				srcCol = th.Warn
			}
			tag := lipgloss.NewStyle().Bold(true).Foreground(srcCol).Render(fmt.Sprintf("[%-6s]", ev.Source))
			ts := sLbl.Render(ev.Time)
			msg := sVal.Render(truncateText(ev.Message, innerW-19))
			lines = append(lines, fmt.Sprintf(" %s %s %s", ts, tag, msg))
		}
	}

	for len(lines) < targetRows {
		lines = append(lines, "")
	}
	return lines
}

func (m Model) renderFooter(w int, th Theme, sKey, sLabel, badgeWarn, badgeCrit lipgloss.Style) string {
	modalBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(th.Secondary).
		Background(th.Surface).
		Padding(0, 1).
		Width(w - 2)

	if m.modal == modalHelp {
		helpBody := strings.Join([]string{
			lipgloss.NewStyle().Bold(true).Foreground(th.Accent).Render("CORNELIUS TACTICAL HUD // KEYBINDINGS"),
			fmt.Sprintf("  %s Navigate routes    %s Hot-swap selected IP    %s Manual route inject", sKey.Render("[j/k]"), sKey.Render("[Enter]"), sKey.Render("[i]")),
			fmt.Sprintf("  %s Cycle stealth mode %s Flip SNISPF direction   %s Toggle XDP Lockdown", sKey.Render("[e]"), sKey.Render("[f]"), sKey.Render("[l]")),
			fmt.Sprintf("  %s DPI hop radar      %s Scan CIDR subnet        %s Cycle color palette", sKey.Render("[t]"), sKey.Render("[s]"), sKey.Render("[m]")),
			sLabel.Render("  Press any key to close this overlay..."),
		}, "\n")
		return modalBox.Render(helpBody)
	}

	if m.modal == modalInject {
		ipLbl := "  Target IP  : "
		spLbl := "  Spoof SNI  : "
		wkLbl := "  Worker SNI : "
		switch m.modalFocus {
		case 0:
			ipLbl = sKey.Render("▶ Target IP  : ")
		case 1:
			spLbl = sKey.Render("▶ Spoof SNI  : ")
		case 2:
			wkLbl = sKey.Render("▶ Worker SNI : ")
		}
		body := fmt.Sprintf("%s%s█\n%s%s█\n%s%s█\n%s",
			ipLbl, m.inputIP,
			spLbl, m.inputSpoof,
			wkLbl, m.inputSNI,
			sLabel.Render("  [Tab] Next Field   [Enter] Hot-Swap Route   [Esc] Cancel"),
		)
		return modalBox.Render(body)
	}

	if m.modal == modalScan {
		cLbl := "  Target CIDR : "
		sLbl := "  Spoof SNI   : "
		if m.modalFocus == 0 {
			cLbl = sKey.Render("▶ Target CIDR : ")
		} else {
			sLbl = sKey.Render("▶ Spoof SNI   : ")
		}
		body := fmt.Sprintf("%s%s█\n%s%s█\n%s",
			cLbl, m.inputCIDR,
			sLbl, m.inputSpoof,
			sLabel.Render("  [Tab] Next Field   [Enter] Launch Bounded Cartographer   [Esc] Cancel"),
		)
		return modalBox.Render(body)
	}

	spin := radarFrames[m.frameIdx%len(radarFrames)]
	statusNote := sLabel.Render("Ready")
	if m.snap.ScanBusy {
		statusNote = badgeWarn.Render(spin + " Scanning CIDR...")
	} else if m.snap.EchoBusy {
		statusNote = badgeWarn.Render(spin + " Echolocating...")
	} else if m.pendingAction != "" {
		statusNote = badgeWarn.Render(m.pendingAction)
	} else if m.lastErr != "" {
		statusNote = badgeCrit.Render(truncateText(m.lastErr, 34))
	}

	return fmt.Sprintf(" %s Stealth  %s Dir  %s XDP  %s Echo  %s Scan  %s Inject  %s Theme  %s Help  %s Quit  %s",
		sKey.Render("[e]"),
		sKey.Render("[f]"),
		sKey.Render("[l]"),
		sKey.Render("[t]"),
		sKey.Render("[s]"),
		sKey.Render("[i]"),
		sKey.Render("[m]"),
		sKey.Render("[?]"),
		sKey.Render("[q]"),
		statusNote,
	)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	sock := flag.String("s", defaultSockPath, "Path to Cornelius IPC Unix socket")
	flag.Parse()

	p := tea.NewProgram(initialModel(*sock))
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
}
