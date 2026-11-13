package main

import (
	"fmt"
	"image/color"

	"charm.land/lipgloss/v2"
)

type RGB struct {
	R, G, B uint8
}

func (c RGB) Color() color.Color {
	return lipgloss.Color(fmt.Sprintf("#%02X%02X%02X", c.R, c.G, c.B))
}

func lerpRGB(a, b RGB, t float64) RGB {
	if t <= 0 {
		return a
	}
	if t >= 1 {
		return b
	}
	return RGB{
		R: uint8(float64(a.R) + t*(float64(b.R)-float64(a.R))),
		G: uint8(float64(a.G) + t*(float64(b.G)-float64(a.G))),
		B: uint8(float64(a.B) + t*(float64(b.B)-float64(a.B))),
	}
}

func sampleGradient(stops []RGB, t float64) color.Color {
	if len(stops) == 0 {
		return lipgloss.Color("#10B981")
	}
	if len(stops) == 1 || t <= 0 {
		return stops[0].Color()
	}
	if t >= 1 {
		return stops[len(stops)-1].Color()
	}
	scaled := t * float64(len(stops)-1)
	idx := int(scaled)
	if idx >= len(stops)-1 {
		return stops[len(stops)-1].Color()
	}
	frac := scaled - float64(idx)
	return lerpRGB(stops[idx], stops[idx+1], frac).Color()
}

type Theme struct {
	Name       string
	Accent     color.Color
	Secondary  color.Color
	Warn       color.Color
	Crit       color.Color
	BorderDim  color.Color
	BorderGlow color.Color
	Text       color.Color
	Muted      color.Color
	Surface    color.Color
	RowAlt     color.Color
	BadgeText  color.Color
	TxStops    []RGB
	RxStops    []RGB
	DropStops  []RGB
}

var themes = []Theme{
	{
		Name:       "OBSIDIAN EMERALD",
		Accent:     lipgloss.Color("#10B981"),
		Secondary:  lipgloss.Color("#38BDF8"),
		Warn:       lipgloss.Color("#F59E0B"),
		Crit:       lipgloss.Color("#F43F5E"),
		BorderDim:  lipgloss.Color("#1E293B"),
		BorderGlow: lipgloss.Color("#0D9488"),
		Text:       lipgloss.Color("#F1F5F9"),
		Muted:      lipgloss.Color("#64748B"),
		Surface:    lipgloss.Color("#090D16"),
		RowAlt:     lipgloss.Color("#0F172A"),
		BadgeText:  lipgloss.Color("#020617"),
		TxStops:    []RGB{{6, 78, 59}, {5, 150, 105}, {16, 185, 129}, {52, 211, 153}, {167, 243, 208}},
		RxStops:    []RGB{{125, 211, 252}, {56, 189, 248}, {2, 132, 199}, {3, 105, 161}, {30, 58, 138}},
		DropStops:  []RGB{{180, 83, 9}, {245, 158, 11}, {244, 63, 94}, {253, 164, 175}},
	},
	{
		Name:       "TOKYO SYNTH",
		Accent:     lipgloss.Color("#E879F9"),
		Secondary:  lipgloss.Color("#22D3EE"),
		Warn:       lipgloss.Color("#FBBF24"),
		Crit:       lipgloss.Color("#FB7185"),
		BorderDim:  lipgloss.Color("#2E1065"),
		BorderGlow: lipgloss.Color("#C026D3"),
		Text:       lipgloss.Color("#F8FAFC"),
		Muted:      lipgloss.Color("#818CF8"),
		Surface:    lipgloss.Color("#0D061A"),
		RowAlt:     lipgloss.Color("#170B2E"),
		BadgeText:  lipgloss.Color("#090414"),
		TxStops:    []RGB{{112, 26, 117}, {162, 28, 175}, {217, 70, 239}, {232, 121, 249}, {245, 208, 254}},
		RxStops:    []RGB{{103, 232, 249}, {34, 211, 238}, {6, 182, 212}, {8, 145, 178}, {22, 78, 99}},
		DropStops:  []RGB{{217, 119, 6}, {244, 63, 94}, {251, 113, 133}, {254, 205, 211}},
	},
	{
		Name:       "NORDIC AURORA",
		Accent:     lipgloss.Color("#88C0D0"),
		Secondary:  lipgloss.Color("#8FBCBB"),
		Warn:       lipgloss.Color("#EBCB8B"),
		Crit:       lipgloss.Color("#BF616A"),
		BorderDim:  lipgloss.Color("#3B4252"),
		BorderGlow: lipgloss.Color("#5E81AC"),
		Text:       lipgloss.Color("#ECEFF4"),
		Muted:      lipgloss.Color("#7B88A1"),
		Surface:    lipgloss.Color("#242933"),
		RowAlt:     lipgloss.Color("#2E3440"),
		BadgeText:  lipgloss.Color("#1D212A"),
		TxStops:    []RGB{{76, 86, 106}, {94, 129, 172}, {129, 161, 193}, {136, 192, 208}, {163, 190, 140}},
		RxStops:    []RGB{{163, 190, 140}, {143, 188, 187}, {136, 192, 208}, {94, 129, 172}, {59, 66, 82}},
		DropStops:  []RGB{{235, 203, 139}, {208, 135, 112}, {191, 97, 106}},
	},
	{
		Name:       "PHOSPHOR CRT",
		Accent:     lipgloss.Color("#F59E0B"),
		Secondary:  lipgloss.Color("#FCD34D"),
		Warn:       lipgloss.Color("#FB923C"),
		Crit:       lipgloss.Color("#EF4444"),
		BorderDim:  lipgloss.Color("#292524"),
		BorderGlow: lipgloss.Color("#B45309"),
		Text:       lipgloss.Color("#FEF3C7"),
		Muted:      lipgloss.Color("#78716C"),
		Surface:    lipgloss.Color("#0C0A09"),
		RowAlt:     lipgloss.Color("#1C1917"),
		BadgeText:  lipgloss.Color("#0C0A09"),
		TxStops:    []RGB{{120, 53, 15}, {180, 83, 9}, {217, 119, 6}, {245, 158, 11}, {253, 230, 138}},
		RxStops:    []RGB{{253, 230, 138}, {251, 191, 36}, {217, 119, 6}, {146, 64, 14}, {69, 26, 3}},
		DropStops:  []RGB{{234, 88, 12}, {220, 38, 38}, {248, 113, 113}},
	},
}
