package main

import (
	"fmt"
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

func renderPanel(title, rightTag string, lines []string, width int, borderColor, titleColor color.Color) string {
	if width < 14 {
		width = 14
	}
	innerWidth := width - 2
	bStyle := lipgloss.NewStyle().Foreground(borderColor)
	tStyle := lipgloss.NewStyle().Bold(true).Foreground(titleColor)

	leftRaw := "─[ " + title + " ]"
	rightRaw := ""
	if rightTag != "" {
		rightRaw = "[ " + rightTag + " ]─"
	}

	fillLen := innerWidth - lipgloss.Width(leftRaw) - lipgloss.Width(rightRaw)
	if fillLen < 0 {
		fillLen = 0
	}

	topBorder := bStyle.Render("╭─[ ") + tStyle.Render(title) + bStyle.Render(" ]"+strings.Repeat("─", fillLen))
	if rightTag != "" {
		topBorder += bStyle.Render("[ "+rightTag+" ]─")
	}
	topBorder += bStyle.Render("╮")

	bottomBorder := bStyle.Render("╰" + strings.Repeat("─", innerWidth) + "╯")

	var out strings.Builder
	out.WriteString(topBorder)
	out.WriteByte('\n')

	for _, line := range lines {
		padded := lipgloss.NewStyle().
			Width(innerWidth).
			MaxWidth(innerWidth).
			Render(line)
		out.WriteString(bStyle.Render("│"))
		out.WriteString(padded)
		out.WriteString(bStyle.Render("│"))
		out.WriteByte('\n')
	}

	out.WriteString(bottomBorder)
	return out.String()
}

func renderBlockGauge(cur, max uint64, width int, fillCol, emptyCol color.Color) string {
	if width < 3 {
		width = 3
	}
	if max == 0 {
		max = 1
	}
	filled := int((float64(cur) / float64(max)) * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	empty := width - filled
	fStr := lipgloss.NewStyle().Foreground(fillCol).Render(strings.Repeat("▰", filled))
	eStr := lipgloss.NewStyle().Foreground(emptyCol).Render(strings.Repeat("▱", empty))
	return fmt.Sprintf("%s%s %d/%d", fStr, eStr, cur, max)
}

func renderScoreBar(score int, th Theme) string {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	blocks := score / 20
	if blocks > 5 {
		blocks = 5
	}
	col := th.Accent
	if score < 60 {
		col = th.Crit
	} else if score < 85 {
		col = th.Warn
	}
	bar := lipgloss.NewStyle().Foreground(col).Render(strings.Repeat("▰", blocks)) +
		lipgloss.NewStyle().Foreground(th.BorderDim).Render(strings.Repeat("▱", 5-blocks))
	return fmt.Sprintf("%s %3d", bar, score)
}

func formatBytesKB(kb uint64) string {
	switch {
	case kb >= 1024*1024:
		return fmt.Sprintf("%.2f GB", float64(kb)/(1024*1024))
	case kb >= 1024:
		return fmt.Sprintf("%.1f MB", float64(kb)/1024)
	default:
		return fmt.Sprintf("%d KB", kb)
	}
}

func truncateText(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
