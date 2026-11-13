package main

import (
	"math"
	"strings"

	"charm.land/lipgloss/v2"
)

type RingBuffer struct {
	data     []float64
	cap      int
	ema      float64
	hasEMA   bool
	peakHold float64
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 16 {
		capacity = 16
	}
	return &RingBuffer{
		data: make([]float64, 0, capacity),
		cap:  capacity,
	}
}

// Push inserts a rate sample with light EMA smoothing and decaying peak-hold tracking.
func (r *RingBuffer) Push(v float64) {
	if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		v = 0
	}
	if !r.hasEMA {
		r.ema = v
		r.hasEMA = true
	} else {
		r.ema = 0.65*v + 0.35*r.ema
	}

	if r.ema > r.peakHold {
		r.peakHold = r.ema
	} else {
		r.peakHold *= 0.96
	}

	if len(r.data) >= r.cap {
		copy(r.data, r.data[1:])
		r.data[len(r.data)-1] = r.ema
		return
	}
	r.data = append(r.data, r.ema)
}

func (r *RingBuffer) Current() float64 {
	if len(r.data) == 0 {
		return 0
	}
	return r.data[len(r.data)-1]
}

func (r *RingBuffer) Tail(n int) []float64 {
	if n <= 0 {
		return nil
	}
	out := make([]float64, n)
	if len(r.data) == 0 {
		return out
	}
	if len(r.data) >= n {
		copy(out, r.data[len(r.data)-n:])
		return out
	}
	offset := n - len(r.data)
	copy(out[offset:], r.data)
	return out
}

var (
	brailleUpLeft    = [4]rune{0x40, 0x04, 0x02, 0x01}
	brailleUpRight   = [4]rune{0x80, 0x20, 0x10, 0x08}
	brailleDownLeft  = [4]rune{0x01, 0x02, 0x04, 0x40}
	brailleDownRight = [4]rune{0x08, 0x10, 0x20, 0x80}
)

// RenderGradientBrailleGraph renders an upward-rising Braille oscilloscope with
// continuous TrueColor vertical interpolation and a subtle peak-hold marker.
func RenderGradientBrailleGraph(buf *RingBuffer, width, height int, minScale float64, stops []RGB) ([]string, float64) {
	if width < 2 {
		width = 2
	}
	if height < 1 {
		height = 1
	}

	samples := buf.Tail(width * 2)
	peak := minScale
	for _, v := range samples {
		if v > peak {
			peak = v
		}
	}

	totalSubRows := height * 4
	holdSub := int(math.Round((buf.peakHold / peak) * float64(totalSubRows)))
	rows := make([]string, height)

	for row := 0; row < height; row++ {
		invRow := height - 1 - row
		rowBaseSub := invRow * 4

		var sb strings.Builder
		sb.Grow(width * 3)

		for col := 0; col < width; col++ {
			leftLevel := int(math.Round((samples[col*2] / peak) * float64(totalSubRows)))
			rightLevel := int(math.Round((samples[col*2+1] / peak) * float64(totalSubRows)))

			var mask rune
			for sub := 0; sub < 4; sub++ {
				level := rowBaseSub + sub + 1
				if leftLevel >= level {
					mask |= brailleUpLeft[sub]
				}
				if rightLevel >= level {
					mask |= brailleUpRight[sub]
				}
				// Faint peak-hold horizon dot on empty top cells
				if mask == 0 && holdSub > 1 && level == holdSub && col%3 == 0 {
					mask |= 0x01
				}
			}
			sb.WriteRune(0x2800 + mask)
		}

		t := float64(invRow) / float64(maxInt(1, height-1))
		col := sampleGradient(stops, t)
		rows[row] = lipgloss.NewStyle().Foreground(col).Render(sb.String())
	}

	return rows, peak
}

// RenderMirroredThroughputGraph renders a btop-style symmetrical dual-band graph:
// topHalf plots TX rising upward, separated by a calibrated axis ruler, and
// bottomHalf plots RX hanging downward.
func RenderMirroredThroughputGraph(txBuf, rxBuf *RingBuffer, width, halfHeight int, th Theme) ([]string, float64, float64) {
	if width < 2 {
		width = 2
	}
	if halfHeight < 1 {
		halfHeight = 1
	}

	txRows, txPeak := RenderGradientBrailleGraph(txBuf, width, halfHeight, 10.0, th.TxStops)

	rxSamples := rxBuf.Tail(width * 2)
	rxPeak := 10.0
	for _, v := range rxSamples {
		if v > rxPeak {
			rxPeak = v
		}
	}

	totalSubRows := halfHeight * 4
	rxRows := make([]string, halfHeight)
	for row := 0; row < halfHeight; row++ {
		rowBaseSub := row * 4
		var sb strings.Builder
		sb.Grow(width * 3)

		for col := 0; col < width; col++ {
			leftLevel := int(math.Round((rxSamples[col*2] / rxPeak) * float64(totalSubRows)))
			rightLevel := int(math.Round((rxSamples[col*2+1] / rxPeak) * float64(totalSubRows)))

			var mask rune
			for sub := 0; sub < 4; sub++ {
				level := rowBaseSub + sub + 1
				if leftLevel >= level {
					mask |= brailleDownLeft[sub]
				}
				if rightLevel >= level {
					mask |= brailleDownRight[sub]
				}
			}
			sb.WriteRune(0x2800 + mask)
		}

		t := float64(row) / float64(maxInt(1, halfHeight-1))
		col := sampleGradient(th.RxStops, t)
		rxRows[row] = lipgloss.NewStyle().Foreground(col).Render(sb.String())
	}

	var axis strings.Builder
	axis.Grow(width * 3)
	for i := 0; i < width; i++ {
		if i%10 == 0 {
			axis.WriteRune('┼')
		} else {
			axis.WriteRune('┄')
		}
	}
	divider := lipgloss.NewStyle().Foreground(th.BorderDim).Render(axis.String())

	out := make([]string, 0, halfHeight*2+1)
	out = append(out, txRows...)
	out = append(out, divider)
	out = append(out, rxRows...)
	return out, txPeak, rxPeak
}
