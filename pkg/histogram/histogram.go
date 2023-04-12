// Copyright 2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package histogram provides a Histogram struct that represents a histogram of
// the number of events that occurred in each interval. The intervals are powers
// of two, so the slots array is indexed by the power of two minus one. For
// example, the first slot is the number of events that occurred in the interval
// [1, 1], the second slot is [2, 3], the third slot is [4, 7], and so on.

package histogram

import (
	"fmt"
	"strings"
)

type Unit string

const (
	UnitMilliseconds Unit = "msecs"
	UnitMicroseconds Unit = "usecs"
)

type Slot struct {
	Count         uint64 `json:"count"`
	IntervalStart uint64 `json:"intervalStart"`
	IntervalEnd   uint64 `json:"intervalEnd"`
}

// Histogram represents a histogram of the number of events that occurred in
// each interval.
type Histogram struct {
	Unit  Unit   `json:"unit,omitempty"`
	Slots []Slot `json:"slots,omitempty"`
}

// NewSlots creates a new Slot array from a C-Slots array returned by the BPF
// program.
func NewSlots(cSlots []uint32) []Slot {
	if len(cSlots) == 0 {
		return nil
	}

	parsedSlots := make([]Slot, 0, len(cSlots))
	indexMax := 0
	for i, val := range cSlots {
		if val > 0 {
			indexMax = i
		}

		start := uint64(1) << i
		end := (uint64(1) << (i + 1)) - 1
		if start == end {
			start -= 1
		}

		parsedSlots = append(parsedSlots, Slot{
			Count:         uint64(val),
			IntervalStart: start,
			IntervalEnd:   end,
		})
	}

	// Slots are 0-indexed, so we need to increment indexMax to get the number
	// of slots.
	return parsedSlots[:indexMax+1]
}

// String returns a string representation of the histogram. It is a golang
// adaption of iovisor/bcc print_log2_hist():
// https://github.com/iovisor/bcc/blob/13b5563c11f7722a61a17c6ca0a1a387d2fa7788/libbpf-tools/trace_helpers.c#L895-L932
func (h *Histogram) String() string {
	if len(h.Slots) == 0 {
		return ""
	}

	valMax := uint64(0)
	for _, slot := range h.Slots {
		if slot.Count > valMax {
			valMax = slot.Count
		}
	}

	// reportEntries maximum value is C.MAX_SLOTS which is 27, so we take the
	// value when idx_max <= 32.
	spaceBefore := 5
	spaceAfter := 19
	width := 10
	stars := 40

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%*s%-*s : count    distribution\n", spaceBefore,
		"", spaceAfter, h.Unit))

	for _, slot := range h.Slots {
		sb.WriteString(fmt.Sprintf("%*d -> %-*d : %-8d |%s|\n", width,
			slot.IntervalStart, width, slot.IntervalEnd, slot.Count,
			starsToString(slot.Count, valMax, uint64(stars))))
	}

	return sb.String()
}

// starsToString returns a string with the number of stars and spaces needed to
// represent the value in the histogram. It is a golang adaption of iovisor/bcc
// print_stars():
// https://github.com/iovisor/bcc/blob/13b5563c11f7722a61a17c6ca0a1a387d2fa7788/libbpf-tools/trace_helpers.c#L878-L893
func starsToString(val, valMax, width uint64) string {
	if valMax == 0 {
		return strings.Repeat(" ", int(width))
	}

	minVal := uint64(0)
	if val < valMax {
		minVal = val
	} else {
		minVal = valMax
	}

	stars := minVal * width / valMax
	spaces := width - stars

	var sb strings.Builder
	sb.WriteString(strings.Repeat("*", int(stars)))
	sb.WriteString(strings.Repeat(" ", int(spaces)))
	if val > valMax {
		sb.WriteByte('+')
	}

	return sb.String()
}
