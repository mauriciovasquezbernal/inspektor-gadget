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

package histogram

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHistogram_NewFromCSlots(t *testing.T) {
	t.Parallel()

	const unit = UnitMicroseconds

	testTable := []struct {
		description string
		cSlots      []uint32
		expected    *Histogram
	}{
		{
			description: "Empty slots",
			cSlots:      []uint32{},
			expected: &Histogram{
				Unit:  unit,
				Slots: nil,
			},
		},
		{
			description: "With 1 slot",
			cSlots:      []uint32{1},
			expected: &Histogram{
				Unit: unit,
				Slots: []Slot{
					{Count: 1, IntervalStart: 0, IntervalEnd: 1},
				},
			},
		},
		{
			description: "With 2 slots",
			cSlots:      []uint32{1, 2},
			expected: &Histogram{
				Unit: unit,
				Slots: []Slot{
					{Count: 1, IntervalStart: 0, IntervalEnd: 1},
					{Count: 2, IntervalStart: 2, IntervalEnd: 3},
				},
			},
		},
		{
			description: "With zero slots",
			cSlots:      []uint32{1, 0, 3},
			expected: &Histogram{
				Unit: unit,
				Slots: []Slot{
					{Count: 1, IntervalStart: 0, IntervalEnd: 1},
					{Count: 0, IntervalStart: 2, IntervalEnd: 3},
					{Count: 3, IntervalStart: 4, IntervalEnd: 7},
				},
			},
		},
		{
			description: "Zero at first slot",
			cSlots:      []uint32{0, 8, 0, 1},
			expected: &Histogram{
				Unit: unit,
				Slots: []Slot{
					{Count: 0, IntervalStart: 0, IntervalEnd: 1},
					{Count: 8, IntervalStart: 2, IntervalEnd: 3},
					{Count: 0, IntervalStart: 4, IntervalEnd: 7},
					{Count: 1, IntervalStart: 8, IntervalEnd: 15},
				},
			},
		},
		{
			description: "Multiple zeros at first slots",
			cSlots:      []uint32{0, 0, 0, 1},
			expected: &Histogram{
				Unit: unit,
				Slots: []Slot{
					{Count: 0, IntervalStart: 0, IntervalEnd: 1},
					{Count: 0, IntervalStart: 2, IntervalEnd: 3},
					{Count: 0, IntervalStart: 4, IntervalEnd: 7},
					{Count: 1, IntervalStart: 8, IntervalEnd: 15},
				},
			},
		},
		{
			description: "Multiple zeros at last slots",
			cSlots:      []uint32{0, 8, 0, 1, 0, 0, 0},
			expected: &Histogram{
				Unit: unit,
				Slots: []Slot{
					{Count: 0, IntervalStart: 0, IntervalEnd: 1},
					{Count: 8, IntervalStart: 2, IntervalEnd: 3},
					{Count: 0, IntervalStart: 4, IntervalEnd: 7},
					{Count: 1, IntervalStart: 8, IntervalEnd: 15},
				},
			},
		},
	}

	for _, test := range testTable {
		test := test
		t.Run(test.description, func(t *testing.T) {
			t.Parallel()

			h := &Histogram{
				Unit:  unit,
				Slots: NewSlots(test.cSlots),
			}
			require.Equal(t, test.expected, h, "histogram")
		})
	}
}

func TestHistogram_String(t *testing.T) {
	t.Parallel()

	testTable := []struct {
		description string
		histogram   *Histogram
		expected    string
	}{
		{
			description: "Empty histogram",
			histogram: &Histogram{
				Unit:  UnitMicroseconds,
				Slots: []Slot{},
			},
			expected: "",
		},
		{
			description: "With 1 slot value 1",
			histogram: &Histogram{
				Unit:  UnitMicroseconds,
				Slots: NewSlots([]uint32{1}),
			},
			expected: "" +
				"     usecs               : count    distribution\n" +
				"         0 -> 1          : 1        |****************************************|\n",
		},
		{
			description: "With 1 slot value 55",
			histogram: &Histogram{
				Unit:  UnitMicroseconds,
				Slots: NewSlots([]uint32{55}),
			},
			expected: "" +
				"     usecs               : count    distribution\n" +
				"         0 -> 1          : 55       |****************************************|\n",
		},
		{
			description: "scale",
			histogram: &Histogram{
				Unit:  UnitMicroseconds,
				Slots: NewSlots([]uint32{1, 2, 3}),
			},
			expected: "" +
				"     usecs               : count    distribution\n" +
				"         0 -> 1          : 1        |*************                           |\n" +
				"         2 -> 3          : 2        |**************************              |\n" +
				"         4 -> 7          : 3        |****************************************|\n",
		},
		{
			description: "scale with empty slots",
			histogram: &Histogram{
				Unit:  UnitMicroseconds,
				Slots: NewSlots([]uint32{1, 0, 3}),
			},
			expected: "" +
				"     usecs               : count    distribution\n" +
				"         0 -> 1          : 1        |*************                           |\n" +
				"         2 -> 3          : 0        |                                        |\n" +
				"         4 -> 7          : 3        |****************************************|\n",
		},
		{
			description: "scale with empty slots and same values 1",
			histogram: &Histogram{
				Unit:  UnitMicroseconds,
				Slots: NewSlots([]uint32{1, 0, 1}),
			},
			expected: "" +
				"     usecs               : count    distribution\n" +
				"         0 -> 1          : 1        |****************************************|\n" +
				"         2 -> 3          : 0        |                                        |\n" +
				"         4 -> 7          : 1        |****************************************|\n",
		},
		{
			description: "scale with empty slots and same values 100",
			histogram: &Histogram{
				Unit:  UnitMicroseconds,
				Slots: NewSlots([]uint32{100, 0, 100}),
			},
			expected: "" +
				"     usecs               : count    distribution\n" +
				"         0 -> 1          : 100      |****************************************|\n" +
				"         2 -> 3          : 0        |                                        |\n" +
				"         4 -> 7          : 100      |****************************************|\n",
		},
	}

	for _, test := range testTable {
		test := test
		t.Run(test.description, func(t *testing.T) {
			t.Parallel()

			actual := test.histogram.String()
			require.Equal(t, test.expected, actual, "histogram string representation")
		})
	}
}
