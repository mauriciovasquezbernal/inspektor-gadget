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

package prometheus

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

//func TestCreateMetrics(t *testing.T) {
//	t.Parallel()
//
//	type testDefinition struct {
//		name          string
//		config        *Config
//		errExpected   bool
//		expectedCalls []string
//	}
//
//	tests := []testDefinition{
//		{
//			name: "counter",
//			config: &Config{
//				Metrics: []Metric{
//					{
//						Name:     "metricname",
//						Type:     "counter",
//						Category: "trace",
//						Gadget:   "stubtracer",
//					},
//				},
//			},
//			errExpected:   false,
//			expectedCalls: []string{"Int64Counter"},
//		},
//		{
//			name: "gauge",
//			config: &Config{
//				Metrics: []Metric{
//					{
//						Name:     "processes",
//						Type:     "gauge",
//						Category: "snapshot",
//						Gadget:   "stubsnapshotter",
//					},
//				},
//			},
//			errExpected:   false,
//			expectedCalls: []string{"Int64ObservableGauge", "RegisterCallback"},
//		},
//		{
//			name: "wrong gadget type for gauge",
//			config: &Config{
//				Metrics: []Metric{
//					{
//						Name:     "metricname",
//						Type:     "gauge",
//						Category: "trace",
//						Gadget:   "stubtracer",
//					},
//				},
//			},
//			errExpected: true,
//		},
//	}
//
//	for _, test := range tests {
//		test := test
//		t.Run(test.name, func(t *testing.T) {
//			t.Parallel()
//
//			meter := NewStubMeter(t)
//
//			ctx, cancel := context.WithCancel(context.Background())
//
//			cleanup, err := CreateMetrics(ctx, test.config, meter)
//			t.Cleanup(cancel)
//			if test.errExpected {
//				require.Error(t, err)
//			} else {
//				require.Nil(t, err)
//				cleanup()
//			}
//
//			require.Equal(t, test.expectedCalls, meter.calls)
//
//			// Give some time to trace to be run
//			time.Sleep(1 * time.Second)
//		})
//	}
//}

// events that are generated in the test. Counters are increments based on them and the metric
// configuration
var testEvents = []stubTracerEvent{
	// root executes cat twice
	{Comm: "cat", Uid: 0},
	{Comm: "cat", Uid: 0},

	// user 1000 executes cat
	{Comm: "cat", Uid: 1000},

	// root executes ping
	{Comm: "ping", Uid: 0},

	// user 1000 executes ls
	{Comm: "ls", Uid: 1000},
}

func TestMetrics(t *testing.T) {
	type testDefinition struct {
		name             string
		config           *Config
		expectedErr      bool
		expectedCounters map[string]map[string]int64
	}

	tests := []testDefinition{
		// Generic checks before
		{
			name: "wrong_metric_type",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "wrong_metric_type",
						Type:     "nonvalidtype",
						Category: "trace",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedErr: true,
		},
		// Wrong configurations
		{
			name: "counter_wrong_gadget_name",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_wrong_gadget_name",
						Type:     "counter",
						Category: "trace",
						Gadget:   "nonexisting",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_gadget_category",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_wrong_gadget_category",
						Type:     "counter",
						Category: "nonexisting",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_gadget_type",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_wrong_gadget_type",
						Type:     "counter",
						Category: "snapshot",
						Gadget:   "stubsnapshotter",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_type_field",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_wrong_type_field",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "comm",
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_selector",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_wrong_selector",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "comm",
						Selector: []string{"wrong:cat"},
					},
				},
			},
			expectedErr: true,
		},
		{
			name: "counter_wrong_labels",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_wrong_labels",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Labels:   []string{"wrong"},
					},
				},
			},
			expectedErr: true,
		},
		// Check that counters are updated correctly
		{
			name: "counter_no_labels_nor_filtering",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_no_labels_nor_filtering",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
					},
					{
						Name:     "counter_no_labels_nor_filtering2",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedCounters: map[string]map[string]int64{
				"counter_no_labels_nor_filtering":  {"": 5},
				"counter_no_labels_nor_filtering2": {"": 5},
			},
		},
		{
			name: "counter_filter_only_root_events",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_filter_only_root_events",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Selector: []string{"uid:0"},
					},
				},
			},
			expectedCounters: map[string]map[string]int64{
				"counter_filter_only_root_events": {"": 3},
			},
		},
		{
			name: "counter_filter_only_root_cat_events",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_filter_only_root_cat_events",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Selector: []string{"uid:0", "comm:cat"},
					},
				},
			},
			expectedCounters: map[string]map[string]int64{
				"counter_filter_only_root_cat_events": {"": 2},
			},
		},
		{
			name: "counter_filter_uid_greater_than_0",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_filter_uid_greater_than_0",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Selector: []string{"uid:>0"},
					},
				},
			},
			expectedCounters: map[string]map[string]int64{
				"counter_filter_uid_greater_than_0": {"": 2},
			},
		},
		{
			name: "counter_aggregate_by_comm",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_aggregate_by_comm",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Labels:   []string{"comm"},
					},
				},
			},
			expectedCounters: map[string]map[string]int64{
				"counter_aggregate_by_comm": {"comm=cat,": 3, "comm=ping,": 1, "comm=ls,": 1},
			},
		},
		{
			name: "counter_aggregate_by_uid",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_aggregate_by_uid",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Labels:   []string{"uid"},
					},
				},
			},
			expectedCounters: map[string]map[string]int64{
				"counter_aggregate_by_uid": {"uid=0,": 3, "uid=1000,": 2},
			},
		},
		{
			name: "counter_aggregate_by_uid_and_comm",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_aggregate_by_uid_and_comm",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Labels:   []string{"uid", "comm"},
					},
				},
			},
			expectedCounters: map[string]map[string]int64{
				"counter_aggregate_by_uid_and_comm": {
					"uid=0,comm=cat,":    2,
					"uid=1000,comm=cat,": 1,
					"uid=0,comm=ping,":   1,
					"uid=1000,comm=ls,":  1,
				},
			},
		},
		{
			name: "counter_aggregate_by_uid_and_filter_by_comm",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_aggregate_by_uid_and_filter_by_comm",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Selector: []string{"comm:cat"},
						Labels:   []string{"uid"},
					},
				},
			},
			expectedCounters: map[string]map[string]int64{
				"counter_aggregate_by_uid_and_filter_by_comm": {"uid=0,": 2, "uid=1000,": 1},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			c := make(chan struct{}, 1)
			ctx = context.WithValue(ctx, valuekey, c)

			meter := NewStubMeter(t)

			cleanup, err := CreateMetrics(ctx, test.config, meter)
			if test.expectedErr {
				require.Error(t, err)
				return
			}
			require.Nil(t, err)
			t.Cleanup(cleanup)

			require.Equal(t, len(test.expectedCounters), len(meter.int64counters))

			// Wait for the tracer to run
			select {
			case <-time.After(1 * time.Second):
				require.Fail(t, "timeout waiting for tracer to run")
			case <-c:
			}

			// check that all counters are created and have the expected values
			for name, expected := range test.expectedCounters {
				counter, ok := meter.int64counters[name]
				require.True(t, ok, "counter %q not found", name)

				require.Equal(t, expected, counter.values, "counter values are wrong")
			}
		})
	}
}
