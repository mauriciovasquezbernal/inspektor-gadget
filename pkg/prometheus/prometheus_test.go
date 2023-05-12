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
	"sync"
	"testing"

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
var testEvents = []stubEvent{
	{Comm: "cat", Uid: 0, IntVal: 105, FloatVal: 201.2},
	{Comm: "cat", Uid: 0, IntVal: 216, FloatVal: 423.3},
	{Comm: "cat", Uid: 1000, IntVal: 327, FloatVal: 645.4},
	{Comm: "ping", Uid: 0, IntVal: 428, FloatVal: 867.5},
	{Comm: "ls", Uid: 1000, IntVal: 429, FloatVal: 1089.6},
}

func TestMetrics(t *testing.T) {
	type testDefinition struct {
		name        string
		config      *Config
		expectedErr bool
		// outer key: metric name, inner key: attributes hash
		expectedInt64Counters   map[string]map[string]int64
		expectedFloat64Counters map[string]map[string]float64
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
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_no_labels_nor_filtering": {"": 5},
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
			expectedInt64Counters: map[string]map[string]int64{
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
			expectedInt64Counters: map[string]map[string]int64{
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
			expectedInt64Counters: map[string]map[string]int64{
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
			expectedInt64Counters: map[string]map[string]int64{
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
			expectedInt64Counters: map[string]map[string]int64{
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
			expectedInt64Counters: map[string]map[string]int64{
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
			expectedInt64Counters: map[string]map[string]int64{
				"counter_aggregate_by_uid_and_filter_by_comm": {"uid=0,": 2, "uid=1000,": 1},
			},
		},
		{
			name: "counter_with_int_field",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_with_int_field",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "intval",
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_with_int_field": {"": 105 + 216 + 327 + 428 + 429},
			},
		},
		{
			name: "counter_with_float_field",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_with_float_field",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "floatval",
					},
				},
			},
			expectedFloat64Counters: map[string]map[string]float64{
				"counter_with_float_field": {"": 201.2 + 423.3 + 645.4 + 867.5 + 1089.6},
			},
		},
		{
			name: "counter_with_float_field_aggregate_by_uid_and_filter_by_comm",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_with_float_field_aggregate_by_uid_and_filter_by_comm",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "floatval",
						Selector: []string{"comm:cat"},
						Labels:   []string{"uid"},
					},
				},
			},
			expectedFloat64Counters: map[string]map[string]float64{
				"counter_with_float_field_aggregate_by_uid_and_filter_by_comm": {"uid=0,": 201.2 + 423.3, "uid=1000,": 645.4},
			},
		},
		{
			name: "counter_multiple_mixed",
			config: &Config{
				Metrics: []Metric{
					{
						Name:     "counter_multiple1",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
						Field:    "floatval",
					},
					{
						Name:     "counter_multiple2",
						Type:     "counter",
						Category: "trace",
						Gadget:   "stubtracer",
					},
				},
			},
			expectedInt64Counters: map[string]map[string]int64{
				"counter_multiple2": {"": 5},
			},
			expectedFloat64Counters: map[string]map[string]float64{
				"counter_multiple1": {"": 201.2 + 423.3 + 645.4 + 867.5 + 1089.6},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			wg := &sync.WaitGroup{}
			wg.Add(len(test.config.Metrics))
			ctx = context.WithValue(ctx, valuekey, wg)

			meter := NewStubMeter(t)

			cleanup, err := CreateMetrics(ctx, test.config, meter)
			if test.expectedErr {
				require.Error(t, err)
				return
			}
			require.Nil(t, err)
			t.Cleanup(cleanup)

			require.Equal(t, len(test.expectedInt64Counters), len(meter.int64counters))
			require.Equal(t, len(test.expectedFloat64Counters), len(meter.float64counters))

			// Wait for the tracer to run
			//select {
			//case <-time.After(1 * time.Second):
			//	require.Fail(t, "timeout waiting for tracer to run")
			//case <-c:
			//}
			// TODO: timeout?
			// https://stackoverflow.com/questions/32840687/timeout-for-waitgroup-wait
			wg.Wait()

			// check that all counters are created and have the expected values
			for name, expected := range test.expectedInt64Counters {
				counter, ok := meter.int64counters[name]
				require.True(t, ok, "counter %q not found", name)

				require.Equal(t, expected, counter.values, "counter values are wrong")
			}

			// check that all counters are created and have the expected values
			for name, expected := range test.expectedFloat64Counters {
				counter, ok := meter.float64counters[name]
				require.True(t, ok, "counter %q not found", name)

				//require.Equal doesn't work because of float comparisons
				require.InDeltaMapValues(t, expected, counter.values, 0.01, "counter values are wrong")
			}
		})
	}
}
