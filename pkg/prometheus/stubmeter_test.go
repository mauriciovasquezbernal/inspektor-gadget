package prometheus

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument"
)

func NewStubMeter(t *testing.T) *stubMeter {
	return &stubMeter{
		t:             t,
		int64counters: make(map[string]*stubInt64Counter),
	}
}

type stubMeter struct {
	t     *testing.T
	calls []string

	int64counters map[string]*stubInt64Counter
}

func (s *stubMeter) Int64Counter(name string, options ...instrument.Int64Option) (instrument.Int64Counter, error) {
	s.calls = append(s.calls, "Int64Counter")
	c := &stubInt64Counter{
		values: make(map[string]int64),
	}
	s.int64counters[name] = c
	return c, nil
}

func (s *stubMeter) Int64UpDownCounter(name string, options ...instrument.Int64Option) (instrument.Int64UpDownCounter, error) {
	s.calls = append(s.calls, "Int64UpDownCounter")
	return nil, nil
}

func (s *stubMeter) Int64Histogram(name string, options ...instrument.Int64Option) (instrument.Int64Histogram, error) {
	s.calls = append(s.calls, "Int64Histogram")
	return nil, nil
}

func (s *stubMeter) Int64ObservableCounter(name string, options ...instrument.Int64ObserverOption) (instrument.Int64ObservableCounter, error) {
	s.calls = append(s.calls, "Int64ObservableCounter")
	return nil, nil
}

func (s *stubMeter) Int64ObservableUpDownCounter(name string, options ...instrument.Int64ObserverOption) (instrument.Int64ObservableUpDownCounter, error) {
	s.calls = append(s.calls, "Int64ObservableUpDownCounter")
	return nil, nil
}

func (s *stubMeter) Int64ObservableGauge(name string, options ...instrument.Int64ObserverOption) (instrument.Int64ObservableGauge, error) {
	s.calls = append(s.calls, "Int64ObservableGauge")
	return nil, nil
}

func (s *stubMeter) Float64Counter(name string, options ...instrument.Float64Option) (instrument.Float64Counter, error) {
	s.calls = append(s.calls, "Float64Counter")
	return nil, nil
}

func (s *stubMeter) Float64UpDownCounter(name string, options ...instrument.Float64Option) (instrument.Float64UpDownCounter, error) {
	s.calls = append(s.calls, "Float64UpDownCounter")
	return nil, nil
}

func (s *stubMeter) Float64Histogram(name string, options ...instrument.Float64Option) (instrument.Float64Histogram, error) {
	s.calls = append(s.calls, "Float64Histogram")
	return nil, nil
}

func (s *stubMeter) Float64ObservableCounter(name string, options ...instrument.Float64ObserverOption) (instrument.Float64ObservableCounter, error) {
	s.calls = append(s.calls, "Float64ObservableCounter")
	return nil, nil
}

func (s *stubMeter) Float64ObservableUpDownCounter(name string, options ...instrument.Float64ObserverOption) (instrument.Float64ObservableUpDownCounter, error) {
	s.calls = append(s.calls, "Float64ObservableUpDownCounter")
	return nil, nil
}

func (s *stubMeter) Float64ObservableGauge(name string, options ...instrument.Float64ObserverOption) (instrument.Float64ObservableGauge, error) {
	s.calls = append(s.calls, "Float64ObservableGauge")
	return nil, nil
}

func (s *stubMeter) RegisterCallback(_ metric.Callback, instruments ...instrument.Asynchronous) (metric.Registration, error) {
	s.calls = append(s.calls, "RegisterCallback")
	return nil, nil
}

func attrsToString(kvs []attribute.KeyValue) string {
	ret := ""
	for _, kv := range kvs {
		ret += fmt.Sprintf("%s=%s,", kv.Key, kv.Value.Emit())
	}

	return ret
}

type stubInt64Counter struct {
	instrument.Synchronous
	values map[string]int64
	mu     sync.Mutex
}

// Add records a change to the counter.
func (c *stubInt64Counter) Add(ctx context.Context, incr int64, attrs ...attribute.KeyValue) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.values[attrsToString(attrs)] += incr
}
