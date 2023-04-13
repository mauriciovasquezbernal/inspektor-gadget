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

//go:build !withoutebpf

package tracer

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	igprometheus "github.com/inspektor-gadget/inspektor-gadget/pkg/prometheus"
)

var hostRoot string

func init() {
	hostRoot = os.Getenv("HOST_ROOT")
}

type Tracer struct{}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	ctx := gadgetCtx.Context()

	params := gadgetCtx.GadgetParams()
	metricsConfig := params.Get(ParamConfig).AsString()
	metricsPath := params.Get(ParamMetricsPath).AsString()
	listenAddress := params.Get(ParamListenAddress).AsString()

	config, err := igprometheus.ParseConfig(filepath.Join(hostRoot, metricsConfig))
	if err != nil {
		return err
	}

	gadgetCtx.Logger().Debugf("config: %+v\n", config)

	// We need to use a custom registry, otherwise the metrics collection fails when it's
	// started / stoppped.
	// See https://github.com/open-telemetry/opentelemetry-go/issues/4032
	var opts []otelprometheus.Option
	register := prometheus.NewRegistry()
	opts = append(opts, otelprometheus.WithRegisterer(register))
	exporter, err := otelprometheus.New(opts...)
	if err != nil {
		return fmt.Errorf("initializing prometheus exporter: %w", err)
	}
	defer exporter.Shutdown(context.TODO())

	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	defer meterProvider.Shutdown(context.TODO())

	meter := meterProvider.Meter("inspektor-gadget")

	cleanup, err := igprometheus.CreateMetrics(ctx, config, meter)
	if err != nil {
		return err
	}
	defer cleanup()

	mux := http.NewServeMux()
	handler := promhttp.HandlerFor(register, promhttp.HandlerOpts{})
	mux.Handle(metricsPath, handler)

	server := &http.Server{Addr: listenAddress, Handler: mux}
	defer server.Close()

	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			gadgetCtx.Logger().Errorf("error serving http: %s", err)
			return
		}
	}()

	gadgetCtx.Logger().Infof("metrics server listening on %s", listenAddress)
	<-ctx.Done()

	return nil
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}
