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
	"gopkg.in/yaml.v3"
)

type Metric struct {
	Name     string   `yaml:"name,omitempty"`
	Category string   `yaml:"category,omitempty"`
	Gadget   string   `yaml:"gadget,omitempty"`
	Type     string   `yaml:"type,omitempty"`
	Field    string   `yaml:"field,omitempty"`
	Labels   []string `yaml:"labels,omitempty"`
	Selector []string `yaml:"selector,omitempty"`
}

type Config struct {
	Metrics []Metric `yaml:"metrics,omitempty"`
}

func ParseConfig(content string) (*Config, error) {
	configBytes := []byte(content)
	config := &Config{}
	if err := yaml.Unmarshal(configBytes, config); err != nil {
		return nil, err
	}

	return config, nil
}
