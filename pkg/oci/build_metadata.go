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

package oci

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
)

func loadSpec(progContent []byte) (*ebpf.CollectionSpec, error) {
	progReader := bytes.NewReader(progContent)
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil, fmt.Errorf("loading spec: %w", err)
	}
	return spec, err
}

func createOrUpdateMetadataFile(ctx context.Context, opts *BuildGadgetImageOpts) error {
	// TODO: we could perform a sanity check to be sure different architectures are the same,
	// but it's too much
	progPath, ok := opts.EBPFObjectPaths[ArchAmd64]
	if !ok {
		return fmt.Errorf("missing eBPF object for %s", ArchAmd64)
	}

	progContent, err := os.ReadFile(progPath)
	if err != nil {
		return fmt.Errorf("reading eBPF object file: %w", err)
	}

	spec, err := loadSpec(progContent)
	if err != nil {
		return fmt.Errorf("loading spec: %w", err)
	}

	_, statErr := os.Stat(opts.MetadataPath)
	update := statErr == nil

	metadata := &types.GadgetMetadata{
		Name:        "TODO: Fill the gadget name",
		Description: "TODO: Fill the gadget description",
		TraceMaps:   make(map[string]types.TraceMaps),
		Structs:     make(map[string]types.Struct),
	}

	if update {
		// load metadata file
		metadataFile, err := os.Open(opts.MetadataPath)
		if err != nil {
			return fmt.Errorf("opening metadata file: %w", err)
		}
		defer metadataFile.Close()

		if err := yaml.NewDecoder(metadataFile).Decode(metadata); err != nil {
			return fmt.Errorf("decoding metadata file: %w", err)
		}

		log.Debugf("Metadata file found, updating it")

		// TODO: this validation could be softer, just printing warnings
		if err := metadata.Validate(spec); err != nil {
			return fmt.Errorf("metadata file is wrong, fix it before continuing: %w", err)
		}
	} else {
		log.Debug("Metadata file not found, generating it")
	}

	if err := metadata.Populate(spec); err != nil {
		return fmt.Errorf("handling trace maps: %w", err)
	}

	marshalled, err := yaml.Marshal(metadata)
	if err != nil {
		return err
	}

	if err := os.WriteFile(opts.MetadataPath, marshalled, 0o644); err != nil {
		return fmt.Errorf("writing metadata file: %w", err)
	}

	// fix owner of created metadata file
	if !update {
		if err := fixMetadataOwner(opts); err != nil {
			log.Warnf("Failed to fix metadata file owner: %v", err)
		}
	}

	return nil
}
