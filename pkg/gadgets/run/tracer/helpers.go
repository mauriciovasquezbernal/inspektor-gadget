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

package tracer

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// getAnyMapElem returns any element of a map. If the map is empty, it returns nil, nil.
func getAnyMapElem[K comparable, V any](m map[K]V) (*K, *V) {
	for k, v := range m {
		return &k, &v
	}
	return nil, nil
}

func loadSpec(progContent []byte) (*ebpf.CollectionSpec, error) {
	progReader := bytes.NewReader(progContent)
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil, fmt.Errorf("loading spec: %w", err)
	}
	return spec, err
}

func getEventTypeBTF(progContent []byte, metadata *types.GadgetMetadata) (*btf.Struct, error) {
	spec, err := loadSpec(progContent)
	if err != nil {
		return nil, err
	}

	switch {
	case len(metadata.Tracers) > 0:
		_, tracer := getAnyMapElem(metadata.Tracers)
		var valueStruct *btf.Struct
		if err := spec.Types.TypeByName(tracer.StructName, &valueStruct); err != nil {
			return nil, fmt.Errorf("finding struct %q in eBPF object: %w", tracer.StructName, err)
		}

		return valueStruct, nil
	case len(metadata.Snapshotters) > 0:
		var btfStruct *btf.Struct
		_, snapshotter := getAnyMapElem(metadata.Snapshotters)
		if err := spec.Types.TypeByName(snapshotter.StructName, &btfStruct); err != nil {
			return nil, err
		}
		return btfStruct, nil
	default:
		return nil, fmt.Errorf("the gadget doesn't provide any compatible way to show information")
	}
}

func getGadgetInfo(params *params.Params, args []string, logger logger.Logger) (*types.GadgetInfo, error) {
	authOpts := &oci.AuthOptions{
		AuthFile: params.Get(authfileParam).AsString(),
		Insecure: params.Get(insecureParam).AsBool(),
	}
	gadget, err := oci.GetGadgetImage(context.TODO(), args[0], authOpts, params.Get(pullParam).AsString())
	if err != nil {
		return nil, fmt.Errorf("getting gadget image: %w", err)
	}

	ret := &types.GadgetInfo{
		ProgContent:    gadget.EbpfObject,
		WasmContent:    gadget.WasmObject,
		GadgetMetadata: &types.GadgetMetadata{},
	}

	spec, err := loadSpec(ret.ProgContent)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(gadget.Metadata, ocispec.DescriptorEmptyJSON.Data) {
		// metadata is not present. synthesize something on the fly from the spec
		if err := ret.GadgetMetadata.Populate(spec); err != nil {
			return nil, err
		}
	} else {
		validate := params.Get(validateMetadataParam).AsBool()

		if err := yaml.Unmarshal(gadget.Metadata, &ret.GadgetMetadata); err != nil {
			return nil, fmt.Errorf("unmarshaling metadata: %w", err)
		}

		if err := ret.GadgetMetadata.Validate(spec); err != nil {
			if !validate {
				logger.Warnf("gadget metadata is not valid: %v", err)
			} else {
				return nil, fmt.Errorf("gadget metadata is not valid: %w", err)
			}
		}
	}

	if err := fillTypeHints(spec, ret.GadgetMetadata.EBPFParams); err != nil {
		return nil, fmt.Errorf("fill parameters type hints: %w", err)
	}

	ret.GadgetType, err = getGadgetType(ret.GadgetMetadata)
	if err != nil {
		return nil, err
	}

	ret.Columns, err = calculateColumnsForClient(ret.GadgetMetadata, gadget.EbpfObject)
	if err != nil {
		return nil, err
	}

	ret.Features, err = getGadgetFeatures(spec, ret)
	if err != nil {
		return nil, fmt.Errorf("getting gadget features: %w", err)
	}

	// needs to be done after getGadgetFeatures
	ret.OperatorsParamsCollection = operators.GetOperatorsForContainerizedGadget(ret).ParamDescCollection()

	return ret, nil
}

// getGadgetType returns the type of the gadget according to the gadget being run.
func getGadgetType(gadgetMetadata *types.GadgetMetadata) (gadgets.GadgetType, error) {
	switch {
	case len(gadgetMetadata.Tracers) > 0:
		return gadgets.TypeTrace, nil
	case len(gadgetMetadata.Snapshotters) > 0:
		return gadgets.TypeOneShot, nil
	default:
		return gadgets.TypeUnknown, fmt.Errorf("unknown gadget type")
	}
}

func getGadgetFeatures(spec *ebpf.CollectionSpec, info *types.GadgetInfo) (types.GadgetFeatures, error) {
	features := types.GadgetFeatures{}

	eventType, err := getEventTypeBTF(info.ProgContent, info.GadgetMetadata)
	if err != nil {
		return types.GadgetFeatures{}, fmt.Errorf("getting value struct: %w", err)
	}

	for _, member := range eventType.Members {
		switch member.Type.TypeName() {
		case types.MntNsIdTypeName:
			features.HasMountNs = true
		case types.L3EndpointTypeName, types.L4EndpointTypeName:
			features.HasEndpoints = true
		}
	}

	for _, p := range spec.Programs {
		if p.Type == ebpf.SocketFilter && strings.HasPrefix(p.SectionName, "socket") {
			features.IsAttacher = true
			// TODO: info.Features.HasNetNs = true
			// However it creates an issue because the netns column is added twice!
		}

		if p.Type == ebpf.Tracing && strings.HasPrefix(p.SectionName, "iter/") {
			switch p.AttachTo {
			case "tcp", "udp":
				features.IsAttacher = true
				features.HasNetNs = true
			}
		}
	}

	for _, p := range spec.Maps {
		if p.Name == gadgets.MntNsFilterMapName {
			features.CanFilterByMountNs = true
		}
	}

	return features, nil
}

// fillTypeHints fills the TypeHint field in the ebpf parameters according to the BTF information
// about those constants.
func fillTypeHints(spec *ebpf.CollectionSpec, params map[string]types.EBPFParam) error {
	for varName, p := range params {
		var btfVar *btf.Var
		err := spec.Types.TypeByName(varName, &btfVar)
		if err != nil {
			return fmt.Errorf("no BTF type found for: %s: %w", p.Key, err)
		}

		btfConst, ok := btfVar.Type.(*btf.Const)
		if !ok {
			return fmt.Errorf("type for %s is not a constant, got %s", p.Key, btfVar.Type)
		}

		p.TypeHint = getTypeHint(btfConst.Type)
		params[varName] = p
	}

	return nil
}

func getTypeHint(typ btf.Type) params.TypeHint {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return params.TypeInt8
			case 2:
				return params.TypeInt16
			case 4:
				return params.TypeInt32
			case 8:
				return params.TypeInt64
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return params.TypeUint8
			case 2:
				return params.TypeUint16
			case 4:
				return params.TypeUint32
			case 8:
				return params.TypeUint64
			}
		case btf.Bool:
			return params.TypeBool
		case btf.Char:
			return params.TypeUint8
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return params.TypeFloat32
		case 8:
			return params.TypeFloat64
		}
	case *btf.Typedef:
		typ, err := getUnderlyingType(typedMember)
		if err != nil {
			return params.TypeUnknown
		}
		return getTypeHint(typ)
	case *btf.Volatile:
		return getTypeHint(typedMember.Type)
	}

	return params.TypeUnknown
}

func getUnderlyingType(tf *btf.Typedef) (btf.Type, error) {
	switch typedMember := tf.Type.(type) {
	case *btf.Typedef:
		return getUnderlyingType(typedMember)
	default:
		return typedMember, nil
	}
}

func getType(typ btf.Type) reflect.Type {
	switch typedMember := typ.(type) {
	case *btf.Array:
		arrType := getSimpleType(typedMember.Type)
		if arrType == nil {
			return nil
		}
		return reflect.ArrayOf(int(typedMember.Nelems), arrType)
	default:
		return getSimpleType(typ)
	}
}

func getSimpleType(typ btf.Type) reflect.Type {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(int8(0))
			case 2:
				return reflect.TypeOf(int16(0))
			case 4:
				return reflect.TypeOf(int32(0))
			case 8:
				return reflect.TypeOf(int64(0))
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(uint8(0))
			case 2:
				return reflect.TypeOf(uint16(0))
			case 4:
				return reflect.TypeOf(uint32(0))
			case 8:
				return reflect.TypeOf(uint64(0))
			}
		case btf.Bool:
			return reflect.TypeOf(bool(false))
		case btf.Char:
			return reflect.TypeOf(uint8(0))
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return reflect.TypeOf(float32(0))
		case 8:
			return reflect.TypeOf(float64(0))
		}
	case *btf.Typedef:
		typ, _ := getUnderlyingType(typedMember)
		return getSimpleType(typ)
	}

	return nil
}

// functions to send columns from server to client
func typeFromBTF(typ btf.Type) *types.Type {
	switch typedMember := typ.(type) {
	case *btf.Array:
		arrType := simpleTypeFromBTF(typedMember.Type)
		if arrType == nil {
			return nil
		}
		return &types.Type{Name: arrType.Name, Size: int(typedMember.Nelems)}
	default:
		return simpleTypeFromBTF(typ)
	}
}

func simpleTypeFromBTF(typ btf.Type) *types.Type {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return &types.Type{Name: "int8"}
			case 2:
				return &types.Type{Name: "int16"}
			case 4:
				return &types.Type{Name: "int32"}
			case 8:
				return &types.Type{Name: "int64"}
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return &types.Type{Name: "uint8"}
			case 2:
				return &types.Type{Name: "int16"}
			case 4:
				return &types.Type{Name: "int32"}
			case 8:
				return &types.Type{Name: "int64"}
			}
		case btf.Bool:
			return &types.Type{Name: "bool"}
		case btf.Char:
			return &types.Type{Name: "uint8"}
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return &types.Type{Name: "float32"}
		case 8:
			return &types.Type{Name: "float64"}
		}
	case *btf.Typedef:
		typ, _ := getUnderlyingType(typedMember)
		return simpleTypeFromBTF(typ)
	}

	return nil
}

func calculateColumnsForClient(gadgetMetadata *types.GadgetMetadata, progContent []byte) ([]types.ColumnDesc, error) {
	eventType, err := getEventTypeBTF(progContent, gadgetMetadata)
	if err != nil {
		return nil, fmt.Errorf("getting value struct: %w", err)
	}

	colNames := map[string]struct{}{}

	eventStruct, ok := gadgetMetadata.Structs[eventType.Name]
	if !ok {
		return nil, fmt.Errorf("struct %s not found in gadget metadata", eventType.Name)
	}

	for _, field := range eventStruct.Fields {
		colNames[field.Name] = struct{}{}
	}

	columns := []types.ColumnDesc{}

	for _, member := range eventType.Members {
		member := member

		_, ok := colNames[member.Name]
		if !ok {
			continue
		}

		switch member.Type.TypeName() {
		case types.L3EndpointTypeName:
			col := types.ColumnDesc{
				Name:  member.Name,
				Index: -1,
				Type:  types.Type{Name: "l3endpoint"},
			}
			columns = append(columns, col)
			continue
		case types.L4EndpointTypeName:
			// Add the column that is enriched
			col := types.ColumnDesc{
				Name:  member.Name,
				Index: -1,
				Type:  types.Type{Name: "l4endpoint"},
			}
			columns = append(columns, col)
			continue
		case types.TimestampTypeName:
			col := types.ColumnDesc{
				Name:  member.Name,
				Index: -1,
				Type:  types.Type{Name: "timestamp"},
			}
			columns = append(columns, col)
			continue
		}

		rType := typeFromBTF(member.Type)
		if rType == nil {
			continue
		}

		col := types.ColumnDesc{
			Name:   member.Name,
			Type:   *rType,
			Offset: uintptr(member.Offset.Bytes()),
		}

		columns = append(columns, col)
	}

	return columns, nil
}
