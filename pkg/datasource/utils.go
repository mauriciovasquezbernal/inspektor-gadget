// Copyright 2024 The Inspektor Gadget authors
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

package datasource

import "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"

// AddFieldOnParentOrDatasource creates a subfield on the parent of "field" if
// it exists, otherwise it creates a field on the data source.
func AddFieldOnParentOrDatasource(field FieldAccessor, ds DataSource, name string, kind api.Kind, opts ...FieldOption) (FieldAccessor, error) {
	if parent := field.Parent(); parent != nil {
		return parent.AddSubField(name, kind, opts...)
	}
	return ds.AddField(name, kind, opts...)
}
