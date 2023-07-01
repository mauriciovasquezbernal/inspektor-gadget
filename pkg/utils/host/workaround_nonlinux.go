//go:build !linux
// +build !linux

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

package host

func isHostNamespace(nsKind string) (bool, error) {
	panic("unsupported")
	return false, nil
}

func autoSdUnitRestart() (exit bool, err error) {
	panic("unsupported")
	return false, nil
}

func autoMount() error {
	panic("unsupported")
	return nil
}

func autoWindowsWorkaround() error {
	panic("unsupported")
	return nil
}
