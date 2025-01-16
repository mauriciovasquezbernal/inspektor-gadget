// Copyright 2025 The Inspektor Gadget authors
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
	"errors"
	"time"

	"oras.land/oras-go/v2/errdef"
)

const (
	retryLimit = 20
	retryDelay = 500 * time.Millisecond
)

func retry(fn func() error) error {
	for i := 0; i < retryLimit; i++ {
		err := fn()
		if err == nil {
			return nil
		}
		if !errors.Is(err, errdef.ErrRetry) {
			return err
		}

		time.Sleep(retryDelay)
	}

	return errors.New("retry limit exceeded")
}
