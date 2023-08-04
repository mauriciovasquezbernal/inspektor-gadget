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

package image

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
)

type pullOptions struct {
	image    string
	authOpts utils.AuthOptions
}

func NewPullCmd() *cobra.Command {
	o := pullOptions{}
	cmd := &cobra.Command{
		Use:          "pull IMAGE",
		Short:        "Pull the specified image from a remote registry",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected exactly one argument")
			}
			o.image = args[0]
			return runPull(o)
		},
	}

	utils.SetupAuthVariablesAndFlags(cmd, &o.authOpts)
	return cmd
}

func runPull(o pullOptions) error {
	ociStore, err := utils.GetLocalOciStore()
	if err != nil {
		return fmt.Errorf("get oci store: %w", err)
	}

	repository, err := utils.GetRepositoryFromImage(o.image)
	if err != nil {
		return fmt.Errorf("get repository from image %q: %w", o.image, err)
	}
	client, err := utils.CreateAuthClient(repository, &o.authOpts)
	if err != nil {
		return fmt.Errorf("create auth client: %w", err)
	}
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return fmt.Errorf("create remote repository: %w", err)
	}
	repo.Client = client

	targetImage, err := utils.NormalizeImage(o.image)
	if err != nil {
		return fmt.Errorf("normalize image: %w", err)
	}
	fmt.Printf("Pulling %s...\n", targetImage)
	desc, err := oras.Copy(context.TODO(), repo, targetImage, ociStore, targetImage, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("copy to remote repository: %w", err)
	}

	fmt.Printf("Successfully pulled %s@%s\n", targetImage, desc.Digest)
	return nil
}
