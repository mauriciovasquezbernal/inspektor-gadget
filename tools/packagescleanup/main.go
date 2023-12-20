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

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/google/go-github/v57/github"
)

type pkgsInterface interface {
	ListPackages(ctx context.Context, user string, opts *github.PackageListOptions) ([]*github.Package, *github.Response, error)
	PackageGetAllVersions(ctx context.Context, username, packageType, packageName string, opts *github.PackageListOptions) ([]*github.PackageVersion, *github.Response, error)
	PackageDeleteVersion(ctx context.Context, username, packageType, packageName string, packageVersionID int64) (*github.Response, error)
}

func cleanUpTag(client *github.Client, ctx context.Context, username, tag string) error {
	if !strings.HasPrefix(tag, "citest-") {
		return fmt.Errorf("tag %q doesn't start with citest-", tag)

	}

	var service pkgsInterface
	user, _, err := client.Users.Get(ctx, username)
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}

	switch *user.Type {
	case "User":
		service = client.Users
	case "Organization":
		service = client.Organizations
	default:
		return fmt.Errorf("invalid user type: %s", *user.Type)
	}

	container := "container"
	active := "active"

	opts := &github.PackageListOptions{
		PackageType: &container,
		State:       &active,
	}

	packages, _, err := service.ListPackages(ctx, username, opts)
	if err != nil {
		return fmt.Errorf("listing packages: %w", err)
	}

	for _, p := range packages {
		if p.Name == nil {
			continue
		}

		escapedName := url.QueryEscape(*p.Name)

		opts := &github.PackageListOptions{
			State: &active,
		}
		versions, _, err := service.PackageGetAllVersions(ctx, username, "container", escapedName, opts)
		if err != nil {
			return fmt.Errorf("getting package versions: %w", err)
		}

		for _, version := range versions {
			if version.Metadata == nil || version.Metadata.Container == nil {
				continue
			}

			for _, t := range version.Metadata.Container.Tags {
				if t != tag {
					continue
				}

				fmt.Printf("removing tag %q in repo %q\n", t, *p.Name)

				_, err := service.PackageDeleteVersion(ctx, username, "container", escapedName, *version.ID)
				if err != nil {
					return fmt.Errorf("removing package version: %s", err)
				}

				fmt.Printf("removed: %s\n", t)
			}
		}
	}

	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("usage: %s username tag\n", os.Args[0])
		return
	}

	client := github.NewClient(nil)

	client.WithAuthToken(os.Getenv("TOKEN"))

	ctx := context.Background()

	userName := os.Args[1]
	tagToRemove := os.Args[2]

	if err := cleanUpTag(client, ctx, userName, tagToRemove); err != nil {
		fmt.Printf("error cleaning tags: %s\n", err)
	}
}
