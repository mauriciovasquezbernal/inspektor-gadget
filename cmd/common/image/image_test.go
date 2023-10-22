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
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

var testBuilderImage = flag.String("builder-image", "ghcr.io/inspektor-gadget/ebpf-builder:latest", "ebpf builder image")

func TestMain(m *testing.M) {
	flag.Parse()
	fmt.Println("Running image tests")
	os.Exit(m.Run())
}

func TestImage(t *testing.T) {
	// start registry
	r := startRegistry(t, "test-image-registry")
	t.Cleanup(func() {
		r.Stop(t)
	})
	var registryAddr string
	for _, binding := range r.PortBindings() {
		registryAddr = binding[0].HostIP + ":" + binding[0].HostPort
		break
	}

	testReg := "reg.com"
	testRepo := "repo1"
	testTag := "tag1"
	testLocalImage := filepath.Join(testReg, testRepo+":"+testTag)
	testRegistryImage := filepath.Join(registryAddr, testRepo+":"+testTag)
	oci.DefaultOciStore = t.TempDir()

	// build image
	buildCmd := NewBuildCmd()
	var buildStdout, buildStderr bytes.Buffer
	buildCmd.SetArgs([]string{"--builder-image", *testBuilderImage, "--tag", testLocalImage, "testdata/hello"})
	buildCmd.SetOut(&buildStdout)
	buildCmd.SetErr(&buildStderr)
	err := buildCmd.Execute()
	require.Nil(t, err)
	require.Equal(t, "", buildStderr.String())
	require.Contains(t, buildStdout.String(), fmt.Sprintf("Successfully built %s", testLocalImage))

	// list images
	listCmd := NewListCmd()
	var listStdout, listStderr bytes.Buffer
	listCmd.SetArgs([]string{})
	listCmd.SetOut(&listStdout)
	listCmd.SetErr(&listStderr)
	err = listCmd.Execute()
	require.Nil(t, err)
	require.Equal(t, "", listStderr.String())
	require.Contains(t, listStdout.String(), testRepo)
	require.Contains(t, listStdout.String(), testTag)

	// tag image
	tagCmd := NewTagCmd()
	var tagStdout, tagStderr bytes.Buffer
	tagCmd.SetArgs([]string{testLocalImage, testRegistryImage})
	tagCmd.SetOut(&tagStdout)
	tagCmd.SetErr(&tagStderr)
	err = tagCmd.Execute()
	require.Nil(t, err)
	require.Equal(t, "", tagStderr.String())
	require.Contains(t, tagStdout.String(), fmt.Sprintf("Successfully tagged with %s", testRegistryImage))

	// push image
	pushCmd := NewPushCmd()
	var pushStdout, pushStderr bytes.Buffer
	pushCmd.SetArgs([]string{testRegistryImage, "--insecure"})
	pushCmd.SetOut(&pushStdout)
	pushCmd.SetErr(&pushStderr)
	err = pushCmd.Execute()
	require.Nil(t, err)
	require.Equal(t, "", pushStderr.String())
	require.Contains(t, pushStdout.String(), fmt.Sprintf("Successfully pushed %s", testRegistryImage))

	// pull image
	oci.DefaultOciStore = t.TempDir()
	pullCmd := NewPullCmd()
	var pullStdout, pullStderr bytes.Buffer
	pullCmd.SetArgs([]string{testRegistryImage, "--insecure"})
	pullCmd.SetOut(&pullStdout)
	pullCmd.SetErr(&pullStderr)
	err = pullCmd.Execute()
	require.Nil(t, err)
	require.Equal(t, "", pullStderr.String())
	require.Contains(t, pullStdout.String(), fmt.Sprintf("Successfully pulled %s", testRegistryImage))
}

func startRegistry(t *testing.T, name string) testutils.Container {
	t.Helper()

	c := testutils.NewDockerContainer(name, "registry serve /etc/docker/registry/config.yml",
		testutils.WithImage("registry:2"),
		testutils.WithoutWait(),
		testutils.WithPortBindings(nat.PortMap{
			"5000/tcp": []nat.PortBinding{{HostIP: "127.0.0.1"}},
		}),
	)
	c.Start(t)
	return c
}
