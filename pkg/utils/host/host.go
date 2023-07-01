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

// Package host provides ways to access the host filesystem.
//
// Inspektor Gadget can run either in the host or in a container. When running
// in a container, the host filesystem must be available in a specific
// directory.
package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	HostRoot   string
	HostProcFs string
)

func init() {
	// Initialize HostRoot and HostProcFs
	HostRoot = os.Getenv("HOST_ROOT")
	if HostRoot == "" {
		HostRoot = "/"
	}
	HostProcFs = filepath.Join(HostRoot, "/proc")
}

type Config struct {
	// AutoMount will automatically mount bpffs, debugfs and tracefs if they
	// are not already mounted.
	//
	// This is useful for some environments where those filesystems are not
	// mounted by default on the host, such as:
	// - minikube with the Docker driver
	// - Docker Desktop with WSL2
	// - Talos Linux
	AutoMount bool

	// AutoWindowsWorkaround will automatically apply workarounds to make
	// Inspektor Gadget work on Docker Desktop on Windows.
	AutoWindowsWorkaround bool
}

var (
	autoSdUnitRestartFlag bool
	initDone              bool

	isHostPidNs bool
	isHostNetNs bool
)

func Init(config Config) error {
	var err error

	// Init() is called both from the local runtime and the local manager operator.
	// Different gadgets (trace-exec and top-ebpf) have different code paths, and we need both to make both work.
	// TODO: understand why we need to call Init() twice and fix it.
	if initDone {
		return nil
	}

	// Apply workarounds
	if autoSdUnitRestartFlag {
		exit, err := autoSdUnitRestart()
		if exit {
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		if err != nil {
			return err
		}
	}
	if config.AutoMount {
		err = autoMount()
		if err != nil {
			return err
		}
	}
	if config.AutoWindowsWorkaround {
		err = autoWindowsWorkaround()
		if err != nil {
			return err
		}
	}

	// Initialize IsHost*Ns once and cache the result
	isHostPidNs, err = isHostNamespace("pid")
	if err != nil {
		return err
	}
	isHostNetNs, err = isHostNamespace("net")
	if err != nil {
		return err
	}

	initDone = true
	return nil
}

// IsHostPidNs returns true if the current process is running in the host PID namespace
func IsHostPidNs() bool {
	if !initDone {
		panic("host.Init() not called")
	}
	return isHostPidNs
}

// IsHostNetNs returns true if the current process is running in the host network namespace
func IsHostNetNs() bool {
	if !initDone {
		panic("host.Init() not called")
	}
	return isHostNetNs
}

// AddAutoSdUnitRestartFlag adds a CLI flag to allow re-execute the process
// in a privileged systemd unit if the current process does not have enough
// capabilities.
//
// This is useful for the "kubectl debug node" command.
func AddAutoSdUnitRestartFlag(command *cobra.Command) {
	command.PersistentFlags().BoolVarP(
		&autoSdUnitRestartFlag,
		"auto-sd-unit-restart",
		"",
		false,
		"Automatically run in a privileged systemd unit if lacking enough capabilities",
	)
}

func GetProcComm(pid int) string {
	pidStr := fmt.Sprint(pid)
	commBytes, _ := os.ReadFile(filepath.Join(HostProcFs, pidStr, "comm"))
	return strings.TrimRight(string(commBytes), "\n")
}

func GetProcCmdline(pid int) []string {
	pidStr := fmt.Sprint(pid)
	cmdlineBytes, _ := os.ReadFile(filepath.Join(HostProcFs, pidStr, "cmdline"))
	return strings.Split(string(cmdlineBytes), "\x00")
}
