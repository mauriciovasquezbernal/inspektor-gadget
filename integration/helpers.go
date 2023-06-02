// Copyright 2022 The Inspektor Gadget authors
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

package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func parseMultiJSONOutput[T any](t *testing.T, output string, normalize func(*T)) []*T {
	ret := []*T{}

	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		var entry T
		err := decoder.Decode(&entry)
		require.Nil(t, err, "decoding json: %s", err)

		// To be able to use reflect.DeepEqual and cmp.Diff, we need to
		// "normalize" the output so that it only includes non-default values
		// for the fields we are able to verify.
		if normalize != nil {
			normalize(&entry)
		}

		ret = append(ret, &entry)
	}

	return ret
}

func parseJSONArrayOutput[T any](t *testing.T, output string, normalize func(*T)) []*T {
	entries := []*T{}

	err := json.Unmarshal([]byte(output), &entries)
	require.Nil(t, err, "unmarshaling output array: %s", err)

	for _, entry := range entries {
		// To be able to use reflect.DeepEqual and cmp.Diff, we need to
		// "normalize" the output so that it only includes non-default values
		// for the fields we are able to verify.
		if normalize != nil {
			normalize(entry)
		}
	}

	return entries
}

func parseMultipleJSONArrayOutput[T any](t *testing.T, output string, normalize func(*T)) []*T {
	allEntries := make([]*T, 0)

	sc := bufio.NewScanner(strings.NewReader(output))
	// On ARO we saw arrays with charcounts of > 100,000. Lets just set 1 MB as the limit
	sc.Buffer(make([]byte, 1024), 1024*1024)
	for sc.Scan() {
		entries := parseJSONArrayOutput(t, sc.Text(), normalize)
		allEntries = append(allEntries, entries...)
	}
	err := sc.Err()
	require.Nil(t, err, "parsing multiple JSON arrays: %s", err)

	return allEntries
}

func expectAllToMatch[T any](t *testing.T, entries []*T, expectedEntry *T) {
	require.NotEmpty(t, entries, "no output entries to match")

	for _, entry := range entries {
		require.Equal(t, expectedEntry, entry, "unexpected output entry")
	}
}

// ExpectAllToMatch verifies that the expectedEntry is matched by all the
// entries in the output (Lines of independent JSON objects).
func ExpectAllToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntry *T) {
	entries := parseMultiJSONOutput(t, output, normalize)
	expectAllToMatch(t, entries, expectedEntry)
}

// ExpectAllInArrayToMatch verifies that the expectedEntry is matched by all the
// entries in the output (JSON array of JSON objects).
func ExpectAllInArrayToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntry *T) {
	entries := parseJSONArrayOutput(t, output, normalize)
	expectAllToMatch(t, entries, expectedEntry)
}

// ExpectAllInMultipleArrayToMatch verifies that the expectedEntry is matched by all the
// entries in the output (multiple JSON array of JSON objects separated by newlines).
func ExpectAllInMultipleArrayToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntry *T) {
	entries := parseMultipleJSONArrayOutput(t, output, normalize)
	expectAllToMatch(t, entries, expectedEntry)
}

func expectEntriesToMatch[T any](t *testing.T, entries []*T, expectedEntries ...*T) {
out:
	for _, expectedEntry := range expectedEntries {
		for _, entry := range entries {
			if reflect.DeepEqual(expectedEntry, entry) {
				continue out
			}
		}
		t.Fatalf("output doesn't contain the expected entry: %+v", expectedEntry)
	}
}

// ExpectEntriesToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (Lines of independent JSON objects).
func ExpectEntriesToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntries ...*T) {
	entries := parseMultiJSONOutput(t, output, normalize)
	expectEntriesToMatch(t, entries, expectedEntries...)
}

// ExpectEntriesInArrayToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (JSON array of JSON objects).
func ExpectEntriesInArrayToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntries ...*T) {
	entries := parseJSONArrayOutput(t, output, normalize)
	expectEntriesToMatch(t, entries, expectedEntries...)
}

// ExpectEntriesInMultipleArrayToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (multiple JSON array of JSON objects separated by newlines).
func ExpectEntriesInMultipleArrayToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntries ...*T) {
	entries := parseMultipleJSONArrayOutput(t, output, normalize)
	expectEntriesToMatch(t, entries, expectedEntries...)
}

func BuildCommonData(namespace string) eventtypes.CommonData {
	return eventtypes.CommonData{
		Namespace: namespace,
		// Pod and Container name are defined by BusyboxPodCommand.
		Pod:       "test-pod",
		Container: "test-pod",
		// TODO: Include the Node
	}
}

func BuildBaseEvent(namespace string) eventtypes.Event {
	return eventtypes.Event{
		Type:       eventtypes.NORMAL,
		CommonData: BuildCommonData(namespace),
	}
}

func GetTestPodIP(ns string, podname string) (string, error) {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return string(r), nil
}

func GetPodIPsFromLabel(ns string, label string) ([]string, error) {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", "-l", label, "-o", "jsonpath={.items[*].status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return strings.Split(string(r), " "), nil
}

func GetPodNode(ns string, podname string) (string, error) {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.spec.nodeName}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return string(r), nil
}

func CheckNamespace(ns string) bool {
	cmd := exec.Command("kubectl", "get", "ns", ns)
	return cmd.Run() == nil
}
