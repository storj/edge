// Copyright (C) 2022 Storj Labs, Inc.
// See LICENSE for copying information.

package testconfiglock

import (
	"bufio"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"storj.io/common/testcontext"
)

var createLock = flag.Bool("generate-config-lock", false, "")

const lockPath = "config.yaml.lock"
const notificationMessage = `The config does not match the lock file. (-want +got):

%s

Notify the #config-changes channel so they can plan for changing it in the release process.
Once you have notified them and got their confirmation, you can update the lock file by running: "go generate ./cmd/%s"`

// Check tests or updates config lock file.
func Check(t *testing.T, name string) {
	t.Parallel()

	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	// run the executable to create a config file
	tmp := ctx.Dir(name + "-cfg-lock")
	exe := ctx.Compile("storj.io/gateway-mt/cmd/" + name)
	cmd := exec.Command(exe, "--config-dir", tmp, "--defaults", "release", "setup")
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "Error running %s: %s", name, out)

	cleanedUpConfig := filepath.Join(tmp, "config-normalized.yaml")
	// normalize certain OS-specific paths that occur in the config
	normalizeConfig(ctx, t, filepath.Join(tmp, "config.yaml"), cleanedUpConfig, tmp)

	// either compare or save the lock file
	if *createLock { // update lockPath
		// copy using ReadFile/WriteFile; os.Rename() won't work across drives
		input, err := os.ReadFile(cleanedUpConfig)
		require.NoErrorf(t, err, "Error reading file for move")
		err = os.WriteFile(lockPath, input, 0644)
		require.NoErrorf(t, err, "Error writing file for move")
	} else { // compare to lockPath
		old := readLines(t, lockPath)
		new := readLines(t, cleanedUpConfig)
		if diff := cmp.Diff(old, new); diff != "" {
			t.Errorf(notificationMessage, diff, name)
		}
	}
}

// readLines takes a file path and returns the contents split by lines.
func readLines(t *testing.T, filePath string) []string {
	file, err := os.ReadFile(filePath)
	require.NoErrorf(t, err, "Error opening %s", filePath)
	return strings.Split(strings.ReplaceAll(string(file), "\r\n", "\n"), "\n")
}

// normalizeConfig replaces platform-specific Storj paths as if everything ran
// on a Linux host.
func normalizeConfig(ctx *testcontext.Context, t *testing.T, configIn, configOut, tempDir string) {
	in, err := os.Open(configIn)
	require.NoErrorf(t, err, "Error opening %s", configIn)
	defer ctx.Check(in.Close)

	out, err := os.Create(configOut)
	require.NoErrorf(t, err, "Error opening %s", configOut)
	defer ctx.Check(out.Close)

	scanner, writer := bufio.NewScanner(in), bufio.NewWriter(out)
	defer ctx.Check(writer.Flush)

	for scanner.Scan() {
		line := scanner.Text()
		// fix metrics.app and tracing.app
		line = strings.Replace(line, ".exe", "", 1)
		// fix cert-dir
		line = strings.Replace(line, tempDir, "testdata", 1)
		_, err = writer.WriteString(line + "\n")
		require.NoErrorf(t, err, "Error writing to %s", configOut)
	}
	require.NoErrorf(t, scanner.Err(), "Error reading from %s", configIn)
}
