// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

//go:build linux

package watcher

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// JournaldWatcher reads sshd logs from systemd's journal using journalctl.
// This approach avoids a CGO dependency on libsystemd while still providing
// reliable journald integration.
type JournaldWatcher struct {
	logger *slog.Logger
}

// NewJournaldWatcher creates a watcher for the systemd journal.
func NewJournaldWatcher(logger *slog.Logger) *JournaldWatcher {
	return &JournaldWatcher{logger: logger}
}

// Name returns the source description.
func (j *JournaldWatcher) Name() string {
	return "journald:sshd"
}

// Watch starts following the journal for sshd entries and sends each log line
// to the handler. It blocks until ctx is cancelled.
func (j *JournaldWatcher) Watch(ctx context.Context, handler LineHandler) error {
	cmd := exec.CommandContext(ctx, "journalctl",
		"-u", "sshd",
		"-u", "ssh",
		"--follow",
		"--no-pager",
		"--output=short-iso",
		"--since=now",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating journalctl stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting journalctl: %w", err)
	}

	j.logger.Info("watching journald for sshd entries")

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		handler(line)
	}

	if err := scanner.Err(); err != nil {
		if ctx.Err() != nil {
			return nil // Context cancelled; normal shutdown.
		}
		return fmt.Errorf("reading journalctl output: %w", err)
	}

	// Wait for the process to exit.
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("journalctl exited: %w", err)
	}

	return nil
}

// tryJournald attempts to create a journald watcher on Linux systems. Returns
// nil if journalctl is not available.
func tryJournald(logger *slog.Logger) Source {
	// Check if journalctl is available.
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil
	}

	// Verify we can query the journal.
	cmd := exec.Command("journalctl", "--no-pager", "-n", "0")
	if err := cmd.Run(); err != nil {
		logger.Debug("journalctl available but not usable", "error", err)
		return nil
	}

	return NewJournaldWatcher(logger)
}
