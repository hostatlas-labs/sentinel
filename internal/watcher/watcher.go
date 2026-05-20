// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package watcher

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/nxadm/tail"
)

// LineHandler is a callback invoked for each new log line.
type LineHandler func(line string)

// Source defines the interface for log sources (file tailing, journald, etc.).
type Source interface {
	// Watch starts reading log lines and calls handler for each one.
	// It blocks until the context is cancelled.
	Watch(ctx context.Context, handler LineHandler) error

	// Name returns a human-readable description of the source.
	Name() string
}

// FileWatcher tails a log file (e.g., /var/log/auth.log) and emits lines.
type FileWatcher struct {
	path   string
	logger *slog.Logger
}

// NewFileWatcher creates a watcher for the specified log file.
func NewFileWatcher(path string, logger *slog.Logger) *FileWatcher {
	return &FileWatcher{
		path:   path,
		logger: logger,
	}
}

// Name returns the source description.
func (w *FileWatcher) Name() string {
	return fmt.Sprintf("file:%s", w.path)
}

// Watch tails the log file starting from the end and sends each new line to
// the handler. It blocks until ctx is cancelled.
func (w *FileWatcher) Watch(ctx context.Context, handler LineHandler) error {
	// Verify the file exists before attempting to tail.
	if _, err := os.Stat(w.path); err != nil {
		return fmt.Errorf("log file not accessible: %w", err)
	}

	t, err := tail.TailFile(w.path, tail.Config{
		Follow:    true,
		ReOpen:    true, // Handle log rotation.
		MustExist: true,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2}, // Seek to end.
		Poll:      true,                                 // Use polling for compatibility.
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		return fmt.Errorf("tailing %s: %w", w.path, err)
	}

	w.logger.Info("watching log file", "path", w.path)

	for {
		select {
		case <-ctx.Done():
			t.Cleanup()
			return ctx.Err()

		case line, ok := <-t.Lines:
			if !ok {
				return fmt.Errorf("tail channel closed unexpectedly")
			}
			if line.Err != nil {
				w.logger.Warn("error reading line", "error", line.Err)
				continue
			}
			handler(line.Text)
		}
	}
}

// AutoDetectSource determines the best log source based on the current system.
// It checks for journald first (systemd-based systems), then falls back to
// common auth log file locations.
func AutoDetectSource(logger *slog.Logger) (Source, error) {
	// Try journald first on Linux.
	if src := tryJournald(logger); src != nil {
		return src, nil
	}

	// Fall back to common auth log paths.
	logPaths := []string{
		"/var/log/auth.log", // Debian / Ubuntu
		"/var/log/secure",   // RHEL / CentOS / Fedora
		"/var/log/authlog",  // OpenBSD
	}

	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			return NewFileWatcher(path, logger), nil
		}
	}

	return nil, fmt.Errorf("no suitable log source found; tried journald and files: %v", logPaths)
}

// ResolveSource returns a Source based on the configuration values.
func ResolveSource(logSource, authLogPath string, logger *slog.Logger) (Source, error) {
	switch logSource {
	case "auto", "":
		return AutoDetectSource(logger)
	case "file":
		return NewFileWatcher(authLogPath, logger), nil
	case "journald":
		src := tryJournald(logger)
		if src == nil {
			return nil, fmt.Errorf("journald is not available on this system")
		}
		return src, nil
	default:
		return nil, fmt.Errorf("unknown log_source: %q (expected auto, file, or journald)", logSource)
	}
}

// WatchWithReconnect wraps a Source.Watch call with automatic reconnection on
// transient failures. It retries with exponential backoff up to a maximum
// interval.
func WatchWithReconnect(ctx context.Context, source Source, handler LineHandler, logger *slog.Logger) error {
	const (
		initialBackoff = 1 * time.Second
		maxBackoff     = 60 * time.Second
	)

	backoff := initialBackoff
	for {
		err := source.Watch(ctx, handler)
		if ctx.Err() != nil {
			// Context was cancelled; clean shutdown.
			return nil
		}
		if err != nil {
			logger.Error("watcher failed, reconnecting",
				"source", source.Name(),
				"error", err,
				"retry_in", backoff,
			)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
