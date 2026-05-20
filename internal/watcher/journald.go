// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

//go:build !linux

package watcher

import "log/slog"

// tryJournald returns nil on non-Linux platforms where journald is not available.
func tryJournald(logger *slog.Logger) Source {
	return nil
}
