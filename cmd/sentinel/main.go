// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

// Sentinel is an SSH & Login Attack Alerter daemon.
// It monitors auth logs for brute-force attempts and sends alerts via
// Slack, Telegram, Discord, or generic webhooks.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hostatlas-labs/sentinel/internal/alerter"
	"github.com/hostatlas-labs/sentinel/internal/config"
	"github.com/hostatlas-labs/sentinel/internal/parser"
	"github.com/hostatlas-labs/sentinel/internal/tracker"
	"github.com/hostatlas-labs/sentinel/internal/updater"
	"github.com/hostatlas-labs/sentinel/internal/watcher"
)

// Build-time variables set by goreleaser via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const banner = `  _   _           _      _   _   _
 | | | | ___  ___| |_   / \ | |_| | __ _ ___
 | |_| |/ _ \/ __| __| / _ \| __| |/ _` + "`" + ` / __|
 |  _  | (_) \__ \ |_ / ___ \ |_| | (_| \__ \
 |_| |_|\___/|___/\__/_/   \_\__|_|\__,_|___/
`

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sentinel",
		Short: "SSH & Login Attack Alerter",
		Long:  "Sentinel monitors SSH authentication logs and alerts on brute-force attacks.",
		RunE: func(cmd *cobra.Command, args []string) error {
			showVersion, _ := cmd.Flags().GetBool("version")
			if showVersion {
				printVersion()
				return nil
			}

			doUpdate, _ := cmd.Flags().GetBool("update")
			if doUpdate {
				return runUpdate()
			}

			// Default: show banner.
			fmt.Print(banner)
			fmt.Printf("  sentinel v%s\n\n", version)
			fmt.Println("  Usage: sentinel watch    Start monitoring")
			fmt.Println("         sentinel test     Send a test alert")
			fmt.Println("         sentinel config   Show configuration")
			fmt.Println("         sentinel --help   Show all commands")
			fmt.Println()
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.Flags().Bool("version", false, "Show version information")
	root.Flags().Bool("update", false, "Self-update from GitHub releases")

	root.AddCommand(watchCmd())
	root.AddCommand(testCmd())
	root.AddCommand(configCmd())

	return root
}

// watchCmd starts the monitoring daemon.
func watchCmd() *cobra.Command {
	var daemon bool

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Start monitoring auth logs for SSH attacks",
		Long:  "Watch auth logs in real-time and send alerts when brute-force attacks are detected.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWatch(daemon)
		},
	}

	cmd.Flags().BoolVarP(&daemon, "daemon", "d", false, "Run as background daemon")

	return cmd
}

// testCmd sends a test alert.
func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Send a test alert to all configured channels",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest()
		},
	}
}

// configCmd shows the current configuration.
func configCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfig()
		},
	}
}

// runWatch starts the main monitoring loop.
func runWatch(daemon bool) error {
	logger := newLogger()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if !cfg.HasAnyChannel() {
		return fmt.Errorf("no notification channels configured; edit %s or run `sentinel config`",
			configLocation())
	}

	// Daemonize if requested.
	if daemon {
		return daemonize()
	}

	fmt.Print(banner)
	fmt.Printf("  sentinel v%s  |  %s\n\n", version, strings.Join(cfg.ConfiguredChannels(), ", "))

	// Set up context with signal handling for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Resolve the log source.
	source, err := watcher.ResolveSource(cfg.LogSource, cfg.AuthLog, logger)
	if err != nil {
		return fmt.Errorf("resolving log source: %w", err)
	}
	logger.Info("log source resolved", "source", source.Name())

	// Initialize components.
	trk := tracker.New(cfg.Threshold.FailedAttempts, cfg.Threshold.TimeWindow, cfg.Cooldown)
	dispatch := alerter.NewDispatcher(cfg, logger)

	logger.Info("sentinel started",
		"channels", dispatch.ChannelNames(),
		"threshold", cfg.Threshold.FailedAttempts,
		"window", fmt.Sprintf("%ds", cfg.Threshold.TimeWindow),
		"cooldown", fmt.Sprintf("%ds", cfg.Cooldown),
	)

	// Start periodic cleanup of stale tracker records.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				trk.Cleanup(time.Duration(cfg.Cooldown*2) * time.Second)
				ips, attempts := trk.Stats()
				logger.Debug("tracker cleanup", "tracked_ips", ips, "total_attempts", attempts)
			}
		}
	}()

	// Define the line handler.
	handler := func(line string) {
		// Fast pre-filter.
		if !parser.IsSSHRelated(line) {
			return
		}

		event := parser.Parse(line)
		if event == nil {
			return
		}

		logger.Debug("auth failure detected",
			"ip", event.IP,
			"user", event.Username,
		)

		alert := trk.Record(event.IP, event.Username, event.Timestamp)
		if alert != nil {
			logger.Warn("threshold reached, sending alert",
				"ip", alert.IP,
				"attempts", alert.Attempts,
			)
			dispatch.Dispatch(ctx, alert)
		}
	}

	// Start watching with automatic reconnection.
	return watcher.WatchWithReconnect(ctx, source, handler, logger)
}

// runTest sends a test alert to all configured channels.
func runTest() error {
	logger := newLogger()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if !cfg.HasAnyChannel() {
		return fmt.Errorf("no notification channels configured; edit %s or run `sentinel config`",
			configLocation())
	}

	dispatch := alerter.NewDispatcher(cfg, logger)
	channels := dispatch.ChannelNames()

	fmt.Printf("Sending test alert to: %s\n", strings.Join(channels, ", "))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := dispatch.SendTest(ctx); err != nil {
		return fmt.Errorf("test alert failed: %w", err)
	}

	fmt.Println("Test alert sent successfully.")
	return nil
}

// runConfig displays the current configuration.
func runConfig() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	cfgPath := config.FilePath()
	if cfgPath == "" {
		fmt.Println("No config file found.")
		fmt.Println()
		fmt.Println("Expected locations:")
		fmt.Println("  ~/.sentinel.yml")
		fmt.Println("  /etc/sentinel/config.yml")
		fmt.Println()
		fmt.Println("Create a config file with default settings:")
		fmt.Println()
		fmt.Print(config.DefaultConfigTemplate())
		return nil
	}

	fmt.Printf("Config file: %s\n\n", cfgPath)
	fmt.Printf("Log source:      %s\n", cfg.LogSource)
	fmt.Printf("Auth log:        %s\n", cfg.AuthLog)
	fmt.Printf("Threshold:       %d failed attempts in %ds\n", cfg.Threshold.FailedAttempts, cfg.Threshold.TimeWindow)
	fmt.Printf("Cooldown:        %ds\n", cfg.Cooldown)
	fmt.Println()

	channels := cfg.ConfiguredChannels()
	if len(channels) == 0 {
		fmt.Println("Channels:        (none configured)")
	} else {
		fmt.Printf("Channels:        %s\n", strings.Join(channels, ", "))
	}

	// Show masked channel details.
	if cfg.Slack.WebhookURL != "" {
		fmt.Printf("  Slack:         %s\n", maskURL(cfg.Slack.WebhookURL))
	}
	if cfg.Telegram.BotToken != "" {
		fmt.Printf("  Telegram:      bot:%s chat:%s\n", maskString(cfg.Telegram.BotToken), cfg.Telegram.ChatID)
	}
	if cfg.Discord.WebhookURL != "" {
		fmt.Printf("  Discord:       %s\n", maskURL(cfg.Discord.WebhookURL))
	}
	if cfg.Webhook.URL != "" {
		fmt.Printf("  Webhook:       %s %s\n", cfg.Webhook.Method, maskURL(cfg.Webhook.URL))
	}

	return nil
}

// runUpdate performs a self-update from GitHub releases.
func runUpdate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	return updater.Update(ctx, version)
}

// printVersion outputs detailed version information.
func printVersion() {
	fmt.Printf("sentinel v%s\n", version)
	fmt.Printf("  commit: %s\n", commit)
	fmt.Printf("  built:  %s\n", date)
}

// daemonize forks the current process into the background. This is a simple
// implementation that re-executes the binary without the -d flag.
func daemonize() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding executable: %w", err)
	}

	// Build args without the -d/--daemon flag.
	args := []string{exe, "watch"}

	attr := &os.ProcAttr{
		Dir: "/",
		Env: os.Environ(),
		Files: []*os.File{
			os.Stdin,
			nil, // stdout → /dev/null
			nil, // stderr → /dev/null
		},
	}

	// Open /dev/null for stdout and stderr.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("opening /dev/null: %w", err)
	}
	defer devNull.Close()
	attr.Files[1] = devNull
	attr.Files[2] = devNull

	proc, err := os.StartProcess(exe, args, attr)
	if err != nil {
		return fmt.Errorf("starting daemon: %w", err)
	}

	fmt.Printf("Sentinel started as daemon (PID %d)\n", proc.Pid)

	// Detach the child process.
	if err := proc.Release(); err != nil {
		return fmt.Errorf("releasing daemon process: %w", err)
	}

	return nil
}

// newLogger creates a structured logger for sentinel.
func newLogger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	// Use debug level when SENTINEL_DEBUG is set.
	if os.Getenv("SENTINEL_DEBUG") != "" {
		opts.Level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	return slog.New(handler)
}

// configLocation returns a user-friendly description of where the config
// file should be.
func configLocation() string {
	path := config.FilePath()
	if path != "" {
		return path
	}
	return "~/.sentinel.yml"
}

// maskURL returns a URL with most of the path obscured for display.
func maskURL(u string) string {
	if len(u) <= 20 {
		return "***"
	}
	return u[:20] + "***"
}

// maskString returns a string with most characters replaced by asterisks.
func maskString(s string) string {
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "***" + s[len(s)-3:]
}
