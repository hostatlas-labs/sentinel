// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package alerter

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hostatlas-labs/sentinel/internal/config"
	"github.com/hostatlas-labs/sentinel/internal/tracker"
)

// Channel is the interface that all notification backends must implement.
type Channel interface {
	// Name returns a human-readable name for the channel (e.g., "slack").
	Name() string

	// Send delivers an alert message. Implementations must respect context
	// cancellation.
	Send(ctx context.Context, alert *AlertMessage) error
}

// AlertMessage is the fully rendered alert payload passed to channels.
type AlertMessage struct {
	Hostname  string
	IP        string
	Attempts  int
	Users     map[string]int
	FirstSeen time.Time
	LastSeen  time.Time
}

// Dispatcher manages a set of notification channels and sends alerts to all
// of them concurrently.
type Dispatcher struct {
	channels []Channel
	hostname string
	logger   *slog.Logger
}

// NewDispatcher creates a Dispatcher from the given configuration. It only
// registers channels that are fully configured.
func NewDispatcher(cfg *config.Config, logger *slog.Logger) *Dispatcher {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	d := &Dispatcher{
		hostname: hostname,
		logger:   logger,
	}

	if cfg.Slack.WebhookURL != "" {
		d.channels = append(d.channels, NewSlack(cfg.Slack.WebhookURL))
	}
	if cfg.Telegram.BotToken != "" && cfg.Telegram.ChatID != "" {
		d.channels = append(d.channels, NewTelegram(cfg.Telegram.BotToken, cfg.Telegram.ChatID))
	}
	if cfg.Discord.WebhookURL != "" {
		d.channels = append(d.channels, NewDiscord(cfg.Discord.WebhookURL))
	}
	if cfg.Webhook.URL != "" {
		method := cfg.Webhook.Method
		if method == "" {
			method = "POST"
		}
		d.channels = append(d.channels, NewWebhook(cfg.Webhook.URL, method, cfg.Webhook.Headers))
	}

	return d
}

// ChannelCount returns the number of configured channels.
func (d *Dispatcher) ChannelCount() int {
	return len(d.channels)
}

// ChannelNames returns the names of all configured channels.
func (d *Dispatcher) ChannelNames() []string {
	names := make([]string, len(d.channels))
	for i, ch := range d.channels {
		names[i] = ch.Name()
	}
	return names
}

// Dispatch sends an alert to all configured channels concurrently. It logs
// errors but does not return them — a failure in one channel must not block
// the others.
func (d *Dispatcher) Dispatch(ctx context.Context, alert *tracker.Alert) {
	msg := &AlertMessage{
		Hostname:  d.hostname,
		IP:        alert.IP,
		Attempts:  alert.Attempts,
		Users:     alert.Users,
		FirstSeen: alert.FirstSeen,
		LastSeen:  alert.LastSeen,
	}

	var wg sync.WaitGroup
	for _, ch := range d.channels {
		wg.Add(1)
		go func(c Channel) {
			defer wg.Done()
			if err := c.Send(ctx, msg); err != nil {
				d.logger.Error("failed to send alert",
					"channel", c.Name(),
					"ip", alert.IP,
					"error", err,
				)
			} else {
				d.logger.Info("alert sent",
					"channel", c.Name(),
					"ip", alert.IP,
					"attempts", alert.Attempts,
				)
			}
		}(ch)
	}
	wg.Wait()
}

// SendTest sends a test alert to all configured channels.
func (d *Dispatcher) SendTest(ctx context.Context) error {
	msg := &AlertMessage{
		Hostname:  d.hostname,
		IP:        "203.0.113.42",
		Attempts:  12,
		Users:     map[string]int{"root": 8, "admin": 3, "ubuntu": 1},
		FirstSeen: time.Now().Add(-5 * time.Minute),
		LastSeen:  time.Now(),
	}

	var errs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ch := range d.channels {
		wg.Add(1)
		go func(c Channel) {
			defer wg.Done()
			if err := c.Send(ctx, msg); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", c.Name(), err))
				mu.Unlock()
			}
		}(ch)
	}
	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("some channels failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

// FormatUserList returns a sorted, human-readable summary of targeted users.
// Example: "root (8), admin (3), ubuntu (1)"
func FormatUserList(users map[string]int) string {
	type userCount struct {
		name  string
		count int
	}

	sorted := make([]userCount, 0, len(users))
	for name, count := range users {
		sorted = append(sorted, userCount{name, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	parts := make([]string, len(sorted))
	for i, uc := range sorted {
		parts[i] = fmt.Sprintf("%s (%d)", uc.name, uc.count)
	}
	return strings.Join(parts, ", ")
}

// FormatDuration returns a human-readable representation of the time span
// between first and last seen.
func FormatDuration(first, last time.Time) string {
	d := last.Sub(first)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
}
