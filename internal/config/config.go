// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the complete sentinel configuration.
type Config struct {
	LogSource string    `mapstructure:"log_source"`
	AuthLog   string    `mapstructure:"auth_log"`
	Threshold Threshold `mapstructure:"threshold"`
	Cooldown  int       `mapstructure:"cooldown"`
	Slack     Slack     `mapstructure:"slack"`
	Telegram  Telegram  `mapstructure:"telegram"`
	Discord   Discord   `mapstructure:"discord"`
	Webhook   Webhook   `mapstructure:"webhook"`
}

// Threshold defines when to trigger an alert.
type Threshold struct {
	FailedAttempts int `mapstructure:"failed_attempts"`
	TimeWindow     int `mapstructure:"time_window"`
}

// Slack holds Slack webhook configuration.
type Slack struct {
	WebhookURL string `mapstructure:"webhook_url"`
}

// Telegram holds Telegram bot configuration.
type Telegram struct {
	BotToken string `mapstructure:"bot_token"`
	ChatID   string `mapstructure:"chat_id"`
}

// Discord holds Discord webhook configuration.
type Discord struct {
	WebhookURL string `mapstructure:"webhook_url"`
}

// Webhook holds generic webhook configuration.
type Webhook struct {
	URL     string            `mapstructure:"url"`
	Method  string            `mapstructure:"method"`
	Headers map[string]string `mapstructure:"headers"`
}

// HasAnyChannel returns true if at least one notification channel is configured.
func (c *Config) HasAnyChannel() bool {
	return c.Slack.WebhookURL != "" ||
		(c.Telegram.BotToken != "" && c.Telegram.ChatID != "") ||
		c.Discord.WebhookURL != "" ||
		c.Webhook.URL != ""
}

// ConfiguredChannels returns the names of all configured notification channels.
func (c *Config) ConfiguredChannels() []string {
	var channels []string
	if c.Slack.WebhookURL != "" {
		channels = append(channels, "slack")
	}
	if c.Telegram.BotToken != "" && c.Telegram.ChatID != "" {
		channels = append(channels, "telegram")
	}
	if c.Discord.WebhookURL != "" {
		channels = append(channels, "discord")
	}
	if c.Webhook.URL != "" {
		channels = append(channels, "webhook")
	}
	return channels
}

// Load reads the configuration from file and environment variables.
// It searches ~/.sentinel.yml and /etc/sentinel/config.yml.
func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	// Set defaults.
	v.SetDefault("log_source", "auto")
	v.SetDefault("auth_log", "/var/log/auth.log")
	v.SetDefault("threshold.failed_attempts", 5)
	v.SetDefault("threshold.time_window", 300)
	v.SetDefault("cooldown", 600)
	v.SetDefault("webhook.method", "POST")
	v.SetDefault("webhook.headers", map[string]string{
		"Content-Type": "application/json",
	})

	// Search paths.
	home, err := os.UserHomeDir()
	if err == nil {
		v.AddConfigPath(home)
		v.SetConfigName(".sentinel")
	}
	v.AddConfigPath("/etc/sentinel")
	v.SetConfigName("config")

	// Allow environment variable overrides with SENTINEL_ prefix.
	v.SetEnvPrefix("SENTINEL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file — it is not an error if no file is found.
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

// FilePath returns the path to the config file that would be used, or an
// empty string if no config file exists.
func FilePath() string {
	home, err := os.UserHomeDir()
	if err == nil {
		p := filepath.Join(home, ".sentinel.yml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		p = filepath.Join(home, ".sentinel.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	p := "/etc/sentinel/config.yml"
	if _, err := os.Stat(p); err == nil {
		return p
	}
	p = "/etc/sentinel/config.yaml"
	if _, err := os.Stat(p); err == nil {
		return p
	}

	return ""
}

// DefaultConfigTemplate returns the default YAML configuration as a string,
// suitable for writing to a new config file.
func DefaultConfigTemplate() string {
	return `# Sentinel Configuration
# SSH & Login Attack Alerter
# https://github.com/hostatlas-labs/sentinel

# Log sources (auto-detect if not specified)
log_source: auto  # auto, file, journald

# Auth log path (when log_source: file)
auth_log: /var/log/auth.log

# Alert thresholds
threshold:
  failed_attempts: 5      # Alert after N failed attempts from same IP
  time_window: 300        # Within N seconds

# Rate limiting
cooldown: 600             # Don't re-alert for same IP within N seconds

# Notification channels (configure one or more)
slack:
  webhook_url: ""

telegram:
  bot_token: ""
  chat_id: ""

discord:
  webhook_url: ""

webhook:
  url: ""
  method: POST
  headers:
    Content-Type: application/json
`
}
