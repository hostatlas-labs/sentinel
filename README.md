# Sentinel

[![Release](https://img.shields.io/github/v/release/hostatlas-labs/sentinel?style=flat-square)](https://github.com/hostatlas-labs/sentinel/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/hostatlas-labs/sentinel?style=flat-square)](https://goreportcard.com/report/github.com/hostatlas-labs/sentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

```
  _   _           _      _   _   _
 | | | | ___  ___| |_   / \ | |_| | __ _ ___
 | |_| |/ _ \/ __| __| / _ \| __| |/ _` / __|
 |  _  | (_) \__ \ |_ / ___ \ |_| | (_| \__ \
 |_| |_|\___/|___/\__/_/   \_\__|_|\__,_|___/
```

A lightweight SSH & Login Attack Alerter daemon. Monitors `auth.log` and `journald` for brute-force attempts and sends real-time alerts via **Slack**, **Telegram**, **Discord**, or **webhooks**.

Single binary. 2-minute setup. Zero dependencies.

## Features

- **Real-time monitoring** of `/var/log/auth.log`, `/var/log/secure`, or `journald`
- **Smart detection** — configurable thresholds (N failures within M seconds)
- **Multi-channel alerts** — Slack, Telegram, Discord, generic webhooks
- **Cooldown** — no alert spam; rate-limited per IP
- **Auto-detect** log source (journald vs. file)
- **Log rotation aware** — handles `logrotate` seamlessly
- **Graceful shutdown** — clean SIGINT/SIGTERM handling
- **Self-update** — update in place from GitHub releases
- **Tiny footprint** — single static binary, zero runtime deps

## Quick Start

### Install

**One-liner:**

```bash
curl -fsSL https://tools.hostatlas.app/install.sh | sh -s sentinel
```

The installer detects your OS + architecture, downloads the right
binary, verifies the SHA-256, and installs to `/usr/local/bin`.

Add `--user` for a `$HOME/.local/bin` install without sudo, or
`--version=1.0.0` to pin a specific release.

**With Go:**

```bash
go install github.com/hostatlas-labs/sentinel/cmd/sentinel@latest
```

**Homebrew (macOS, Linuxbrew):**

```bash
brew install hostatlas-labs/tap/sentinel
```

**Manual:** Browse all releases at [github.com/hostatlas-labs/sentinel/releases](https://github.com/hostatlas-labs/sentinel/releases) or [tools.hostatlas.app](https://tools.hostatlas.app/tools.json).

### Configure

```bash
cat > ~/.sentinel.yml << 'EOF'
threshold:
  failed_attempts: 5
  time_window: 300

cooldown: 600

slack:
  webhook_url: "https://hooks.slack.com/services/T00/B00/xxx"
EOF
```

### Run

```bash
# Test your configuration
sentinel test

# Start monitoring (foreground)
sentinel watch

# Start as daemon
sentinel watch -d
```

## Usage

```
sentinel              Show banner and version
sentinel watch        Start monitoring (foreground)
sentinel watch -d     Start as background daemon
sentinel test         Send a test alert to configured channels
sentinel config       Show current configuration
sentinel --update     Self-update from GitHub releases
sentinel --version    Show version
```

## Configuration

Sentinel searches for configuration in this order:

1. `~/.sentinel.yml`
2. `/etc/sentinel/config.yml`

Environment variables with `SENTINEL_` prefix override config file values.

### Full Configuration Reference

```yaml
# Log source: auto, file, or journald
log_source: auto

# Auth log path (when log_source is "file")
auth_log: /var/log/auth.log

# Alert thresholds
threshold:
  failed_attempts: 5      # Alert after N failed attempts from same IP
  time_window: 300        # Within N seconds

# Rate limiting
cooldown: 600             # Don't re-alert for same IP within N seconds

# Slack
slack:
  webhook_url: "https://hooks.slack.com/services/..."

# Telegram
telegram:
  bot_token: "123456:ABC-DEF1234..."
  chat_id: "-1001234567890"

# Discord
discord:
  webhook_url: "https://discord.com/api/webhooks/..."

# Generic webhook
webhook:
  url: "https://your-api.example.com/alerts"
  method: POST
  headers:
    Content-Type: application/json
    Authorization: "Bearer your-token"
```

### Environment Variables

| Variable | Config equivalent |
|---|---|
| `SENTINEL_LOG_SOURCE` | `log_source` |
| `SENTINEL_AUTH_LOG` | `auth_log` |
| `SENTINEL_THRESHOLD_FAILED_ATTEMPTS` | `threshold.failed_attempts` |
| `SENTINEL_THRESHOLD_TIME_WINDOW` | `threshold.time_window` |
| `SENTINEL_COOLDOWN` | `cooldown` |
| `SENTINEL_SLACK_WEBHOOK_URL` | `slack.webhook_url` |
| `SENTINEL_TELEGRAM_BOT_TOKEN` | `telegram.bot_token` |
| `SENTINEL_TELEGRAM_CHAT_ID` | `telegram.chat_id` |
| `SENTINEL_DISCORD_WEBHOOK_URL` | `discord.webhook_url` |
| `SENTINEL_WEBHOOK_URL` | `webhook.url` |

## Alert Format

When an attack is detected, you receive an alert like this:

```
🚨 SSH Attack Detected

Host:            production-web-01
Attacker IP:     45.142.120.71
Failed attempts: 12 in 5 minutes
Target users:    root (8), admin (3), ubuntu (1)
First seen:      2026-04-16 14:23:01
Last seen:       2026-04-16 14:27:45
```

Each channel renders this information in its native format (Slack blocks, Telegram HTML, Discord embeds, or JSON webhook).

### Webhook JSON Payload

```json
{
  "host": "production-web-01",
  "ip": "45.142.120.71",
  "attempts": 12,
  "users": {"root": 8, "admin": 3, "ubuntu": 1},
  "first_seen": "2026-04-16T14:23:01Z",
  "last_seen": "2026-04-16T14:27:45Z",
  "timestamp": "2026-04-16T14:27:46Z"
}
```

## Detected Attack Patterns

Sentinel recognizes these SSH failure patterns:

| Pattern | Example |
|---|---|
| Failed password | `Failed password for root from 1.2.3.4 port 22` |
| Invalid user | `Invalid user admin from 1.2.3.4 port 22` |
| Connection closed (preauth) | `Connection closed by authenticating user root 1.2.3.4 port 22 [preauth]` |
| PAM auth failure | `pam_unix(sshd:auth): authentication failure; ... rhost=1.2.3.4` |
| Keyboard-interactive failure | `Failed keyboard-interactive/pam for root from 1.2.3.4 port 22` |
| Disconnected (preauth) | `Disconnected from authenticating user root 1.2.3.4 port 22 [preauth]` |

## Systemd Service

To run Sentinel as a system service:

```bash
sudo tee /etc/systemd/system/sentinel.service << 'EOF'
[Unit]
Description=Sentinel SSH Attack Alerter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel watch
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sentinel
```

## Building from Source

```bash
git clone https://github.com/hostatlas-labs/sentinel.git
cd sentinel
go build -o sentinel ./cmd/sentinel
```

## Self-Update

```bash
sentinel --update
```

This checks GitHub releases for a newer version and replaces the binary in place.

## How It Compares

| | sentinel | fail2ban | sshguard | CrowdSec |
|---|---|---|---|---|
| Reads `auth.log` / journald | ✓ | ✓ | ✓ | ✓ |
| Sends alerts (Slack / Telegram / Discord / webhook) | ✓ | partial (scripts) | — | ✓ |
| Modifies iptables / firewall | — | ✓ | ✓ | ✓ |
| Single binary, no daemon for the firewall | ✓ | — | — | — |
| Setup time | < 2 min | 15-30 min | 10 min | 30 min |
| Footprint | tiny | medium | small | medium |

sentinel is positioned for "tell me when it happens" rather than "block it
for me". The two roles compose well — run sentinel for the alerting,
fail2ban for the banning. They read the same source and don't fight.

## FAQ

**Will it block attackers?**
No — sentinel is an alerter, not an enforcer. It tells you when an attack
is happening; fail2ban / sshguard / CrowdSec do the blocking. Run sentinel
alongside one of them.

**Does it work with key-only SSH?**
Yes — sentinel reads every failed authentication attempt, including
attempts against accounts that don't accept passwords at all. Brute-force
against key-only accounts still leaves auth-log entries.

**Multi-host?**
sentinel runs per-host. For multi-host correlation, point every channel
at the same Slack / webhook endpoint — your downstream sees them aggregated.
Or use [HostAtlas Under Attack Mode](https://hostatlas.app/security-backup/attack-mode)
for platform-side correlation across the fleet.

**Performance hit?**
Streams from journald via subscription (not polling). Idle hosts cost
essentially nothing — a couple of MB resident, no CPU until a failed
attempt comes in.

**False positives?**
The default thresholds (5 failures in 5 minutes per IP) are conservative.
A user mistyping a password twice won't trigger. A real bot trying
dictionary attacks will trigger within a minute. Tune the thresholds in
config if your environment generates legitimate failure bursts (CI
runners testing SSH connectivity, for example).

**Cooldown — why?**
Without a cooldown, a sustained attack from one IP would emit hundreds
of alerts in a few minutes. The default 10-minute cooldown per IP
collapses that into one alert per attacker per 10 minutes. Override it
per-channel in config.

**Does it ship logs anywhere?**
By default — only the alert payloads to your configured channels. It
writes a small JSON event log locally for the daily summary. Nothing else
leaves the host.

**Containers?**
sentinel reads the host's auth.log / journald. SSH attacks against
containerised SSH servers show up if the container's SSHD logs to the
host journal (rare). For container-isolated SSH, run sentinel inside the
container.

**License?**
MIT — fork, modify, redistribute. See [LICENSE](LICENSE).

## Troubleshooting

### No alerts firing during what should be an attack

Run `sentinel test` to verify every configured channel delivers. If the
test alert arrives, sentinel and the channels work — the live alerts
aren't firing because either:

1. The threshold hasn't been met yet (default: 5 attempts in 5 minutes
   from the same IP).
2. The log source isn't being read. Check `sentinel config` for the
   detected log_source; force `log_source: file` and explicit `auth_log`
   if auto-detection failed.

### `permission denied` reading `/var/log/auth.log`

sentinel needs read access to the auth log. Either run it as root (via
systemd `User=root`) or add it to the `adm` group:

```bash
sudo usermod -aG adm sentinel
```

### journald shows no SSH events

Some distros log SSHD to syslog/file rather than journald. Either change
the SSHD log target (`SyslogFacility` / `LogLevel` in `sshd_config`) or
set `log_source: file` in sentinel's config.

### Alert payload missing the attacker IP

The log line didn't include the IP for parsing reasons — usually because
SSHD's log format is non-default. Set `LogLevel VERBOSE` in `sshd_config`
and restart SSHD. sentinel parses the verbose format reliably.

### Discord embed doesn't render

Discord requires a webhook URL of the form
`https://discord.com/api/webhooks/<id>/<token>`. The webhook integration
must be enabled for the channel. Check the channel settings → Integrations
→ Webhooks.

## Support

Sentinel is primarily maintained by the source control team at HostAtlas Technologies LLC.
Please submit a [GitHub Issue](https://github.com/hostatlas-labs/sentinel/issues) to report any trouble.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [HostAtlas](https://hostatlas.app) — HostAtlas Technologies LLC, an [Akyros Labs](https://akyroslabs.com) brand.  
[www.hostatlas.app](https://hostatlas.app) · [hello@hostatlas.app](mailto:hello@hostatlas.app)
