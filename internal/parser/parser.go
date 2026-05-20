// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package parser

import (
	"regexp"
	"strings"
	"time"
)

// Event represents a parsed authentication failure event.
type Event struct {
	IP        string
	Username  string
	Timestamp time.Time
	RawLine   string
}

// patterns defines the regular expressions used to detect SSH authentication
// failures. Each pattern must contain a named capture group "ip" and optionally
// a named capture group "user".
var patterns = []*regexp.Regexp{
	// Failed password for root from 192.168.1.1 port 22 ssh2
	regexp.MustCompile(`Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port`),

	// Invalid user admin from 192.168.1.1 port 22
	regexp.MustCompile(`Invalid user (?P<user>\S+) from (?P<ip>\S+) port`),

	// Connection closed by authenticating user root 192.168.1.1 port 22 [preauth]
	regexp.MustCompile(`Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+) port .* \[preauth\]`),

	// pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 ... rhost=192.168.1.1 user=root
	regexp.MustCompile(`pam_unix\(sshd:auth\): authentication failure.*rhost=(?P<ip>\S+)(?:.*user=(?P<user>\S+))?`),

	// Disconnected from authenticating user root 192.168.1.1 port 22 [preauth]
	regexp.MustCompile(`Disconnected from authenticating user (?P<user>\S+) (?P<ip>\S+) port .* \[preauth\]`),

	// Failed keyboard-interactive/pam for invalid user admin from 192.168.1.1 port 22 ssh2
	regexp.MustCompile(`Failed keyboard-interactive/pam for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port`),
}

// syslogTimestampFormats lists common timestamp formats found in auth logs.
var syslogTimestampFormats = []string{
	"Jan  2 15:04:05",
	"Jan 2 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05.000000+00:00",
}

// Parse attempts to extract an authentication failure event from a log line.
// Returns nil if the line does not match any known failure pattern.
func Parse(line string) *Event {
	for _, p := range patterns {
		match := p.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		event := &Event{
			Timestamp: parseTimestamp(line),
			RawLine:   line,
		}

		for i, name := range p.SubexpNames() {
			if i == 0 || name == "" {
				continue
			}
			switch name {
			case "ip":
				event.IP = match[i]
			case "user":
				event.Username = match[i]
			}
		}

		// Skip if we could not extract an IP.
		if event.IP == "" {
			continue
		}

		// Default username to "unknown" when not captured.
		if event.Username == "" {
			event.Username = "unknown"
		}

		return event
	}

	return nil
}

// parseTimestamp attempts to extract a timestamp from the beginning of a log
// line. Falls back to the current time if no format matches.
func parseTimestamp(line string) time.Time {
	// Trim leading whitespace.
	trimmed := strings.TrimSpace(line)

	for _, format := range syslogTimestampFormats {
		if len(trimmed) < len(format) {
			continue
		}
		t, err := time.Parse(format, trimmed[:len(format)])
		if err == nil {
			// Syslog timestamps without a year default to year 0. Use the
			// current year in that case.
			if t.Year() == 0 {
				now := time.Now()
				t = t.AddDate(now.Year(), 0, 0)
				// Handle year boundary: if the parsed time is in the future
				// by more than a day, assume it was last year.
				if t.After(now.Add(24 * time.Hour)) {
					t = t.AddDate(-1, 0, 0)
				}
			}
			return t
		}
	}

	return time.Now()
}

// IsSSHRelated returns true if the log line appears to come from sshd.
// This can be used as a fast pre-filter before calling Parse.
func IsSSHRelated(line string) bool {
	return strings.Contains(line, "sshd")
}
