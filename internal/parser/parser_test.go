// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package parser

import (
	"testing"
)

func TestParse_FailedPassword(t *testing.T) {
	line := "Apr 16 14:23:01 server sshd[12345]: Failed password for root from 45.142.120.71 port 22 ssh2"
	event := Parse(line)
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.IP != "45.142.120.71" {
		t.Errorf("expected IP 45.142.120.71, got %s", event.IP)
	}
	if event.Username != "root" {
		t.Errorf("expected username root, got %s", event.Username)
	}
}

func TestParse_FailedPasswordInvalidUser(t *testing.T) {
	line := "Apr 16 14:23:01 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 49999 ssh2"
	event := Parse(line)
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.IP != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", event.IP)
	}
	if event.Username != "admin" {
		t.Errorf("expected username admin, got %s", event.Username)
	}
}

func TestParse_InvalidUser(t *testing.T) {
	line := "Apr 16 14:23:01 server sshd[12345]: Invalid user test from 10.0.0.5 port 22"
	event := Parse(line)
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.IP != "10.0.0.5" {
		t.Errorf("expected IP 10.0.0.5, got %s", event.IP)
	}
	if event.Username != "test" {
		t.Errorf("expected username test, got %s", event.Username)
	}
}

func TestParse_ConnectionClosedPreauth(t *testing.T) {
	line := "Apr 16 14:23:01 server sshd[12345]: Connection closed by authenticating user ubuntu 203.0.113.50 port 22 [preauth]"
	event := Parse(line)
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.IP != "203.0.113.50" {
		t.Errorf("expected IP 203.0.113.50, got %s", event.IP)
	}
	if event.Username != "ubuntu" {
		t.Errorf("expected username ubuntu, got %s", event.Username)
	}
}

func TestParse_PamUnixFailure(t *testing.T) {
	line := "Apr 16 14:23:01 server sshd[12345]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=172.16.0.1 user=deploy"
	event := Parse(line)
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.IP != "172.16.0.1" {
		t.Errorf("expected IP 172.16.0.1, got %s", event.IP)
	}
	if event.Username != "deploy" {
		t.Errorf("expected username deploy, got %s", event.Username)
	}
}

func TestParse_PamUnixFailureNoUser(t *testing.T) {
	line := "Apr 16 14:23:01 server sshd[12345]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=172.16.0.1"
	event := Parse(line)
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.IP != "172.16.0.1" {
		t.Errorf("expected IP 172.16.0.1, got %s", event.IP)
	}
	if event.Username != "unknown" {
		t.Errorf("expected username unknown, got %s", event.Username)
	}
}

func TestParse_DisconnectedPreauth(t *testing.T) {
	line := "Apr 16 14:23:01 server sshd[12345]: Disconnected from authenticating user git 198.51.100.20 port 55555 [preauth]"
	event := Parse(line)
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.IP != "198.51.100.20" {
		t.Errorf("expected IP 198.51.100.20, got %s", event.IP)
	}
	if event.Username != "git" {
		t.Errorf("expected username git, got %s", event.Username)
	}
}

func TestParse_KeyboardInteractive(t *testing.T) {
	line := "Apr 16 14:23:01 server sshd[12345]: Failed keyboard-interactive/pam for invalid user oracle from 10.10.10.10 port 22 ssh2"
	event := Parse(line)
	if event == nil {
		t.Fatal("expected event, got nil")
	}
	if event.IP != "10.10.10.10" {
		t.Errorf("expected IP 10.10.10.10, got %s", event.IP)
	}
	if event.Username != "oracle" {
		t.Errorf("expected username oracle, got %s", event.Username)
	}
}

func TestParse_NoMatch(t *testing.T) {
	lines := []string{
		"Apr 16 14:23:01 server sshd[12345]: Accepted publickey for user from 10.0.0.1 port 22",
		"Apr 16 14:23:01 server cron[999]: pam_unix(cron:session): session opened",
		"random garbage that should not match",
		"",
	}
	for _, line := range lines {
		event := Parse(line)
		if event != nil {
			t.Errorf("expected nil for line %q, got event with IP=%s", line, event.IP)
		}
	}
}

func TestIsSSHRelated(t *testing.T) {
	tests := []struct {
		line     string
		expected bool
	}{
		{"Apr 16 14:23:01 server sshd[12345]: Failed password", true},
		{"Apr 16 14:23:01 server cron[999]: session opened", false},
		{"sshd is mentioned here", true},
		{"no match here", false},
	}
	for _, tt := range tests {
		got := IsSSHRelated(tt.line)
		if got != tt.expected {
			t.Errorf("IsSSHRelated(%q) = %v, want %v", tt.line, got, tt.expected)
		}
	}
}
