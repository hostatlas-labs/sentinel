// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package alerter

import (
	"testing"
	"time"
)

func TestFormatUserList(t *testing.T) {
	users := map[string]int{
		"root":   8,
		"admin":  3,
		"ubuntu": 1,
	}

	result := FormatUserList(users)

	// root should be first (highest count).
	if result != "root (8), admin (3), ubuntu (1)" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestFormatUserList_Single(t *testing.T) {
	users := map[string]int{"root": 5}
	result := FormatUserList(users)
	if result != "root (5)" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestFormatDuration_Seconds(t *testing.T) {
	first := time.Now()
	last := first.Add(30 * time.Second)
	result := FormatDuration(first, last)
	if result != "30 seconds" {
		t.Errorf("expected '30 seconds', got '%s'", result)
	}
}

func TestFormatDuration_Minutes(t *testing.T) {
	first := time.Now()
	last := first.Add(5 * time.Minute)
	result := FormatDuration(first, last)
	if result != "5 minutes" {
		t.Errorf("expected '5 minutes', got '%s'", result)
	}
}

func TestFormatDuration_Hours(t *testing.T) {
	first := time.Now()
	last := first.Add(2 * time.Hour)
	result := FormatDuration(first, last)
	if result != "2 hours" {
		t.Errorf("expected '2 hours', got '%s'", result)
	}
}
