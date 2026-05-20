// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package tracker

import (
	"sync"
	"testing"
	"time"
)

func TestTracker_BelowThreshold(t *testing.T) {
	trk := New(5, 300, 600)
	now := time.Now()

	// Record 4 failures — should not trigger.
	for i := 0; i < 4; i++ {
		alert := trk.Record("1.2.3.4", "root", now.Add(time.Duration(i)*time.Second))
		if alert != nil {
			t.Fatalf("unexpected alert after %d attempts", i+1)
		}
	}
}

func TestTracker_ThresholdReached(t *testing.T) {
	trk := New(5, 300, 600)
	now := time.Now()

	var alert *Alert
	for i := 0; i < 5; i++ {
		alert = trk.Record("1.2.3.4", "root", now.Add(time.Duration(i)*time.Second))
	}

	if alert == nil {
		t.Fatal("expected alert after 5 attempts")
	}
	if alert.IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", alert.IP)
	}
	if alert.Attempts != 5 {
		t.Errorf("expected 5 attempts, got %d", alert.Attempts)
	}
	if alert.Users["root"] != 5 {
		t.Errorf("expected root count 5, got %d", alert.Users["root"])
	}
}

func TestTracker_MultipleUsers(t *testing.T) {
	trk := New(5, 300, 600)
	now := time.Now()

	trk.Record("1.2.3.4", "root", now)
	trk.Record("1.2.3.4", "admin", now.Add(1*time.Second))
	trk.Record("1.2.3.4", "root", now.Add(2*time.Second))
	trk.Record("1.2.3.4", "ubuntu", now.Add(3*time.Second))
	alert := trk.Record("1.2.3.4", "root", now.Add(4*time.Second))

	if alert == nil {
		t.Fatal("expected alert")
	}
	if alert.Users["root"] != 3 {
		t.Errorf("expected root=3, got %d", alert.Users["root"])
	}
	if alert.Users["admin"] != 1 {
		t.Errorf("expected admin=1, got %d", alert.Users["admin"])
	}
	if alert.Users["ubuntu"] != 1 {
		t.Errorf("expected ubuntu=1, got %d", alert.Users["ubuntu"])
	}
}

func TestTracker_Cooldown(t *testing.T) {
	trk := New(3, 300, 600)
	now := time.Now()

	// First batch triggers alert.
	trk.Record("1.2.3.4", "root", now)
	trk.Record("1.2.3.4", "root", now.Add(1*time.Second))
	alert := trk.Record("1.2.3.4", "root", now.Add(2*time.Second))
	if alert == nil {
		t.Fatal("expected alert on first batch")
	}

	// Second batch within cooldown — no alert.
	trk.Record("1.2.3.4", "root", now.Add(10*time.Second))
	trk.Record("1.2.3.4", "root", now.Add(11*time.Second))
	alert = trk.Record("1.2.3.4", "root", now.Add(12*time.Second))
	if alert != nil {
		t.Fatal("expected no alert during cooldown")
	}

	// Third batch after cooldown — alert again.
	trk.Record("1.2.3.4", "root", now.Add(610*time.Second))
	trk.Record("1.2.3.4", "root", now.Add(611*time.Second))
	alert = trk.Record("1.2.3.4", "root", now.Add(612*time.Second))
	if alert == nil {
		t.Fatal("expected alert after cooldown expired")
	}
}

func TestTracker_TimeWindowPruning(t *testing.T) {
	trk := New(3, 10, 600) // 10-second window
	now := time.Now()

	// Record 2 attempts, then wait past the window and add 1 more.
	trk.Record("1.2.3.4", "root", now)
	trk.Record("1.2.3.4", "root", now.Add(1*time.Second))
	// 15 seconds later — the first two should be pruned.
	alert := trk.Record("1.2.3.4", "root", now.Add(15*time.Second))
	if alert != nil {
		t.Fatal("expected no alert, old attempts should be pruned")
	}
}

func TestTracker_SeparateIPs(t *testing.T) {
	trk := New(3, 300, 600)
	now := time.Now()

	// Two IPs, each with 2 attempts.
	trk.Record("1.1.1.1", "root", now)
	trk.Record("1.1.1.1", "root", now.Add(1*time.Second))
	trk.Record("2.2.2.2", "admin", now)
	trk.Record("2.2.2.2", "admin", now.Add(1*time.Second))

	// Third attempt for IP 1 triggers.
	alert := trk.Record("1.1.1.1", "root", now.Add(2*time.Second))
	if alert == nil {
		t.Fatal("expected alert for 1.1.1.1")
	}
	if alert.IP != "1.1.1.1" {
		t.Errorf("expected IP 1.1.1.1, got %s", alert.IP)
	}

	// IP 2 still below threshold.
	alert = trk.Record("2.2.2.2", "admin", now.Add(2*time.Second))
	if alert == nil {
		t.Fatal("expected alert for 2.2.2.2")
	}
}

func TestTracker_Cleanup(t *testing.T) {
	trk := New(5, 300, 600)
	now := time.Now()

	trk.Record("1.2.3.4", "root", now.Add(-2*time.Hour))
	trk.Record("5.6.7.8", "root", now)

	trk.Cleanup(1 * time.Hour)

	ips, _ := trk.Stats()
	if ips != 1 {
		t.Errorf("expected 1 tracked IP after cleanup, got %d", ips)
	}
}

func TestTracker_Stats(t *testing.T) {
	trk := New(5, 300, 600)
	now := time.Now()

	trk.Record("1.2.3.4", "root", now)
	trk.Record("1.2.3.4", "admin", now.Add(1*time.Second))
	trk.Record("5.6.7.8", "root", now)

	ips, attempts := trk.Stats()
	if ips != 2 {
		t.Errorf("expected 2 IPs, got %d", ips)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestTracker_Concurrent(t *testing.T) {
	trk := New(100, 300, 600)
	now := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				trk.Record("1.2.3.4", "root", now.Add(time.Duration(i*10+j)*time.Millisecond))
			}
		}(i)
	}
	wg.Wait()

	ips, attempts := trk.Stats()
	if ips != 1 {
		t.Errorf("expected 1 IP, got %d", ips)
	}
	if attempts != 500 {
		t.Errorf("expected 500 attempts, got %d", attempts)
	}
}
