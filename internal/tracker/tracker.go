// SPDX-License-Identifier: MIT
// © 2026 HostAtlas Technologies LLC
// hello@hostatlas.app

package tracker

import (
	"sync"
	"time"
)

// Attempt records a single authentication failure event.
type Attempt struct {
	Username  string
	Timestamp time.Time
}

// IPRecord holds all tracked attempts for a single source IP.
type IPRecord struct {
	Attempts  []Attempt
	LastAlert time.Time
}

// Alert contains the information needed to send a notification.
type Alert struct {
	IP          string
	Attempts    int
	Users       map[string]int
	FirstSeen   time.Time
	LastSeen    time.Time
	TimeWindowS int
}

// Tracker monitors authentication failures per IP and determines when
// thresholds have been exceeded.
type Tracker struct {
	mu             sync.Mutex
	records        map[string]*IPRecord
	failedAttempts int
	timeWindow     time.Duration
	cooldown       time.Duration
}

// New creates a Tracker with the given threshold and cooldown parameters.
func New(failedAttempts int, timeWindowSec int, cooldownSec int) *Tracker {
	return &Tracker{
		records:        make(map[string]*IPRecord),
		failedAttempts: failedAttempts,
		timeWindow:     time.Duration(timeWindowSec) * time.Second,
		cooldown:       time.Duration(cooldownSec) * time.Second,
	}
}

// Record adds a failed authentication attempt and returns an Alert if the
// threshold has been reached. Returns nil when no alert should be fired.
func (t *Tracker) Record(ip string, username string, ts time.Time) *Alert {
	t.mu.Lock()
	defer t.mu.Unlock()

	rec, ok := t.records[ip]
	if !ok {
		rec = &IPRecord{}
		t.records[ip] = rec
	}

	rec.Attempts = append(rec.Attempts, Attempt{
		Username:  username,
		Timestamp: ts,
	})

	// Prune attempts outside the time window.
	cutoff := ts.Add(-t.timeWindow)
	pruned := rec.Attempts[:0]
	for _, a := range rec.Attempts {
		if a.Timestamp.After(cutoff) || a.Timestamp.Equal(cutoff) {
			pruned = append(pruned, a)
		}
	}
	rec.Attempts = pruned

	// Check if we have reached the threshold.
	if len(rec.Attempts) < t.failedAttempts {
		return nil
	}

	// Check cooldown: do not re-alert for the same IP too quickly.
	if !rec.LastAlert.IsZero() && ts.Sub(rec.LastAlert) < t.cooldown {
		return nil
	}

	// Build the alert.
	users := make(map[string]int)
	var firstSeen, lastSeen time.Time
	for i, a := range rec.Attempts {
		users[a.Username]++
		if i == 0 || a.Timestamp.Before(firstSeen) {
			firstSeen = a.Timestamp
		}
		if i == 0 || a.Timestamp.After(lastSeen) {
			lastSeen = a.Timestamp
		}
	}

	rec.LastAlert = ts

	return &Alert{
		IP:          ip,
		Attempts:    len(rec.Attempts),
		Users:       users,
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
		TimeWindowS: int(t.timeWindow.Seconds()),
	}
}

// Cleanup removes stale records that have no recent activity. This should be
// called periodically to prevent unbounded memory growth.
func (t *Tracker) Cleanup(maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for ip, rec := range t.records {
		if len(rec.Attempts) == 0 {
			delete(t.records, ip)
			continue
		}
		last := rec.Attempts[len(rec.Attempts)-1].Timestamp
		if now.Sub(last) > maxAge {
			delete(t.records, ip)
		}
	}
}

// Stats returns the number of currently tracked IPs and total attempts.
func (t *Tracker) Stats() (ips int, attempts int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ips = len(t.records)
	for _, rec := range t.records {
		attempts += len(rec.Attempts)
	}
	return ips, attempts
}
