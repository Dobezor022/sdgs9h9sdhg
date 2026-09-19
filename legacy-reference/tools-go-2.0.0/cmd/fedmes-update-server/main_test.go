package main

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestTicketBoundToDeviceAndSingleUse(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	manager := &ticketManager{key: key, used: make(map[string]time.Time), now: func() time.Time { return now }}
	item := release{VersionCode: 10004, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	ticket, err := manager.issue("android-normal", item, "grisha", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.consume(ticket, "grisha", "device-2"); err == nil {
		t.Fatal("ticket accepted for another device")
	}
	if _, err := manager.consume(ticket, "grisha", "device-1"); err != nil {
		t.Fatalf("ticket rejected: %v", err)
	}
	if _, err := manager.consume(ticket, "grisha", "device-1"); !errors.Is(err, errTicketUsed) {
		t.Fatalf("expected used ticket error, got %v", err)
	}
}

func TestTicketExpiresAfterThreeMinutes(t *testing.T) {
	key := make([]byte, 32)
	managerNow := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	manager := &ticketManager{key: key, used: make(map[string]time.Time), now: func() time.Time { return managerNow }}
	item := release{VersionCode: 10004, SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	ticket, err := manager.issue("windows-x64", item, "grisha", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	managerNow = managerNow.Add(ticketTTL + time.Second)
	if _, err := manager.consume(ticket, "grisha", "device-1"); !errors.Is(err, errTicketExpired) {
		t.Fatalf("expected expired ticket error, got %v", err)
	}
}
