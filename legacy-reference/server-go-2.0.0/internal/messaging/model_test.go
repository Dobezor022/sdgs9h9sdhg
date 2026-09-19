package messaging

import (
	"testing"
	"time"
)

func TestPresenceCategory(t *testing.T) {
	now := time.Date(2026, time.July, 11, 15, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		last time.Time
		want string
	}{
		{"online", now.Add(-30 * time.Second), "online"},
		{"today", now.Add(-2 * time.Hour), "today"},
		{"yesterday", now.Add(-24 * time.Hour), "yesterday"},
		{"week", now.Add(-4 * 24 * time.Hour), "week"},
		{"month", now.Add(-9 * 24 * time.Hour), "month"},
		{"long ago", now.Add(-40 * 24 * time.Hour), "long_ago"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := presenceCategory(now, test.last); got != test.want {
				t.Fatalf("presenceCategory()=%q, want %q", got, test.want)
			}
		})
	}
}

func TestValidateUUID(t *testing.T) {
	if !ValidateUUID("7c92bac9-8261-4c50-998b-4c30c36db33e") {
		t.Fatal("valid UUID rejected")
	}
	for _, invalid := range []string{"", "7c92bac9", "7c92bac9-8261-4c50-998b-4c30c36db33z"} {
		if ValidateUUID(invalid) {
			t.Fatalf("invalid UUID accepted: %q", invalid)
		}
	}
}

func TestCanonicalMessageAAD(t *testing.T) {
	got := CanonicalMessageAAD("dm:grisha:papa", "grisha", "device-1", "message-1")
	want := "fedmes-message-v1\ndm:grisha:papa\ngrisha\ndevice-1\nmessage-1"
	if got != want {
		t.Fatalf("CanonicalMessageAAD()=%q, want %q", got, want)
	}
}
