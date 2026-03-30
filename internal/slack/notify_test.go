package slack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookNotifier_SendSingleAlert(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		received, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, "#test-channel")
	alerts := []Alert{
		{
			Domain:       "example.com",
			ExpiresAt:    time.Now().Add(10 * 24 * time.Hour),
			DaysLeft:     10,
			IP:           "1.2.3.4",
			InstanceID:   "i-abc123",
			InstanceName: "web-server",
		},
	}

	err := notifier.Send(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}

	if payload["channel"] != "#test-channel" {
		t.Errorf("expected channel '#test-channel', got %v", payload["channel"])
	}

	blocks, ok := payload["blocks"].([]interface{})
	if !ok {
		t.Fatal("blocks not found in payload")
	}
	if len(blocks) < 4 {
		t.Errorf("expected at least 4 blocks (header, section, divider, alert), got %d", len(blocks))
	}
}

func TestWebhookNotifier_Batching(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, "")

	// Create 20 alerts — should result in 2 batches (15 + 5).
	alerts := make([]Alert, 20)
	for i := range alerts {
		alerts[i] = Alert{
			Domain:   "example.com",
			DaysLeft: 5,
			IP:       "1.2.3.4",
		}
	}

	err := notifier.Send(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount.Load() != 2 {
		t.Errorf("expected 2 webhook calls for 20 alerts, got %d", callCount.Load())
	}
}

func TestWebhookNotifier_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, "")
	alerts := []Alert{{Domain: "example.com", DaysLeft: 5, IP: "1.2.3.4"}}

	err := notifier.Send(context.Background(), alerts)
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestWebhookNotifier_NoChannel(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, "")
	alerts := []Alert{{Domain: "example.com", DaysLeft: 5, IP: "1.2.3.4"}}

	err := notifier.Send(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]interface{}
	json.Unmarshal(received, &payload)
	if _, exists := payload["channel"]; exists {
		t.Error("channel should not be set when empty")
	}
}

func TestWebhookNotifier_InstanceInfoFormatting(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(server.URL, "")

	// Alert without instance info should show N/A.
	alerts := []Alert{{Domain: "example.com", DaysLeft: 5, IP: "1.2.3.4"}}
	err := notifier.Send(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := string(received)
	if body == "" {
		t.Fatal("empty response body")
	}
	// Verify the payload contains "N/A" for missing instance info.
	if !contains(body, "N/A") {
		t.Error("expected 'N/A' in payload for missing instance info")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
