package checker

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/gearsec/cert-validity-checker/internal/certcheck"
	"github.com/gearsec/cert-validity-checker/internal/config"
	"github.com/gearsec/cert-validity-checker/internal/ec2"
	"github.com/gearsec/cert-validity-checker/internal/route53"
	"github.com/gearsec/cert-validity-checker/internal/slack"
)

// --- Mocks ---

type mockRecordFetcher struct {
	records []route53.DNSRecord
	err     error
}

func (m *mockRecordFetcher) FetchRecords(_ context.Context, _ string) ([]route53.DNSRecord, error) {
	return m.records, m.err
}

type mockCertChecker struct {
	results map[string]*certcheck.CertResult
}

func (m *mockCertChecker) CheckCertificate(_ context.Context, host string, _ int) (*certcheck.CertResult, error) {
	if r, ok := m.results[host]; ok {
		return r, nil
	}
	return &certcheck.CertResult{Host: host, Error: "connection refused"}, nil
}

type mockInstanceLookup struct {
	instances map[string]*ec2.InstanceInfo
}

func (m *mockInstanceLookup) LookupByIP(_ context.Context, ip string) (*ec2.InstanceInfo, error) {
	return m.instances[ip], nil
}

type mockNotifier struct {
	alerts []slack.Alert
	err    error
}

func (m *mockNotifier) Send(_ context.Context, alerts []slack.Alert) error {
	m.alerts = alerts
	return m.err
}

// --- Tests ---

func TestChecker_Run_ExpiringNonACM(t *testing.T) {
	notifier := &mockNotifier{}
	c := New(
		&mockRecordFetcher{
			records: []route53.DNSRecord{
				{Name: "expiring.example.com", Type: "A", Values: []string{"1.2.3.4"}},
				{Name: "acm.example.com", Type: "A", Values: []string{"5.6.7.8"}},
				{Name: "valid.example.com", Type: "A", Values: []string{"9.10.11.12"}},
			},
		},
		&mockCertChecker{
			results: map[string]*certcheck.CertResult{
				"expiring.example.com": {
					Host:      "expiring.example.com",
					IP:        "1.2.3.4",
					ExpiresAt: time.Now().Add(10 * 24 * time.Hour),
					DaysLeft:  10,
					Issuer:    "Let's Encrypt",
					IsACM:     false,
				},
				"acm.example.com": {
					Host:      "acm.example.com",
					IP:        "5.6.7.8",
					ExpiresAt: time.Now().Add(5 * 24 * time.Hour),
					DaysLeft:  5,
					Issuer:    "Amazon",
					IsACM:     true,
				},
				"valid.example.com": {
					Host:      "valid.example.com",
					IP:        "9.10.11.12",
					ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
					DaysLeft:  90,
					Issuer:    "Let's Encrypt",
					IsACM:     false,
				},
			},
		},
		&mockInstanceLookup{
			instances: map[string]*ec2.InstanceInfo{
				"1.2.3.4": {InstanceID: "i-abc123", Name: "web-server"},
			},
		},
		notifier,
		&config.Config{
			Check: config.CheckConfig{
				ExpiryThresholdDays: 15,
				Concurrency:         2,
			},
		},
		slog.Default(),
	)

	err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(notifier.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
	}

	alert := notifier.alerts[0]
	if alert.Domain != "expiring.example.com" {
		t.Errorf("expected domain 'expiring.example.com', got '%s'", alert.Domain)
	}
	if alert.InstanceID != "i-abc123" {
		t.Errorf("expected instance 'i-abc123', got '%s'", alert.InstanceID)
	}
	if alert.InstanceName != "web-server" {
		t.Errorf("expected instance name 'web-server', got '%s'", alert.InstanceName)
	}
}

func TestChecker_Run_NoExpiring(t *testing.T) {
	notifier := &mockNotifier{}
	c := New(
		&mockRecordFetcher{
			records: []route53.DNSRecord{
				{Name: "valid.example.com", Type: "A", Values: []string{"1.2.3.4"}},
			},
		},
		&mockCertChecker{
			results: map[string]*certcheck.CertResult{
				"valid.example.com": {
					Host:      "valid.example.com",
					IP:        "1.2.3.4",
					ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
					DaysLeft:  90,
					IsACM:     false,
				},
			},
		},
		&mockInstanceLookup{instances: map[string]*ec2.InstanceInfo{}},
		notifier,
		&config.Config{Check: config.CheckConfig{ExpiryThresholdDays: 15, Concurrency: 2}},
		slog.Default(),
	)

	err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if notifier.alerts != nil {
		t.Errorf("expected no alerts, got %d", len(notifier.alerts))
	}
}

func TestChecker_Run_CertCheckError_Skipped(t *testing.T) {
	notifier := &mockNotifier{}
	c := New(
		&mockRecordFetcher{
			records: []route53.DNSRecord{
				{Name: "broken.example.com", Type: "A", Values: []string{"1.2.3.4"}},
			},
		},
		&mockCertChecker{
			results: map[string]*certcheck.CertResult{
				"broken.example.com": {
					Host:  "broken.example.com",
					Error: "TLS dial failed: connection refused",
				},
			},
		},
		&mockInstanceLookup{instances: map[string]*ec2.InstanceInfo{}},
		notifier,
		&config.Config{Check: config.CheckConfig{ExpiryThresholdDays: 15, Concurrency: 2}},
		slog.Default(),
	)

	err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if notifier.alerts != nil {
		t.Errorf("expected no alerts for broken cert, got %d", len(notifier.alerts))
	}
}

func TestChecker_Run_NoRecords(t *testing.T) {
	notifier := &mockNotifier{}
	c := New(
		&mockRecordFetcher{records: nil},
		&mockCertChecker{results: map[string]*certcheck.CertResult{}},
		&mockInstanceLookup{instances: map[string]*ec2.InstanceInfo{}},
		notifier,
		&config.Config{Check: config.CheckConfig{ExpiryThresholdDays: 15, Concurrency: 2}},
		slog.Default(),
	)

	err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if notifier.alerts != nil {
		t.Errorf("expected no alerts, got %d", len(notifier.alerts))
	}
}

func TestChecker_Run_EC2LookupReturnsNil(t *testing.T) {
	notifier := &mockNotifier{}
	c := New(
		&mockRecordFetcher{
			records: []route53.DNSRecord{
				{Name: "expiring.example.com", Type: "A", Values: []string{"1.2.3.4"}},
			},
		},
		&mockCertChecker{
			results: map[string]*certcheck.CertResult{
				"expiring.example.com": {
					Host:      "expiring.example.com",
					IP:        "1.2.3.4",
					ExpiresAt: time.Now().Add(5 * 24 * time.Hour),
					DaysLeft:  5,
					IsACM:     false,
				},
			},
		},
		&mockInstanceLookup{instances: map[string]*ec2.InstanceInfo{}},
		notifier,
		&config.Config{Check: config.CheckConfig{ExpiryThresholdDays: 15, Concurrency: 2}},
		slog.Default(),
	)

	err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(notifier.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
	}
	if notifier.alerts[0].InstanceID != "" {
		t.Errorf("expected empty instance ID for unknown IP, got '%s'", notifier.alerts[0].InstanceID)
	}
}

func TestChecker_Run_CNAMEUsesTarget(t *testing.T) {
	notifier := &mockNotifier{}
	c := New(
		&mockRecordFetcher{
			records: []route53.DNSRecord{
				{Name: "alias.example.com", Type: "CNAME", Values: []string{"target.example.com"}},
			},
		},
		&mockCertChecker{
			results: map[string]*certcheck.CertResult{
				"target.example.com": {
					Host:      "target.example.com",
					IP:        "1.2.3.4",
					ExpiresAt: time.Now().Add(5 * 24 * time.Hour),
					DaysLeft:  5,
					IsACM:     false,
				},
			},
		},
		&mockInstanceLookup{
			instances: map[string]*ec2.InstanceInfo{
				"1.2.3.4": {InstanceID: "i-cname", Name: "cname-target"},
			},
		},
		notifier,
		&config.Config{Check: config.CheckConfig{ExpiryThresholdDays: 15, Concurrency: 2}},
		slog.Default(),
	)

	err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(notifier.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(notifier.alerts))
	}
	// The alert domain should be the CNAME record name, not the target.
	if notifier.alerts[0].Domain != "alias.example.com" {
		t.Errorf("expected domain 'alias.example.com', got '%s'", notifier.alerts[0].Domain)
	}
}
