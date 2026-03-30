package config

import (
	"os"
	"testing"
)

func TestManager_EnvVarLoading(t *testing.T) {
	if err := os.Setenv("CERTCHECKER_SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"); err != nil {
		t.Fatalf("failed to set env var: %v", err)
	}
	defer func() { _ = os.Unsetenv("CERTCHECKER_SLACK_WEBHOOK_URL") }()

	m := NewManager()
	var cfg Config
	m.RegisterStruct(&cfg)

	if err := m.Load(&cfg); err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Slack.WebhookURL != "https://hooks.slack.com/test" {
		t.Errorf("expected webhook URL 'https://hooks.slack.com/test', got '%s'", cfg.Slack.WebhookURL)
	}
}

func TestManager_Defaults(t *testing.T) {
	m := NewManager()
	var cfg Config
	m.RegisterStruct(&cfg)

	if err := m.Load(&cfg); err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.AWS.Region != "us-east-1" {
		t.Errorf("expected default region 'us-east-1', got '%s'", cfg.AWS.Region)
	}
	if cfg.Check.ExpiryThresholdDays != 15 {
		t.Errorf("expected default expiry threshold 15, got %d", cfg.Check.ExpiryThresholdDays)
	}
	if cfg.Check.TLSTimeoutSeconds != 10 {
		t.Errorf("expected default TLS timeout 10, got %d", cfg.Check.TLSTimeoutSeconds)
	}
	if cfg.Check.Concurrency != 10 {
		t.Errorf("expected default concurrency 10, got %d", cfg.Check.Concurrency)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("expected default log level 'info', got '%s'", cfg.Log.Level)
	}
}

func TestManager_EnvOverridesDefault(t *testing.T) {
	if err := os.Setenv("CERTCHECKER_AWS_REGION", "eu-west-1"); err != nil {
		t.Fatalf("failed to set env var: %v", err)
	}
	defer func() { _ = os.Unsetenv("CERTCHECKER_AWS_REGION") }()

	m := NewManager()
	var cfg Config
	m.RegisterStruct(&cfg)

	if err := m.Load(&cfg); err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.AWS.Region != "eu-west-1" {
		t.Errorf("expected region 'eu-west-1', got '%s'", cfg.AWS.Region)
	}
}

func TestManager_NestedEnvVar(t *testing.T) {
	if err := os.Setenv("CERTCHECKER_CHECK_EXPIRY_THRESHOLD_DAYS", "30"); err != nil {
		t.Fatalf("failed to set env var: %v", err)
	}
	defer func() { _ = os.Unsetenv("CERTCHECKER_CHECK_EXPIRY_THRESHOLD_DAYS") }()

	m := NewManager()
	var cfg Config
	m.RegisterStruct(&cfg)

	if err := m.Load(&cfg); err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Check.ExpiryThresholdDays != 30 {
		t.Errorf("expected expiry threshold 30, got %d", cfg.Check.ExpiryThresholdDays)
	}
}

func TestManager_LoadFile_Missing(t *testing.T) {
	m := NewManager()
	var cfg Config
	m.RegisterStruct(&cfg)

	err := m.LoadFile("/nonexistent/config.yaml", &cfg)
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}

	// Defaults should still be applied
	if cfg.AWS.Region != "us-east-1" {
		t.Errorf("expected default region after missing file, got '%s'", cfg.AWS.Region)
	}
}
