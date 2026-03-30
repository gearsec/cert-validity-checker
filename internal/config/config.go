package config

// Config is the top-level application configuration.
type Config struct {
	AWS   AWSConfig   `mapstructure:"aws"`
	Slack SlackConfig `mapstructure:"slack"`
	Check CheckConfig `mapstructure:"check"`
	Log   LogConfig   `mapstructure:"log"`
}

// AWSConfig holds AWS-specific settings.
type AWSConfig struct {
	Region string `mapstructure:"region" default:"us-east-1"`
}

// SlackConfig holds Slack notification settings.
type SlackConfig struct {
	WebhookURL string `mapstructure:"webhook_url"`
	Channel    string `mapstructure:"channel"`
}

// CheckConfig holds certificate checking parameters.
type CheckConfig struct {
	ExpiryThresholdDays int    `mapstructure:"expiry_threshold_days" default:"15"`
	HostedZoneFilter    string `mapstructure:"hosted_zone_filter"`
	TLSTimeoutSeconds   int    `mapstructure:"tls_timeout_seconds" default:"10"`
	Concurrency         int    `mapstructure:"concurrency" default:"10"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level string `mapstructure:"level" default:"info"`
}
