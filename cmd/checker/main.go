package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	r53svc "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/gearsec/cert-validity-checker/internal/certcheck"
	"github.com/gearsec/cert-validity-checker/internal/checker"
	"github.com/gearsec/cert-validity-checker/internal/config"
	"github.com/gearsec/cert-validity-checker/internal/ec2"
	"github.com/gearsec/cert-validity-checker/internal/route53"
	"github.com/gearsec/cert-validity-checker/internal/slack"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		lambda.Start(handler)
	} else {
		if err := run(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
}

func handler(ctx context.Context) error {
	return run(ctx)
}

func run(ctx context.Context) error {
	// Load configuration.
	mgr := config.NewManager()
	// Set slice defaults before RegisterStruct (struct tags don't support slices).
	mgr.Register("check", config.Item{
		Key:          "skip_name_prefixes",
		DefaultValue: []string{"_"},
	})
	var cfg config.Config
	mgr.RegisterStruct(&cfg)
	if err := mgr.Load(&cfg); err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Validate required config.
	if cfg.Slack.WebhookURL == "" {
		return fmt.Errorf("CERTCHECKER_SLACK_WEBHOOK_URL is required")
	}

	// Setup structured logging.
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	logger.Info("starting cert-validity-checker",
		"version", version,
		"commit", commit,
		"date", date,
	)

	// Create shared AWS config.
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWS.Region))
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	// Wire dependencies.
	r53Client := r53svc.NewFromConfig(awsCfg)
	ec2Client := ec2svc.NewFromConfig(awsCfg)

	recordFetcher := route53.NewFetcher(r53Client)
	certChecker := certcheck.NewTLSChecker(cfg.Check.TLSTimeoutSeconds)
	instanceLookup := ec2.NewLookup(ec2Client)
	notifier := slack.NewWebhookNotifier(cfg.Slack.WebhookURL, cfg.Slack.Channel)

	c := checker.New(recordFetcher, certChecker, instanceLookup, notifier, &cfg, logger)
	return c.Run(ctx)
}
