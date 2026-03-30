package checker

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/gearsec/cert-validity-checker/internal/certcheck"
	"github.com/gearsec/cert-validity-checker/internal/config"
	"github.com/gearsec/cert-validity-checker/internal/ec2"
	"github.com/gearsec/cert-validity-checker/internal/route53"
	"github.com/gearsec/cert-validity-checker/internal/slack"
)

// Checker orchestrates the certificate validity checking workflow.
type Checker struct {
	records    route53.RecordFetcher
	certs      certcheck.Checker
	instances  ec2.InstanceLookup
	notifier   slack.Notifier
	config     *config.Config
	logger     *slog.Logger
}

// New creates a new Checker with all dependencies injected.
func New(
	records route53.RecordFetcher,
	certs certcheck.Checker,
	instances ec2.InstanceLookup,
	notifier slack.Notifier,
	cfg *config.Config,
	logger *slog.Logger,
) *Checker {
	return &Checker{
		records:   records,
		certs:     certs,
		instances: instances,
		notifier:  notifier,
		config:    cfg,
		logger:    logger,
	}
}

// certResult pairs a DNS record with its certificate check result.
type certResult struct {
	record route53.DNSRecord
	result *certcheck.CertResult
}

// Run executes the full check workflow:
// 1. Fetch DNS records from Route53
// 2. Check TLS certificates concurrently
// 3. Filter to non-ACM certs expiring within threshold
// 4. Look up EC2 instances for each expiring cert
// 5. Send Slack alerts
func (c *Checker) Run(ctx context.Context) error {
	c.logger.Info("starting certificate validity check")

	// Step 1: Fetch DNS records.
	records, err := c.records.FetchRecords(ctx, c.config.Check.HostedZoneFilter)
	if err != nil {
		return err
	}
	c.logger.Info("fetched DNS records", "count", len(records))

	if len(records) == 0 {
		c.logger.Info("no records to check")
		return nil
	}

	// Step 2: Filter out records whose names match configured skip prefixes.
	records = c.filterRecords(records)
	c.logger.Info("records after prefix filtering", "count", len(records))

	// Step 3: Check certificates concurrently.
	results := c.checkCerts(ctx, records)
	c.logger.Info("completed certificate checks", "checked", len(results))

	// Step 4: Filter to expiring non-ACM certs.
	var expiring []certResult
	for _, cr := range results {
		if cr.result.Error != "" {
			c.logger.Warn("cert check failed",
				"host", cr.result.Host,
				"error", cr.result.Error,
			)
			continue
		}
		if cr.result.IsACM {
			continue
		}
		if cr.result.DaysLeft > c.config.Check.ExpiryThresholdDays {
			continue
		}
		expiring = append(expiring, cr)
	}

	c.logger.Info("found expiring certificates", "count", len(expiring))
	if len(expiring) == 0 {
		c.logger.Info("no certificates expiring within threshold")
		return nil
	}

	// Step 5: Look up EC2 instances and build alerts.
	alerts := make([]slack.Alert, 0, len(expiring))
	for _, cr := range expiring {
		alert := slack.Alert{
			Domain:    cr.record.Name,
			ExpiresAt: cr.result.ExpiresAt,
			DaysLeft:  cr.result.DaysLeft,
			IP:        cr.result.IP,
		}

		if cr.result.IP != "" {
			info, err := c.instances.LookupByIP(ctx, cr.result.IP)
			if err != nil {
				c.logger.Warn("EC2 lookup failed",
					"ip", cr.result.IP,
					"error", err,
				)
			} else if info != nil {
				alert.InstanceID = info.InstanceID
				alert.InstanceName = info.Name
			}
		}

		alerts = append(alerts, alert)
	}

	// Step 6: Send Slack alerts.
	c.logger.Info("sending alerts", "count", len(alerts))
	if err := c.notifier.Send(ctx, alerts); err != nil {
		return err
	}

	c.logger.Info("certificate check complete",
		"total_records", len(records),
		"expiring", len(expiring),
		"alerts_sent", len(alerts),
	)
	return nil
}

// filterRecords removes records whose names start with any of the configured skip prefixes.
func (c *Checker) filterRecords(records []route53.DNSRecord) []route53.DNSRecord {
	if len(c.config.Check.SkipNamePrefixes) == 0 {
		return records
	}
	filtered := records[:0]
	for _, r := range records {
		skip := false
		for _, prefix := range c.config.Check.SkipNamePrefixes {
			// Match against the subdomain portion (before the first dot).
			label := r.Name
			if idx := strings.Index(r.Name, "."); idx != -1 {
				label = r.Name[:idx]
			}
			if strings.HasPrefix(label, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (c *Checker) checkCerts(ctx context.Context, records []route53.DNSRecord) []certResult {
	concurrency := c.config.Check.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var results []certResult

	var wg sync.WaitGroup
	for _, record := range records {
		// For CNAME records, check the target host for the cert.
		// For A/AAAA, check the record name itself.
		host := record.Name
		if record.Type == "CNAME" && len(record.Values) > 0 {
			host = record.Values[0]
		}

		wg.Add(1)
		go func(rec route53.DNSRecord, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := c.certs.CheckCertificate(ctx, h, 443)
			if err != nil {
				c.logger.Warn("cert check error", "host", h, "error", err)
				return
			}

			mu.Lock()
			results = append(results, certResult{record: rec, result: result})
			mu.Unlock()
		}(record, host)
	}
	wg.Wait()

	return results
}
