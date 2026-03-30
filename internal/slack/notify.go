package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Alert represents a single certificate expiry alert.
type Alert struct {
	Domain       string
	ExpiresAt    time.Time
	DaysLeft     int
	IP           string
	InstanceID   string
	InstanceName string
}

// Notifier sends certificate expiry alerts to Slack.
type Notifier interface {
	Send(ctx context.Context, alerts []Alert) error
}

// WebhookNotifier implements Notifier using Slack incoming webhooks.
type WebhookNotifier struct {
	webhookURL string
	channel    string
	httpClient *http.Client
}

// NewWebhookNotifier creates a new Slack webhook notifier.
func NewWebhookNotifier(webhookURL, channel string) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		channel:    channel,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// maxAlertsPerMessage is the maximum number of alerts per Slack message
// to stay within the 50-block limit.
const maxAlertsPerMessage = 15

// Send sends alerts to Slack, splitting into multiple messages if needed.
func (n *WebhookNotifier) Send(ctx context.Context, alerts []Alert) error {
	for i := 0; i < len(alerts); i += maxAlertsPerMessage {
		end := i + maxAlertsPerMessage
		if end > len(alerts) {
			end = len(alerts)
		}
		if err := n.sendBatch(ctx, alerts[i:end], i/maxAlertsPerMessage+1); err != nil {
			return err
		}
	}
	return nil
}

func (n *WebhookNotifier) sendBatch(ctx context.Context, alerts []Alert, batchNum int) error {
	blocks := buildBlocks(alerts, batchNum)

	payload := map[string]interface{}{
		"blocks": blocks,
	}
	if n.channel != "" {
		payload["channel"] = n.channel
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending slack notification: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func buildBlocks(alerts []Alert, batchNum int) []map[string]interface{} {
	var blocks []map[string]interface{}

	// Header
	headerText := ":warning: *SSL Certificate Expiry Warning*"
	if batchNum > 1 {
		headerText = fmt.Sprintf(":warning: *SSL Certificate Expiry Warning (Part %d)*", batchNum)
	}
	blocks = append(blocks, map[string]interface{}{
		"type": "header",
		"text": map[string]interface{}{
			"type": "plain_text",
			"text": "SSL Certificate Expiry Warning",
		},
	})

	blocks = append(blocks, map[string]interface{}{
		"type": "section",
		"text": map[string]interface{}{
			"type": "mrkdwn",
			"text": fmt.Sprintf("%s\nThe following certificates are expiring soon and require attention:", headerText),
		},
	})

	blocks = append(blocks, map[string]interface{}{"type": "divider"})

	for _, alert := range alerts {
		instanceInfo := "N/A"
		if alert.InstanceID != "" {
			instanceInfo = alert.InstanceID
			if alert.InstanceName != "" {
				instanceInfo = fmt.Sprintf("%s (%s)", alert.InstanceID, alert.InstanceName)
			}
		}

		text := fmt.Sprintf(
			"*Domain:* `%s`\n*Expires:* %s (*%d days remaining*)\n*IP:* `%s`\n*Instance:* %s",
			alert.Domain,
			alert.ExpiresAt.Format("2006-01-02 15:04 UTC"),
			alert.DaysLeft,
			alert.IP,
			instanceInfo,
		)

		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": text,
			},
		})
		blocks = append(blocks, map[string]interface{}{"type": "divider"})
	}

	// Footer
	blocks = append(blocks, map[string]interface{}{
		"type": "context",
		"elements": []map[string]interface{}{
			{
				"type": "mrkdwn",
				"text": fmt.Sprintf("cert-validity-checker | %s", time.Now().UTC().Format("2006-01-02 15:04 UTC")),
			},
		},
	})

	return blocks
}
