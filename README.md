# cert-validity-checker

An open-source Go tool that monitors SSL/TLS certificate validity for domains managed in AWS Route53. When a non-ACM certificate is about to expire, it sends a Slack alert with the domain, expiry date, associated EC2 instance, and IP address.

Designed to run as an AWS Lambda on a daily schedule.

## How It Works

```
Route53 ─── List Zones ──┐
                          ├─ Filter A/AAAA/CNAME ─── TLS Handshake ─── Check Expiry
                          │                                                  │
                          │                                    ┌─────────────┤
                          │                                    │ Non-ACM &   │
                          │                                    │ Expiring    │
                          │                                    ▼             │
                          │                              EC2 Lookup ──── Slack Alert
                          └──────────────────────────────────────────────────┘
```

1. Fetches all public hosted zones from Route53
2. Lists A, AAAA, and CNAME records (skips alias records — they use ACM)
3. Performs TLS handshake on each domain (port 443) to read the certificate
4. Filters to non-Amazon/ACM-issued certs expiring within the threshold (default: 15 days)
5. Looks up the EC2 instance associated with each IP
6. Sends a formatted Slack Block Kit message with all expiring certificates

## Configuration

All configuration follows the [12-factor](https://12factor.net/) methodology and can be set via environment variables, config file, or defaults.

| Environment Variable | Default | Description |
|---|---|---|
| `CERTCHECKER_AWS_REGION` | `us-east-1` | AWS region |
| `CERTCHECKER_SLACK_WEBHOOK_URL` | *(required)* | Slack incoming webhook URL |
| `CERTCHECKER_SLACK_CHANNEL` | | Slack channel override |
| `CERTCHECKER_CHECK_EXPIRY_THRESHOLD_DAYS` | `15` | Days before expiry to alert |
| `CERTCHECKER_CHECK_HOSTED_ZONE_FILTER` | | Only check zones containing this string |
| `CERTCHECKER_CHECK_TLS_TIMEOUT_SECONDS` | `10` | TLS connection timeout |
| `CERTCHECKER_CHECK_CONCURRENCY` | `10` | Max concurrent TLS checks |
| `CERTCHECKER_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |

Config files are loaded from `./config.yaml` or `/etc/certchecker/config.yaml`. See [`local.config.yaml`](local.config.yaml) for an example.

## Prerequisites

- Go 1.25.8+
- AWS credentials with permissions:
  - `route53:ListHostedZones`
  - `route53:ListResourceRecordSets`
  - `ec2:DescribeInstances`
- A Slack incoming webhook URL

## Local Development

```bash
# Run locally
make local-run

# Run tests
make test

# Run linter
make lint

# Build Lambda binary
make build

# Package for Lambda deployment
make package
```

## Deployment

### Lambda (Terraform)

The `terraform/` directory contains infrastructure-as-code for deploying to AWS:

- Lambda function (ARM64/Graviton, `provided.al2023` runtime)
- IAM role with least-privilege permissions
- EventBridge rule (daily at 9:00 AM IST)
- CloudWatch log group (30-day retention)

```bash
cd terraform
terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

Required Terraform variables:
- `slack_webhook_url` — Slack webhook (sensitive)
- `lambda_s3_bucket` — S3 bucket for deployment package
- `lambda_s3_key` — S3 key for the function zip

### CI/CD

The project includes GitHub Actions workflows:

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Push/PR to main | Test, lint, build |
| `release.yml` | `v*.*.*` tags | GoReleaser + cosign signing |
| `security.yml` | Push/PR + weekly | SafeDep, gosec, govulncheck |
| `deploy.yml` | Terraform changes | Plan + apply with approval |

## Architecture

```
cmd/checker/          Entry point (Lambda or direct)
internal/
  config/             Viper-based config (12-factor, env vars)
  route53/            Route53 record fetching with pagination
  certcheck/          TLS certificate inspection
  ec2/                EC2 instance lookup by IP
  slack/              Slack Block Kit notifications
  checker/            Orchestrator (ties all modules together)
terraform/            Lambda + IAM + EventBridge infrastructure
```

All AWS SDK interactions are behind interfaces for testability. The orchestrator uses a bounded worker pool for concurrent certificate checks.

## Security

- Release artifacts are signed with [Sigstore cosign](https://www.sigstore.dev/) (keyless)
- Dependencies are scanned weekly via SafeDep, gosec, and govulncheck
- See [SECURITY.md](SECURITY.md) for vulnerability reporting

## License

[MIT](LICENSE)
