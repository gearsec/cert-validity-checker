package certcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertResult holds the result of checking a single host's TLS certificate.
type CertResult struct {
	Host      string
	IP        string
	ExpiresAt time.Time
	DaysLeft  int
	Issuer    string
	IsACM     bool
	Error     string
}

// Checker inspects TLS certificates for hosts.
type Checker interface {
	CheckCertificate(ctx context.Context, host string, port int) (*CertResult, error)
}

// TLSChecker implements Checker using real TLS connections.
type TLSChecker struct {
	timeout time.Duration
}

// NewTLSChecker creates a checker with the given dial timeout.
func NewTLSChecker(timeoutSeconds int) *TLSChecker {
	return &TLSChecker{
		timeout: time.Duration(timeoutSeconds) * time.Second,
	}
}

// CheckCertificate connects to host:port via TLS and inspects the leaf certificate.
// InsecureSkipVerify is intentionally true — we check expiry, not trust chains.
func (c *TLSChecker) CheckCertificate(ctx context.Context, host string, port int) (*CertResult, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	result := &CertResult{Host: host}

	// Resolve IP for the result.
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		result.Error = fmt.Sprintf("DNS resolution failed: %v", err)
		return result, nil
	}
	if len(ips) > 0 {
		result.IP = ips[0]
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: c.timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 — intentional: we inspect expiry, not trust
			ServerName:         host,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = fmt.Sprintf("TLS dial failed: %v", err)
		return result, nil
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.Error = "connection is not TLS"
		return result, nil
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.Error = "no certificates presented"
		return result, nil
	}

	leaf := certs[0]
	result.ExpiresAt = leaf.NotAfter
	result.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	result.Issuer = formatIssuer(leaf.Issuer.Organization, leaf.Issuer.CommonName)
	result.IsACM = isACMIssued(leaf.Issuer.Organization, leaf.Issuer.CommonName)

	return result, nil
}

// isACMIssued returns true if the certificate was issued by AWS Certificate Manager.
// ACM certificates have issuer organization "Amazon" and CN like "Amazon RSA 2048 M0x".
func isACMIssued(orgs []string, cn string) bool {
	for _, org := range orgs {
		if strings.EqualFold(org, "Amazon") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(cn), "amazon")
}

func formatIssuer(orgs []string, cn string) string {
	if len(orgs) > 0 && orgs[0] != "" {
		if cn != "" {
			return fmt.Sprintf("%s (%s)", orgs[0], cn)
		}
		return orgs[0]
	}
	if cn != "" {
		return cn
	}
	return "unknown"
}
