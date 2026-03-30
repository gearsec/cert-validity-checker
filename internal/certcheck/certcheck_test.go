package certcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// newTestTLSServer creates a TLS listener with a certificate that has the given
// issuer organization and expiry time.
func newTestTLSServer(t *testing.T, issuerOrg string, notAfter time.Time) (net.Listener, int) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// For self-signed certs, the Subject becomes the Issuer.
	// So we set Subject to the desired issuer org for ACM detection testing.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{issuerOrg},
			CommonName:   issuerOrg + " CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Accept connections in the background and complete the TLS handshake
	// before closing, so the client can read the certificate.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Complete TLS handshake so the client can read the peer certificate.
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return listener, port
}

func TestCheckCertificate_ValidCert(t *testing.T) {
	listener, port := newTestTLSServer(t, "Let's Encrypt", time.Now().Add(90*24*time.Hour))
	defer listener.Close()

	checker := NewTLSChecker(5)
	result, err := checker.CheckCertificate(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected cert error: %s", result.Error)
	}
	if result.DaysLeft < 89 {
		t.Errorf("expected ~90 days left, got %d", result.DaysLeft)
	}
	if result.IsACM {
		t.Error("expected non-ACM cert")
	}
}

func TestCheckCertificate_ExpiringCert(t *testing.T) {
	listener, port := newTestTLSServer(t, "Internal CA", time.Now().Add(10*24*time.Hour))
	defer listener.Close()

	checker := NewTLSChecker(5)
	result, err := checker.CheckCertificate(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected cert error: %s", result.Error)
	}
	if result.DaysLeft > 10 {
		t.Errorf("expected <=10 days left, got %d", result.DaysLeft)
	}
}

func TestCheckCertificate_ACMDetection(t *testing.T) {
	listener, port := newTestTLSServer(t, "Amazon", time.Now().Add(365*24*time.Hour))
	defer listener.Close()

	checker := NewTLSChecker(5)
	result, err := checker.CheckCertificate(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected cert error: %s", result.Error)
	}
	if !result.IsACM {
		t.Error("expected ACM cert to be detected")
	}
}

func TestCheckCertificate_ConnectionRefused(t *testing.T) {
	checker := NewTLSChecker(2)
	// Use a port that's almost certainly not listening.
	result, err := checker.CheckCertificate(context.Background(), "127.0.0.1", 19999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected an error for connection refused")
	}
}

func TestIsACMIssued(t *testing.T) {
	tests := []struct {
		name     string
		orgs     []string
		cn       string
		expected bool
	}{
		{"Amazon org", []string{"Amazon"}, "Amazon RSA 2048 M03", true},
		{"amazon lowercase cn", []string{""}, "amazon rsa 2048", true},
		{"Let's Encrypt", []string{"Let's Encrypt"}, "R3", false},
		{"empty", []string{}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isACMIssued(tt.orgs, tt.cn)
			if got != tt.expected {
				t.Errorf("isACMIssued(%v, %q) = %v, want %v", tt.orgs, tt.cn, got, tt.expected)
			}
		})
	}
}

func TestFormatIssuer(t *testing.T) {
	tests := []struct {
		orgs     []string
		cn       string
		expected string
	}{
		{[]string{"Amazon"}, "Amazon RSA", "Amazon (Amazon RSA)"},
		{[]string{"Let's Encrypt"}, "", "Let's Encrypt"},
		{[]string{}, "R3", "R3"},
		{[]string{}, "", "unknown"},
	}

	for _, tt := range tests {
		got := formatIssuer(tt.orgs, tt.cn)
		if got != tt.expected {
			t.Errorf("formatIssuer(%v, %q) = %q, want %q", tt.orgs, tt.cn, got, tt.expected)
		}
	}
}
