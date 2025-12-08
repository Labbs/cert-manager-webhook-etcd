package solver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func TestFqdnToEtcdPath(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		fqdn     string
		expected string
	}{
		{
			name:     "simple domain with trailing dot",
			prefix:   "/skydns",
			fqdn:     "_acme-challenge.example.com.",
			expected: "/skydns/com/example/_acme-challenge",
		},
		{
			name:     "simple domain without trailing dot",
			prefix:   "/skydns",
			fqdn:     "_acme-challenge.example.com",
			expected: "/skydns/com/example/_acme-challenge",
		},
		{
			name:     "subdomain",
			prefix:   "/skydns",
			fqdn:     "_acme-challenge.sub.example.com.",
			expected: "/skydns/com/example/sub/_acme-challenge",
		},
		{
			name:     "deep subdomain",
			prefix:   "/skydns",
			fqdn:     "_acme-challenge.a.b.c.example.com.",
			expected: "/skydns/com/example/c/b/a/_acme-challenge",
		},
		{
			name:     "custom prefix",
			prefix:   "/dns",
			fqdn:     "_acme-challenge.example.com.",
			expected: "/dns/com/example/_acme-challenge",
		},
		{
			name:     "empty prefix",
			prefix:   "",
			fqdn:     "_acme-challenge.example.com.",
			expected: "/com/example/_acme-challenge",
		},
		{
			name:     "single part domain",
			prefix:   "/skydns",
			fqdn:     "localhost.",
			expected: "/skydns/localhost",
		},
		{
			name:     "wildcard challenge",
			prefix:   "/skydns",
			fqdn:     "_acme-challenge.wildcard.example.com.",
			expected: "/skydns/com/example/wildcard/_acme-challenge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fqdnToEtcdPath(tt.prefix, tt.fqdn)
			if result != tt.expected {
				t.Errorf("fqdnToEtcdPath(%q, %q) = %q, want %q", tt.prefix, tt.fqdn, result, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configJSON  *extapi.JSON
		expectError bool
		validate    func(*testing.T, *EtcdConfig)
	}{
		{
			name:        "nil config returns error",
			configJSON:  nil,
			expectError: true,
			validate:    nil,
		},
		{
			name: "valid config with endpoints",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": ["http://etcd:2379"], "prefix": "/dns"}`),
			},
			expectError: false,
			validate: func(t *testing.T, cfg *EtcdConfig) {
				if len(cfg.Endpoints) != 1 {
					t.Errorf("expected 1 endpoint, got %d", len(cfg.Endpoints))
				}
				if cfg.Endpoints[0] != "http://etcd:2379" {
					t.Errorf("expected endpoint http://etcd:2379, got %s", cfg.Endpoints[0])
				}
				if cfg.Prefix != "/dns" {
					t.Errorf("expected prefix /dns, got %s", cfg.Prefix)
				}
			},
		},
		{
			name: "valid config with multiple endpoints",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": ["http://etcd-0:2379", "http://etcd-1:2379", "http://etcd-2:2379"]}`),
			},
			expectError: false,
			validate: func(t *testing.T, cfg *EtcdConfig) {
				if len(cfg.Endpoints) != 3 {
					t.Errorf("expected 3 endpoints, got %d", len(cfg.Endpoints))
				}
			},
		},
		{
			name: "valid config with authentication",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": ["http://etcd:2379"], "username": "root", "password": "secret"}`),
			},
			expectError: false,
			validate: func(t *testing.T, cfg *EtcdConfig) {
				if cfg.Username != "root" {
					t.Errorf("expected username root, got %s", cfg.Username)
				}
				if cfg.Password != "secret" {
					t.Errorf("expected password secret, got %s", cfg.Password)
				}
			},
		},
		{
			name: "valid config with TLS secret ref",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": ["https://etcd:2379"], "tlsSecretRef": "etcd-tls", "tlsSecretNamespace": "etcd"}`),
			},
			expectError: false,
			validate: func(t *testing.T, cfg *EtcdConfig) {
				if cfg.TLSSecretRef != "etcd-tls" {
					t.Errorf("expected tlsSecretRef etcd-tls, got %s", cfg.TLSSecretRef)
				}
				if cfg.TLSSecretNamespace != "etcd" {
					t.Errorf("expected tlsSecretNamespace etcd, got %s", cfg.TLSSecretNamespace)
				}
			},
		},
		{
			name: "valid config with credentials secret ref",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": ["http://etcd:2379"], "credentialsSecretRef": "etcd-credentials", "credentialsSecretNamespace": "etcd"}`),
			},
			expectError: false,
			validate: func(t *testing.T, cfg *EtcdConfig) {
				if cfg.CredentialsSecretRef != "etcd-credentials" {
					t.Errorf("expected credentialsSecretRef etcd-credentials, got %s", cfg.CredentialsSecretRef)
				}
				if cfg.CredentialsSecretNamespace != "etcd" {
					t.Errorf("expected credentialsSecretNamespace etcd, got %s", cfg.CredentialsSecretNamespace)
				}
			},
		},
		{
			name: "valid config with credentials secret ref without namespace",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": ["http://etcd:2379"], "credentialsSecretRef": "etcd-credentials"}`),
			},
			expectError: false,
			validate: func(t *testing.T, cfg *EtcdConfig) {
				if cfg.CredentialsSecretRef != "etcd-credentials" {
					t.Errorf("expected credentialsSecretRef etcd-credentials, got %s", cfg.CredentialsSecretRef)
				}
				if cfg.CredentialsSecretNamespace != "" {
					t.Errorf("expected credentialsSecretNamespace to be empty, got %s", cfg.CredentialsSecretNamespace)
				}
			},
		},
		{
			name: "valid config with dial timeout",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": ["http://etcd:2379"], "dialTimeout": 30}`),
			},
			expectError: false,
			validate: func(t *testing.T, cfg *EtcdConfig) {
				if cfg.DialTimeout != 30 {
					t.Errorf("expected dialTimeout 30, got %d", cfg.DialTimeout)
				}
			},
		},
		{
			name: "valid config with insecure skip verify",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": ["https://etcd:2379"], "tlsInsecureSkipVerify": true}`),
			},
			expectError: false,
			validate: func(t *testing.T, cfg *EtcdConfig) {
				if !cfg.TLSInsecureSkipVerify {
					t.Error("expected tlsInsecureSkipVerify to be true")
				}
			},
		},
		{
			name: "missing endpoints returns error",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"prefix": "/dns"}`),
			},
			expectError: true,
			validate:    nil,
		},
		{
			name: "empty endpoints returns error",
			configJSON: &extapi.JSON{
				Raw: []byte(`{"endpoints": []}`),
			},
			expectError: true,
			validate:    nil,
		},
		{
			name: "invalid JSON returns error",
			configJSON: &extapi.JSON{
				Raw: []byte(`{invalid json}`),
			},
			expectError: true,
			validate:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadConfig(tt.configJSON)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestLoadTLSConfigFromInline(t *testing.T) {
	// Generate test certificates
	caCert, caKey := generateTestCA(t)
	clientCert, clientKey := generateTestClientCert(t, caCert, caKey)

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	solver := &EtcdDNSSolver{}

	tests := []struct {
		name        string
		cfg         *EtcdConfig
		expectError bool
		validate    func(*testing.T, *EtcdConfig)
	}{
		{
			name: "valid CA only",
			cfg: &EtcdConfig{
				TLSCA: string(caCertPEM),
			},
			expectError: false,
		},
		{
			name: "valid CA and client cert",
			cfg: &EtcdConfig{
				TLSCA:   string(caCertPEM),
				TLSCert: string(clientCertPEM),
				TLSKey:  string(clientKeyPEM),
			},
			expectError: false,
		},
		{
			name: "client cert without key returns error",
			cfg: &EtcdConfig{
				TLSCert: string(clientCertPEM),
			},
			expectError: true,
		},
		{
			name: "client key without cert returns error",
			cfg: &EtcdConfig{
				TLSKey: string(clientKeyPEM),
			},
			expectError: true,
		},
		{
			name: "invalid CA certificate returns error",
			cfg: &EtcdConfig{
				TLSCA: "not a valid certificate",
			},
			expectError: true,
		},
		{
			name: "invalid client certificate returns error",
			cfg: &EtcdConfig{
				TLSCert: "not a valid certificate",
				TLSKey:  string(clientKeyPEM),
			},
			expectError: true,
		},
		{
			name: "mismatched client cert and key returns error",
			cfg: &EtcdConfig{
				TLSCert: string(clientCertPEM),
				TLSKey:  "not a valid key",
			},
			expectError: true,
		},
		{
			name: "insecure skip verify is set",
			cfg: &EtcdConfig{
				TLSCA:                 string(caCertPEM),
				TLSInsecureSkipVerify: true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, err := solver.loadTLSConfigFromInline(tt.cfg)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tlsConfig == nil {
				t.Error("expected non-nil TLS config")
				return
			}

			// Verify InsecureSkipVerify is set correctly
			if tlsConfig.InsecureSkipVerify != tt.cfg.TLSInsecureSkipVerify {
				t.Errorf("InsecureSkipVerify = %v, want %v", tlsConfig.InsecureSkipVerify, tt.cfg.TLSInsecureSkipVerify)
			}

			// Verify CA is loaded when provided
			if tt.cfg.TLSCA != "" && tlsConfig.RootCAs == nil {
				t.Error("expected RootCAs to be set when CA is provided")
			}

			// Verify client cert is loaded when provided
			if tt.cfg.TLSCert != "" && tt.cfg.TLSKey != "" && len(tlsConfig.Certificates) == 0 {
				t.Error("expected Certificates to be set when client cert/key are provided")
			}
		})
	}
}

func TestDNSRecord(t *testing.T) {
	record := DNSRecord{
		Text: "test-challenge-token",
		TTL:  60,
	}

	if record.Text != "test-challenge-token" {
		t.Errorf("expected Text to be 'test-challenge-token', got %s", record.Text)
	}

	if record.TTL != 60 {
		t.Errorf("expected TTL to be 60, got %d", record.TTL)
	}
}

func TestEtcdDNSSolverName(t *testing.T) {
	solver := &EtcdDNSSolver{}
	if solver.Name() != "etcd" {
		t.Errorf("expected solver name to be 'etcd', got %s", solver.Name())
	}
}

// Helper functions to generate test certificates

func generateTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return caCert, caKey
}

func generateTestClientCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("failed to parse client certificate: %v", err)
	}

	return clientCert, clientKey
}
