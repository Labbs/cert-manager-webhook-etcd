package solver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	clientv3 "go.etcd.io/etcd/client/v3"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// EtcdDNSSolver implements the DNS01 solver interface for etcd
type EtcdDNSSolver struct {
	client *kubernetes.Clientset
}

// EtcdConfig holds the configuration for connecting to etcd
type EtcdConfig struct {
	// Endpoints is a list of etcd endpoints
	Endpoints []string `json:"endpoints"`
	// Username for etcd authentication (optional, use credentialsSecretRef for production)
	Username string `json:"username,omitempty"`
	// Password for etcd authentication (optional, use credentialsSecretRef for production)
	Password string `json:"password,omitempty"`
	// CredentialsSecretRef is the name of the secret containing etcd credentials (username/password)
	CredentialsSecretRef string `json:"credentialsSecretRef,omitempty"`
	// CredentialsSecretNamespace is the namespace of the credentials secret (defaults to challenge namespace)
	CredentialsSecretNamespace string `json:"credentialsSecretNamespace,omitempty"`
	// TLSSecretRef is the name of the secret containing TLS certificates
	TLSSecretRef string `json:"tlsSecretRef,omitempty"`
	// TLSSecretNamespace is the namespace of the TLS secret (defaults to challenge namespace)
	TLSSecretNamespace string `json:"tlsSecretNamespace,omitempty"`
	// TLSCAKey is the key name for CA certificate in the secret (default: ca.crt)
	TLSCAKey string `json:"tlsCAKey,omitempty"`
	// TLSCertKey is the key name for client certificate in the secret (default: tls.crt)
	TLSCertKey string `json:"tlsCertKey,omitempty"`
	// TLSKeyKey is the key name for client private key in the secret (default: tls.key)
	TLSKeyKey string `json:"tlsKeyKey,omitempty"`
	// TLSServerName is the server name for TLS certificate verification (useful when connecting via IP)
	TLSServerName string `json:"tlsServerName,omitempty"`
	// TLSInsecureSkipVerify skips TLS certificate verification (not recommended for production)
	TLSInsecureSkipVerify bool `json:"tlsInsecureSkipVerify,omitempty"`
	// TLSCA is the CA certificate in PEM format (alternative to using a secret)
	TLSCA string `json:"tlsCA,omitempty"`
	// TLSCert is the client certificate in PEM format (alternative to using a secret)
	TLSCert string `json:"tlsCert,omitempty"`
	// TLSKey is the client private key in PEM format (alternative to using a secret)
	TLSKey string `json:"tlsKey,omitempty"`
	// Prefix for DNS records in etcd (default: /skydns)
	Prefix string `json:"prefix,omitempty"`
	// DialTimeout is the timeout for connecting to etcd
	DialTimeout int `json:"dialTimeout,omitempty"`
}

// DNSRecord represents a DNS record stored in etcd (SkyDNS format)
type DNSRecord struct {
	Host     string `json:"host,omitempty"`
	Text     string `json:"text,omitempty"`
	TTL      uint32 `json:"ttl,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// Name returns the name of this DNS solver
func (e *EtcdDNSSolver) Name() string {
	return "etcd"
}

// Present creates the TXT record in etcd for the ACME challenge
func (e *EtcdDNSSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Presenting challenge for domain %s with key %s", ch.ResolvedFQDN, ch.Key)
	klog.Infof("Challenge request config: %+v", ch.Config)
	if ch.Config != nil {
		klog.Infof("Config raw data: %s", string(ch.Config.Raw))
	} else {
		klog.Error("Config is nil!")
	}

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	etcdClient, err := e.getEtcdClient(cfg, ch)
	if err != nil {
		return fmt.Errorf("failed to create etcd client: %v", err)
	}
	defer etcdClient.Close()

	// Convert FQDN to etcd path (reverse domain format for SkyDNS)
	etcdPath := fqdnToEtcdPath(cfg.Prefix, ch.ResolvedFQDN)

	// Create the DNS TXT record
	record := DNSRecord{
		Text: ch.Key,
		TTL:  60,
	}

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal DNS record: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = etcdClient.Put(ctx, etcdPath, string(recordJSON))
	if err != nil {
		return fmt.Errorf("failed to put record in etcd: %v", err)
	}

	klog.V(2).Infof("Successfully created TXT record at %s", etcdPath)
	return nil
}

// CleanUp removes the TXT record from etcd after the challenge is complete
func (e *EtcdDNSSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.V(2).Infof("Cleaning up challenge for domain %s", ch.ResolvedFQDN)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	etcdClient, err := e.getEtcdClient(cfg, ch)
	if err != nil {
		return fmt.Errorf("failed to create etcd client: %v", err)
	}
	defer etcdClient.Close()

	etcdPath := fqdnToEtcdPath(cfg.Prefix, ch.ResolvedFQDN)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = etcdClient.Delete(ctx, etcdPath)
	if err != nil {
		return fmt.Errorf("failed to delete record from etcd: %v", err)
	}

	klog.V(2).Infof("Successfully deleted TXT record at %s", etcdPath)
	return nil
}

// Initialize initializes the DNS solver with the Kubernetes client
func (e *EtcdDNSSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.V(2).Info("Initializing etcd DNS solver")

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	e.client = cl
	return nil
}

// getEtcdClient creates a new etcd client based on the configuration
func (e *EtcdDNSSolver) getEtcdClient(cfg *EtcdConfig, ch *v1alpha1.ChallengeRequest) (*clientv3.Client, error) {
	dialTimeout := time.Duration(cfg.DialTimeout) * time.Second
	if dialTimeout == 0 {
		dialTimeout = 10 * time.Second
	}

	etcdConfig := clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: dialTimeout,
	}

	// Add authentication - priority: secret reference > inline credentials
	if cfg.CredentialsSecretRef != "" {
		username, password, err := e.loadCredentialsFromSecret(cfg, ch)
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials from secret: %v", err)
		}
		etcdConfig.Username = username
		etcdConfig.Password = password
		klog.V(2).Info("Credentials loaded from secret")
	} else if cfg.Username != "" && cfg.Password != "" {
		etcdConfig.Username = cfg.Username
		etcdConfig.Password = cfg.Password
		klog.V(2).Info("Using inline credentials (consider using credentialsSecretRef for production)")
	}

	// Configure TLS - priority: inline certs > secret reference > insecure
	if cfg.TLSCA != "" || cfg.TLSCert != "" {
		// Use inline certificates
		tlsConfig, err := e.loadTLSConfigFromInline(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to load inline TLS config: %v", err)
		}
		etcdConfig.TLS = tlsConfig
		klog.V(2).Info("TLS configuration loaded from inline certificates")
	} else if cfg.TLSSecretRef != "" {
		// Use secret reference
		tlsConfig, err := e.loadTLSConfigFromSecret(cfg, ch)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config from secret: %v", err)
		}
		etcdConfig.TLS = tlsConfig
		klog.V(2).Info("TLS configuration loaded from secret")
	} else if cfg.TLSInsecureSkipVerify {
		// Allow insecure TLS (skip verification)
		etcdConfig.TLS = &tls.Config{
			InsecureSkipVerify: true,
		}
		klog.Warning("TLS configured with InsecureSkipVerify=true (SECURITY RISK: TLS verification is disabled; not recommended for production)")
	}

	client, err := clientv3.New(etcdConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %v", err)
	}

	return client, nil
}

// loadCredentialsFromSecret loads etcd credentials from a Kubernetes secret
func (e *EtcdDNSSolver) loadCredentialsFromSecret(cfg *EtcdConfig, ch *v1alpha1.ChallengeRequest) (string, string, error) {
	// Determine the namespace for the credentials secret
	namespace := cfg.CredentialsSecretNamespace
	if namespace == "" {
		namespace = ch.ResourceNamespace
	}

	klog.V(2).Infof("Loading credentials secret %s from namespace %s", cfg.CredentialsSecretRef, namespace)

	// Fetch the secret from Kubernetes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret, err := e.client.CoreV1().Secrets(namespace).Get(ctx, cfg.CredentialsSecretRef, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("failed to get credentials secret %s/%s: %v", namespace, cfg.CredentialsSecretRef, err)
	}

	username, usernameOk := secret.Data["username"]
	password, passwordOk := secret.Data["password"]

	if !usernameOk || !passwordOk {
		return "", "", fmt.Errorf("credentials secret %s/%s must contain both 'username' and 'password' keys", namespace, cfg.CredentialsSecretRef)
	}

	klog.V(2).Info("Credentials loaded from secret")
	return string(username), string(password), nil
}

// loadTLSConfigFromInline loads TLS certificates from inline PEM strings in the config
func (e *EtcdDNSSolver) loadTLSConfigFromInline(cfg *EtcdConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
	}

	// Set ServerName for TLS verification if specified
	if cfg.TLSServerName != "" {
		tlsConfig.ServerName = cfg.TLSServerName
		klog.V(2).Infof("Using TLS ServerName: %s", cfg.TLSServerName)
	}

	// Load CA certificate if provided
	if cfg.TLSCA != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(cfg.TLSCA)) {
			return nil, fmt.Errorf("failed to parse inline CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
		klog.V(2).Info("CA certificate loaded from inline config")
	}

	// Load client certificate and key if provided (for mTLS)
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.X509KeyPair([]byte(cfg.TLSCert), []byte(cfg.TLSKey))
		if err != nil {
			return nil, fmt.Errorf("failed to load inline client certificate and key: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		klog.V(2).Info("Client certificate and key loaded from inline config")
	} else if cfg.TLSCert != "" || cfg.TLSKey != "" {
		return nil, fmt.Errorf("both tlsCert and tlsKey must be provided for client authentication")
	}

	return tlsConfig, nil
}

// loadTLSConfigFromSecret loads TLS certificates from a Kubernetes secret
func (e *EtcdDNSSolver) loadTLSConfigFromSecret(cfg *EtcdConfig, ch *v1alpha1.ChallengeRequest) (*tls.Config, error) {
	// Determine the namespace for the TLS secret
	namespace := cfg.TLSSecretNamespace
	if namespace == "" {
		namespace = ch.ResourceNamespace
	}

	klog.V(2).Infof("Loading TLS secret %s from namespace %s", cfg.TLSSecretRef, namespace)

	// Fetch the secret from Kubernetes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret, err := e.client.CoreV1().Secrets(namespace).Get(ctx, cfg.TLSSecretRef, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS secret %s/%s: %v", namespace, cfg.TLSSecretRef, err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TLSInsecureSkipVerify,
	}

	// Set ServerName for TLS verification if specified
	if cfg.TLSServerName != "" {
		tlsConfig.ServerName = cfg.TLSServerName
		klog.V(2).Infof("Using TLS ServerName: %s", cfg.TLSServerName)
	}

	// Determine key names (use defaults if not specified)
	caKey := cfg.TLSCAKey
	if caKey == "" {
		caKey = "ca.crt"
	}
	certKey := cfg.TLSCertKey
	if certKey == "" {
		certKey = "tls.crt"
	}
	keyKey := cfg.TLSKeyKey
	if keyKey == "" {
		keyKey = "tls.key"
	}

	klog.V(2).Infof("Using TLS secret keys: CA=%s, Cert=%s, Key=%s", caKey, certKey, keyKey)

	// Load CA certificate if present
	if caCert, ok := secret.Data[caKey]; ok {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from key '%s'", caKey)
		}
		tlsConfig.RootCAs = caCertPool
		klog.V(2).Infof("CA certificate loaded from secret key '%s'", caKey)
	}

	// Load client certificate and key if present (for mTLS)
	clientCert, certOk := secret.Data[certKey]
	clientKey, keyOk := secret.Data[keyKey]

	if certOk && keyOk {
		cert, err := tls.X509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		klog.V(2).Infof("Client certificate and key loaded from secret keys '%s' and '%s'", certKey, keyKey)
	} else if certOk || keyOk {
		return nil, fmt.Errorf("both '%s' and '%s' must be present in the secret for client authentication", certKey, keyKey)
	}

	return tlsConfig, nil
}

// loadConfig loads the etcd configuration from the ChallengeRequest
func loadConfig(cfgJSON *extapi.JSON) (*EtcdConfig, error) {
	cfg := &EtcdConfig{
		Prefix: "/skydns", // Default prefix for SkyDNS/CoreDNS
	}

	if cfgJSON == nil {
		return nil, fmt.Errorf("config is required")
	}

	if err := json.Unmarshal(cfgJSON.Raw, cfg); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	if len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("etcd endpoints must be specified")
	}

	return cfg, nil
}

// fqdnToEtcdPath converts a FQDN to an etcd path in reverse domain format
// Example: _acme-challenge.example.com. -> /skydns/com/example/_acme-challenge
func fqdnToEtcdPath(prefix, fqdn string) string {
	// Remove trailing dot if present
	fqdn = strings.TrimSuffix(fqdn, ".")

	// Split the domain into parts
	parts := strings.Split(fqdn, ".")

	// Reverse the parts for SkyDNS format
	reversed := make([]string, len(parts))
	for i, part := range parts {
		reversed[len(parts)-1-i] = part
	}

	// Build the etcd path
	path := prefix + "/" + strings.Join(reversed, "/")

	return path
}

// GetSecretsClient returns the Kubernetes client for accessing secrets
func (e *EtcdDNSSolver) GetSecretsClient(namespace string) kubernetes.Interface {
	return e.client
}
