# cert-manager-webhook-etcd

DNS webhook solver for [cert-manager](https://cert-manager.io/) using **etcd** as DNS backend. This webhook allows cert-manager to create DNS TXT records in etcd for ACME DNS-01 validation.

## 🎯 Features

- ✅ DNS-01 validation support for Let's Encrypt (and other ACME CAs)
- ✅ DNS records storage in etcd using SkyDNS/CoreDNS format
- ✅ Compatible with CoreDNS using the etcd plugin
- ✅ Deployment via Helm or Kubernetes manifests
- ✅ etcd authentication support
- ✅ TLS/mTLS support for secure etcd connections
- ✅ Wildcard certificates supported

## 📋 Prerequisites

- Kubernetes 1.20+
- cert-manager 1.0+
- etcd cluster accessible from Kubernetes
- CoreDNS (or other DNS server) configured with etcd backend

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────┐
│   cert-manager  │────▶│  webhook-etcd        │────▶│  etcd   │
│                 │     │  (this project)      │     │         │
└─────────────────┘     └──────────────────────┘     └────┬────┘
                                                          │
                        ┌──────────────────────┐          │
                        │  CoreDNS             │◀─────────┘
                        │  (etcd plugin)       │
                        └──────────────────────┘
```

## 🚀 Installation

### Option 1: Helm (Recommended)

```bash
# Install the Helm chart
helm install cert-manager-webhook-etcd \
  ./charts/cert-manager-webhook-etcd \
  --namespace cert-manager \
  --set groupName=acme.example.com
```

### Option 2: Kubernetes Manifests

```bash
# Apply the manifests
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/apiservice.yaml
```

## ⚙️ Configuration

### 1. Create a ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.example.com  # Must match GROUP_NAME
            solverName: etcd
            config:
              endpoints:
                - "http://etcd-0.etcd:2379"
                - "http://etcd-1.etcd:2379"
                - "http://etcd-2.etcd:2379"
              prefix: "/skydns"
              dialTimeout: 10
              # Optional: authentication
              # username: "root"
              # password: "password"
```

### 2. Create a Certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-certificate
  namespace: default
spec:
  secretName: my-tls-secret
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - example.com
    - "*.example.com"  # Wildcard supported
```

## 🔧 Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `endpoints` | List of etcd endpoints | **Required** |
| `prefix` | Prefix for DNS records | `/skydns` |
| `username` | etcd username | - |
| `password` | etcd password | - |
| `dialTimeout` | Connection timeout (seconds) | `10` |
| `tlsSecretRef` | Name of Kubernetes secret containing TLS certs | - |
| `tlsSecretNamespace` | Namespace of the TLS secret | challenge namespace |
| `tlsInsecureSkipVerify` | Skip TLS verification (not recommended) | `false` |

## 🔐 TLS Configuration

To connect to a TLS-secured etcd cluster, create a Kubernetes secret containing the certificates:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: etcd-tls-certs
  namespace: cert-manager
type: Opaque
data:
  # CA certificate to verify the etcd server
  ca.crt: <base64-encoded-ca-cert>
  # Client certificate (optional, for mTLS)
  tls.crt: <base64-encoded-client-cert>
  # Client private key (optional, for mTLS)
  tls.key: <base64-encoded-client-key>
```

Then reference it in your Issuer:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - dns01:
          webhook:
            groupName: acme.example.com
            solverName: etcd
            config:
              endpoints:
                - "https://etcd-0.etcd:2379"
                - "https://etcd-1.etcd:2379"
                - "https://etcd-2.etcd:2379"
              prefix: "/skydns"
              tlsSecretRef: "etcd-tls-certs"
              tlsSecretNamespace: "cert-manager"
```

### TLS Options

- **CA only**: Provide only `ca.crt` to verify the etcd server
- **mTLS (mutual TLS)**: Provide `ca.crt`, `tls.crt` and `tls.key` for client authentication
- **Insecure**: Use `tlsInsecureSkipVerify: true` (not recommended for production)

## 📁 DNS Records Format

DNS records are stored in etcd using the SkyDNS format, compatible with CoreDNS:

```
/skydns/com/example/_acme-challenge
```

The content is JSON:
```json
{
  "text": "challenge-token-value",
  "ttl": 60
}
```

## 🔍 Verification

To verify that the webhook is working:

```bash
# Check the pod
kubectl get pods -n cert-manager -l app.kubernetes.io/name=cert-manager-webhook-etcd

# Check the logs
kubectl logs -n cert-manager -l app.kubernetes.io/name=cert-manager-webhook-etcd

# Check the APIService
kubectl get apiservice v1alpha1.acme.example.com
```

## 🔨 Development

### Local Build

```bash
# Download dependencies
make deps

# Build
make build

# Tests
make test
```

### Docker Build

```bash
# Build the image
make docker-build

# Push to a registry
REGISTRY=ghcr.io/your-org make docker-push
```

## 🐛 Troubleshooting

### DNS challenge not resolving

1. Verify that etcd is accessible from the webhook
2. Check the prefix in the configuration
3. Verify that CoreDNS uses the same prefix

### Authentication error

Check the etcd credentials in the Issuer configuration.

### Webhook not starting

```bash
kubectl describe pod -n cert-manager -l app.kubernetes.io/name=cert-manager-webhook-etcd
kubectl logs -n cert-manager -l app.kubernetes.io/name=cert-manager-webhook-etcd
```

## 📄 License

Apache License 2.0

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or a pull request.