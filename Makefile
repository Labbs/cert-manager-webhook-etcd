# Makefile for cert-manager-webhook-etcd

IMAGE_NAME ?= cert-manager-webhook-etcd
IMAGE_TAG ?= latest
REGISTRY ?= 

.PHONY: all build test docker-build docker-push deploy clean

all: build

# Build the Go binary
build:
	CGO_ENABLED=0 go build -o bin/webhook -ldflags="-w -s" .

# Run tests
test:
	go test -v ./...

# Download dependencies
deps:
	go mod download
	go mod tidy

# Build Docker image
docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Push Docker image
docker-push:
ifdef REGISTRY
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
else
	docker push $(IMAGE_NAME):$(IMAGE_TAG)
endif

# Deploy to Kubernetes using Helm
deploy:
	helm upgrade --install cert-manager-webhook-etcd \
		./charts/cert-manager-webhook-etcd \
		--namespace cert-manager \
		--create-namespace

# Deploy using kubectl
deploy-manifests:
	kubectl apply -f deploy/rbac.yaml
	kubectl apply -f deploy/deployment.yaml
	kubectl apply -f deploy/apiservice.yaml

# Undeploy from Kubernetes
undeploy:
	helm uninstall cert-manager-webhook-etcd --namespace cert-manager || true

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Lint the code
lint:
	golangci-lint run ./...

# Format the code
fmt:
	go fmt ./...

# Generate go.sum
generate-sum:
	go mod tidy

# Local development - run the webhook locally
run-local:
	go run . --tls-cert-file=./testdata/tls.crt --tls-private-key-file=./testdata/tls.key --secure-port=8443

# Help target
help:
	@echo "Available targets:"
	@echo "  build          - Build the Go binary"
	@echo "  test           - Run tests"
	@echo "  deps           - Download dependencies"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-push    - Push Docker image to registry"
	@echo "  deploy         - Deploy to Kubernetes using Helm"
	@echo "  deploy-manifests - Deploy using kubectl manifests"
	@echo "  undeploy       - Undeploy from Kubernetes"
	@echo "  clean          - Clean build artifacts"
	@echo "  lint           - Lint the code"
	@echo "  fmt            - Format the code"
	@echo "  help           - Show this help message"
