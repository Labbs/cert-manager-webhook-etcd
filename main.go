package main

import (
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"k8s.io/klog/v2"

	"github.com/cert-manager-webhook-etcd/pkg/solver"
)

// GroupName is the API group name for this webhook
var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		GroupName = "acme.etcd.labbs"
	}

	klog.InitFlags(nil)

	// Run the webhook server with our custom DNS solver
	cmd.RunWebhookServer(GroupName,
		&solver.EtcdDNSSolver{},
	)
}
