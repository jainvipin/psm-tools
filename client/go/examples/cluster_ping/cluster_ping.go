package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/pensando/psm-go/psm_ent"
	"github.com/spf13/cobra"
)

func main() {

	var rootCmd = &cobra.Command{
		Use:   "cluster_ping",
		Short: "Ping the PSM Cluster",
		Long:  `Ping the PSM Cluster and print some details about it.`,
		Args:  cobra.MinimumNArgs(0),
		Run:   ClusterPing,
	}

	rootCmd.Execute()
}

func ClusterPing(cmd *cobra.Command, args []string) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	cfg := psm_ent.NewConfiguration()
	cfg.Scheme = "https"
	client := psm_ent.NewAPIClient(cfg)
	ClusterV1Api := (*psm_ent.ClusterV1ApiService)(&client.Common)

	ctx := context.Background()
	defer ctx.Done()
	cluster, _, _ := ClusterV1Api.GetCluster(ctx).Execute()

	// Cluster Uptime
	currentTime := cluster.Status.CurrentTime
	creationTime := cluster.Meta.CreationTime
	uptime := currentTime.Sub(*creationTime)
	fmt.Println("Cluster Uptime: ", uptime)

	nodes_unhealthy := false
	for _, node := range *cluster.Status.QuorumStatus.Members {
		conditions := *node.Conditions
		if conditions != nil && len(conditions) > 0 {
			node_health := conditions[0].Type
			if *node_health != "healthy" {
				nodes_unhealthy = true
				fmt.Println("\tCluster Quorum Node:", node.Name)
				fmt.Println("\tCluster Quorum Node:", node_health)
			}
		}
	}

	if !nodes_unhealthy {
		fmt.Println("\tAll nodes are healthy")
	}

	// DSCs and health
	dscs, _, _ := ClusterV1Api.ListDistributedServiceCard(ctx).Execute()

	if dscs.Items != nil {
		for _, dsc := range *dscs.Items {
			conditions := *dsc.Status.Conditions
			if conditions != nil && len(conditions) > 0 {
				fmt.Println("\tDSC "+*dsc.Meta.Name+" is ", *conditions[0].Type)
			} else {
				fmt.Println("\tDSC " + *dsc.Meta.Name + " health cannot be determined.")
			}
		}
	}

	fmt.Println("\nNo DSCs found.")

}
