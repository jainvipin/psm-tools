package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"

	"github.com/pensando/psm-go/psm_ent"
	"github.com/spf13/cobra"
)

func main() {

	var findWithIP = &cobra.Command{
		Use:   "ip [ip to search]",
		Short: "Search using workload ip",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return FindRule(strings.Join(args, " "), "")
		},
	}

	var findWithName = &cobra.Command{
		Use:   "wname [workload name to search]",
		Short: "Search using workload name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return FindRule("", strings.Join(args, " "))
		},
	}

	var rootCmd = &cobra.Command{Use: "find_rule"}
	rootCmd.AddCommand(findWithName, findWithIP)
	rootCmd.Execute()
}

func checkIpInRange(iprange string, ip net.IP) bool {
	subnetip, subnet, err := net.ParseCIDR(iprange)

	// if err is not nil iprange is an individual IP and not a range
	if err == nil {
		return subnet.Contains(ip)
	} else {
		subnetip = net.ParseIP(iprange)
		if subnetip != nil {
			return reflect.DeepEqual(subnetip, ip)
		}
	}

	return false
}

func printRule(rule psm_ent.SecuritySGRule) {
	if rule.Name != nil {
		fmt.Printf("\t\t\tName: %v\n", *rule.Name)
	}
	if rule.Description != nil {
		fmt.Printf("\t\t\tDescription: %v\n", *rule.Description)
	}
	fmt.Printf("\t\t\tAction: %v\n", *rule.Action)
	if rule.FromIpAddresses != nil && rule.ToIpAddresses != nil {
		fmt.Printf("\t\t\tFrom IPs: %v\n", strings.Join((*rule.FromIpAddresses)[:], ", "))
		fmt.Printf("\t\t\tTo IPs: %v\n", strings.Join((*rule.ToIpAddresses)[:], ", "))
	}
	if rule.Apps != nil {
		fmt.Printf("\t\t\tApps: %v\n", strings.Join((*rule.Apps)[:], ", "))
	}
	if rule.ProtoPorts != nil {
		for _, protoport := range *rule.ProtoPorts {
			fmt.Printf("\t\t\tProtocol/Ports: %v/%v\n", *protoport.Protocol, *protoport.Ports)
		}
	}
}

func findIpInPolicies(ipaddress net.IP, policies psm_ent.SecurityNetworkSecurityPolicyList) bool {

	found := false

	for _, policy := range *policies.Items {

		policy_match := false
		rule_index := 0

	ruleloop:
		for _, rule := range *policy.Spec.Rules {
			rule_index = rule_index + 1

			for _, from := range *rule.FromIpAddresses {
				if checkIpInRange(from, ipaddress) {
					if !policy_match {
						policy_match = true
						fmt.Println("\tPolicy:", *policy.Meta.Name)
					}
					fmt.Println("\t\tRule#", rule_index)
					printRule(rule)
					continue ruleloop
				}
			}

			for _, from := range *rule.ToIpAddresses {
				if checkIpInRange(from, ipaddress) {
					if !policy_match {
						policy_match = true
						fmt.Println("\tPolicy:", *policy.Meta.Name)
					}
					fmt.Println("\t\tRule#", rule_index)
					printRule(rule)
				}
			}
		}

		if policy_match && !found {
			found = true
		}
	}

	return found
}

func FindRule(ip string, wname string) error {

	if wname == "" && ip == "" {
		return fmt.Errorf("Enter either a workload name or a ip address")
	}
	if wname != "" && ip != "" {
		return fmt.Errorf("Please only provide one parameter, workload name or a ip address")
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	cfg := psm_ent.NewConfiguration()
	cfg.Scheme = "https"
	client := psm_ent.NewAPIClient(cfg)
	SecurityV1Api := (*psm_ent.SecurityV1ApiService)(&client.Common)
	WorkloadV1Api := (*psm_ent.WorkloadV1ApiService)(&client.Common)

	ctx := context.Background()
	defer ctx.Done()

	policies, _, err := SecurityV1Api.ListNetworkSecurityPolicy(ctx, "default").Execute()

	if err != nil {
		return fmt.Errorf("Error retrieving policies: %v", err)
	}

	if wname != "" {
		workload, _, err := WorkloadV1Api.GetWorkload1(ctx, wname).Execute()

		if err != nil {
		}

		fmt.Println("Found workload:", *workload.Meta.Name)

		for _, interface_ := range *workload.Spec.Interfaces {
			for _, ipaddress := range *interface_.IpAddresses {

				ip_ := net.ParseIP(ipaddress)

				if ip_ == nil {
					fmt.Println("Error parsing interface ip:", ipaddress)
				} else {
					found := findIpInPolicies(ip_, policies)
					if !found {
						fmt.Println("No rules matched")
					}
				}
			}
		}
	}

	if ip != "" {

		ip_ := net.ParseIP(ip)
		if ip_ == nil {
			return fmt.Errorf("Error parsing interface ip", ip)
		} else {
			found := findIpInPolicies(ip_, policies)
			if !found {
				fmt.Println("No rules matched")
			}
		}

	}
	return nil
}
