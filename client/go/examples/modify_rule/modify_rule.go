package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"unicode"

	"github.com/pensando/psm-go/psm_ent"
	"github.com/spf13/cobra"
)

type ErrReponse struct {
	Message []string `json:"message,omitempty"`
}

type Params struct {
	tenant     string
	policyname string

	action     string
	src_ip     string
	dest_ip    string
	proto_port string

	new_action     string
	new_src_ip     string
	new_dest_ip    string
	new_proto_port string
}

func main() {

	var params Params = Params{
		tenant:         "",
		policyname:     "",
		action:         "",
		src_ip:         "",
		dest_ip:        "",
		proto_port:     "",
		new_action:     "",
		new_src_ip:     "",
		new_dest_ip:    "",
		new_proto_port: "",
	}

	var addRule = &cobra.Command{
		Use:   "add [flags]",
		Short: "Add a new rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			return ModifyRule("add", params, cmd)
		},
	}

	var updateRule = &cobra.Command{
		Use:   "update [flags]",
		Short: "Update a existing rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			return ModifyRule("update", params, cmd)
		},
	}

	var deleteRule = &cobra.Command{
		Use:   "delete [flags]",
		Short: "delete a existing rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			return ModifyRule("delete", params, cmd)
		},
	}

	var rootCmd = &cobra.Command{Use: "modify_rule"}

	rootCmd.PersistentFlags().StringVarP(&params.tenant, "tenant", "t", "default", "Tenant name")
	rootCmd.PersistentFlags().StringVarP(&params.policyname, "policy", "n", "", "Name of policy to edit")

	rootCmd.PersistentFlags().StringVarP(&params.action, "action", "a", "", "Rule Action")
	rootCmd.PersistentFlags().StringVarP(&params.src_ip, "src_ip", "s", "any", "Source IP address for rule")
	rootCmd.PersistentFlags().StringVarP(&params.dest_ip, "dest_ip", "d", "any", "Destination IP address for rule")
	rootCmd.PersistentFlags().StringVarP(&params.proto_port, "protoport", "p", "any", "[protocol/port] for rule")

	updateRule.Flags().StringVarP(&params.new_action, "new_action", "A", "", "New action for rule (permit, deny, reject)")
	updateRule.Flags().StringVarP(&params.new_src_ip, "new_src_ip", "S", "any", "New source IP address for rule update")
	updateRule.Flags().StringVarP(&params.new_dest_ip, "new_dest_ip", "D", "any", "New destination IP address for rule update")
	updateRule.Flags().StringVarP(&params.new_proto_port, "new_protoport", "P", "any", "New [protocol/port] for rule update")

	rootCmd.AddCommand(addRule, updateRule, deleteRule)
	rootCmd.Execute()
}

func ruleInRuleList(a psm_ent.SecuritySGRule, list []psm_ent.SecuritySGRule) (bool, int) {
	matches := []int{}
	for ix, b := range list {
		if reflect.DeepEqual(b, a) {
			matches = append(matches, ix)
		}
	}

	if len(matches) > 1 {
		fmt.Println("multiple matching rules found, only modifying the first matched rule")
	}

	if len(matches) >= 1 {
		return true, matches[0]
	}

	return false, -1
}

func IsLetter(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func readProtoPort(protoport string) (string, string, error) {
	protocol := ""
	port := ""
	split := strings.Split(protoport, "/")
	if len(split) == 2 {
		protocol = split[0]
		port = split[1]
	} else if len(split) == 1 && IsLetter(split[0]) {
		protocol = split[0]
	} else {
		return "", "", fmt.Errorf("protocol and port should be entered in the following format: (protocol)/(port number)")
	}
	return protocol, port, nil

}

func ModifyRule(operation string, params Params, cmd *cobra.Command) error {

	if params.policyname == "" {
		return fmt.Errorf("'policyname' is required")
	}

	if params.action == "" {
		return fmt.Errorf("please provide action target rule")
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	cfg := psm_ent.NewConfiguration()
	cfg.Scheme = "https"
	client := psm_ent.NewAPIClient(cfg)

	protocol, port, err := readProtoPort(params.proto_port)
	if err != nil {
		return err
	}
	protoport := psm_ent.SecurityProtoPort{Ports: &port, Protocol: &protocol}

	protoports := make([]psm_ent.SecurityProtoPort, 0)
	protoports = append(protoports, protoport)

	targetrule := psm_ent.SecuritySGRule{Action: &params.action,
		FromIpAddresses: &[]string{params.src_ip},
		ProtoPorts:      &protoports,
		ToIpAddresses:   &[]string{params.dest_ip}}

	ctx := context.Background()
	defer ctx.Done()
	SecurityV1Api := (*psm_ent.SecurityV1ApiService)(&client.Common)
	policy, _, err := SecurityV1Api.GetNetworkSecurityPolicy1(ctx, params.policyname).Execute()

	if err != nil {
		return fmt.Errorf("unable to find policy named: %s", params.policyname)
	}

	if operation == "add" {
		if policy.Spec.Rules != nil {

			present, _ := ruleInRuleList(targetrule, *policy.Spec.Rules)
			if present {
				fmt.Println("Rule already exists")
				return nil
			}
			*policy.Spec.Rules = append(*policy.Spec.Rules, targetrule)
		} else {
			*policy.Spec.Rules = []psm_ent.SecuritySGRule{targetrule}
		}

	} else if operation == "update" {

		if params.new_action == "" {
			return fmt.Errorf("please provide action for new rule")
		}

		if params.new_action == "" {
			params.new_action = params.action
		}

		if params.new_src_ip == "" {
			params.new_src_ip = params.src_ip
		}

		if params.new_dest_ip == "" {
			params.new_dest_ip = params.dest_ip
		}

		if params.new_proto_port == "" {
			params.new_proto_port = params.proto_port
		}

		protocol, port, err := readProtoPort(params.new_proto_port)
		if err != nil {
			return err
		}
		protoport := psm_ent.SecurityProtoPort{Ports: &port, Protocol: &protocol}

		protoports := make([]psm_ent.SecurityProtoPort, 0)
		protoports = append(protoports, protoport)

		newrule := psm_ent.SecuritySGRule{Action: &params.new_action,
			FromIpAddresses: &[]string{params.new_src_ip},
			ProtoPorts:      &protoports,
			ToIpAddresses:   &[]string{params.new_dest_ip}}

		present, ix := ruleInRuleList(targetrule, *policy.Spec.Rules)
		if !present {
			return fmt.Errorf("target rule not found")
		}

		(*policy.Spec.Rules)[ix] = newrule

	} else if operation == "delete" {
		present, ix := ruleInRuleList(targetrule, *policy.Spec.Rules)
		if present {
			*policy.Spec.Rules = append((*policy.Spec.Rules)[:ix], (*policy.Spec.Rules)[ix+1:]...)
		} else {
			return fmt.Errorf("rule not found in policy")
		}

	} else {
		return fmt.Errorf("illegal operation, use one of [add|update|delete]")
	}

	_, resp, err := SecurityV1Api.UpdateNetworkSecurityPolicy1(ctx, params.policyname).Body(policy).Execute()

	if err == nil {
		fmt.Println("Successfully updated security policy")
	} else {

		bytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error parsing api response: %v", resp.Body)
		}

		res := ErrReponse{}
		json.Unmarshal(bytes, &res)
		return fmt.Errorf("error updating security policy\n  API Response Error: %v", strings.Join(res.Message, "\n"))
	}

	return nil
}
