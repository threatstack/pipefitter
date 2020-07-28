package main

// awsVPCe.go - functions for VPC endpoints
// Copyright 2020 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE.md for more information.

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func getVPCEndpointIDs(sess map[string]*session.Session, config config) (map[string][]string, error) {
	var vpcebyregion map[string][]string
	vpcebyregion = make(map[string][]string)
	for _, region := range config.PLRegions {
		var vpceids []string

		ec2svc := ec2.New(sess[region])
		params := &ec2.DescribeVpcEndpointServicesInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String("tag:pipefitter"),
					Values: []*string{aws.String(config.ID)},
				},
			},
		}
		resp, err := ec2svc.DescribeVpcEndpointServices(params)
		if err != nil {
			return nil, err
		}

		// vpc id is buried in the servicename. cycle through them and grab it.
		serviceNames := aws.StringValueSlice(resp.ServiceNames)
		for _, v := range serviceNames {
			if strings.Contains(v, "vpce-svc-") {
				vpceids = append(vpceids, strings.Split(v, ".")[4])
			}
		}
		if len(vpceids) > 0 {
			vpcebyregion[region] = vpceids
		}
	}
	return vpcebyregion, nil
}

func updateVPCEndpointPermissions(sess map[string]*session.Session, config config, endpoints map[string][]string) error {
	for region := range endpoints {
		// pull permissions
		for _, vpceid := range endpoints[region] {
			ec2svc := ec2.New(sess[region])
			vpcparams := &ec2.DescribeVpcEndpointServicePermissionsInput{
				ServiceId: aws.String(vpceid),
			}

			vpcresp, err := ec2svc.DescribeVpcEndpointServicePermissions(vpcparams)
			if err != nil {
				return err
			}

			var principalsOnEndpoint []string
			for _, pr := range vpcresp.AllowedPrincipals {
				// convert account ARN to just account number
				p := aws.StringValue(pr.Principal)
				if strings.Contains(p, ":root") {
					principalsOnEndpoint = append(principalsOnEndpoint, strings.Split(p, ":")[4])
				} else {
					// could be a *, could be something we dont know, let's just take care of it.
					principalsOnEndpoint = append(principalsOnEndpoint, p)
				}
			}

			var principalsToAdd []string
			var principalsToRemove []string
			var changes bool
			for _, account := range config.PLAllowedPeers {
				if !contains(principalsOnEndpoint, account) {
					// Account is in the allowed peers group, but not in AWS.
					principalsToAdd = append(principalsToAdd, fmt.Sprintf("arn:aws:iam::%s:root", account))
					changes = true
				}
			}
			for _, account := range principalsOnEndpoint {
				if !contains(config.PLAllowedPeers, account) {
					// AWS has this peer, but we don't. Either its a parsed account id (ideal) or another thing
					// but we can handle either situation.
					if len(account) == 12 {
						// probably an account number, format it
						principalsToRemove = append(principalsToRemove, fmt.Sprintf("arn:aws:iam::%s:root", account))
					} else {
						principalsToRemove = append(principalsToRemove, account)
					}
					changes = true
				}
			}

			if changes == true {
				vpceModifyParams := &ec2.ModifyVpcEndpointServicePermissionsInput{
					ServiceId: aws.String(vpceid),
				}
				if len(principalsToAdd) > 0 {
					vpceModifyParams.AddAllowedPrincipals = aws.StringSlice(principalsToAdd)
				}
				if len(principalsToRemove) > 0 {
					vpceModifyParams.RemoveAllowedPrincipals = aws.StringSlice(principalsToRemove)
				}

				vpceModifyPerms, err := ec2svc.ModifyVpcEndpointServicePermissions(vpceModifyParams)
				if err != nil {
					return err
				}

				if aws.BoolValue(vpceModifyPerms.ReturnValue) {
					fmt.Printf("INFO : Updated %s/%s: ", region, vpceid)
					if len(principalsToAdd) > 0 {
						fmt.Printf("added %s", principalsToAdd)
					}
					if len(principalsToRemove) > 0 {
						fmt.Printf("removed %s", principalsToRemove)
					}
					fmt.Printf("\n")
				}
			} else {
				fmt.Printf("INFO : %s/%s: No PL permisisons changes\n", region, vpceid)
			}
		}
	}
	return nil
}
