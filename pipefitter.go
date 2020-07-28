package main

// pipefitter.go - main function
// Copyright 2020 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE.md for more information.

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

func main() {
	lambda.Start(runLambda)
}

func runLambda(ctx context.Context) (string, error) {
	config := buildConfig()
	fmt.Printf("START: Pipefitter %s (id: %s) starting. ", version, config.ID)
	fmt.Printf("Targets exist in %s on port %d - will search for hosts using %s=%s. ",
		config.TargetRegions, config.TargetPort, config.TargetTag, config.TargetValue)
	fmt.Printf("PL enabled for %s (Satellites: %s). ", config.PLRegions, config.SatelliteRegions)
	if config.UpdateAllIPs == true {
		fmt.Printf("PIPEFITTER_UPDATE_ALL_IPS is 1: will update target groups in %s. ", config.AllRegions)
	} else {
		fmt.Printf("PIPEFITTER_UPDATE_ALL_IPS is 0: will update target groups in %s. ", config.SatelliteRegions)
	}
	fmt.Printf("\n")

	var sess map[string]*session.Session
	sess = make(map[string]*session.Session)

	for _, region := range config.AllRegions {
		sess[region], _ = session.NewSession(&aws.Config{
			Region: aws.String(region)},
		)
	}

	targetHostIPs, err := getTargetHostIPs(sess, config)
	if err != nil {
		return "", fmt.Errorf("ERROR: Unable to get Target Host IPs: %s\n", err)
	}
	if len(targetHostIPs) > 0 {
		fmt.Printf("INFO : Found %d hosts with search %s=%s across %s: %s\n", len(targetHostIPs), config.TargetTag, config.TargetValue, config.TargetRegions, targetHostIPs)
	} else {
		fmt.Printf("INFO : Did not find any target hosts!")
	}

	var targetGroupRegions []string
	if config.UpdateAllIPs == true {
		targetGroupRegions = config.AllRegions
	} else {
		targetGroupRegions = config.SatelliteRegions
	}

	// Get our managed Target Group ARNs
	pfTargetGroupARNs, err := getTargetGroupARNs(sess, config, targetGroupRegions)
	if err != nil {
		return "", fmt.Errorf("ERROR: Unable to get Target Group ARNs: %s\n", err)
	}
	if len(pfTargetGroupARNs) > 0 {
		err = updateTargets(sess, config, targetHostIPs, pfTargetGroupARNs)
		if err != nil {
			return "", fmt.Errorf("ERROR: Unable to update target groups: %s", err)
		}
	} else {
		fmt.Printf("INFO : No ELB target groups to update!\n")
	}

	// get endpoint IDs by region, then update permissions
	vpceids, err := getVPCEndpointIDs(sess, config)
	if err != nil {
		return "", fmt.Errorf("ERROR: Unable to get VPC Endpoint IDs: %s\n", err)
	}

	if len(vpceids) > 0 {
		err = updateVPCEndpointPermissions(sess, config, vpceids)
		if err != nil {
			return "", fmt.Errorf("ERROR: Unable to update permissions: %s", err)
		}
	} else {
		fmt.Printf("INFO : No PL Endpoints to update!\n")
	}
	return "OK", nil
}
