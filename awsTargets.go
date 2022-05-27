package main

// awsTargets.go - handle targets
// Copyright 2020-2022 F5 Inc.
// Licensed under the BSD 3-clause license; see LICENSE.md for more information.

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elbv2"
)

func getTargetHostIPs(sess map[string]*session.Session, config config) ([]string, error) {
	var targetIPs []string
	for _, region := range config.TargetRegions {
		ec2svc := ec2.New(sess[region])
		params := &ec2.DescribeInstancesInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String(config.TargetTag),
					Values: []*string{aws.String(config.TargetValue)},
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: []*string{aws.String("running"), aws.String("pending")},
				},
			},
		}
		resp, err := ec2svc.DescribeInstances(params)
		if err != nil {
			return []string{}, fmt.Errorf("Unable to get instances for %s=%s in %s: %s", config.TargetTag, config.TargetValue, region, err)
		}
		for idx := range resp.Reservations {
			for _, inst := range resp.Reservations[idx].Instances {
				for _, iface := range inst.NetworkInterfaces {
					targetIPs = append(targetIPs, aws.StringValue(iface.PrivateIpAddress))
				}
			}
		}
	}
	return targetIPs, nil
}

func updateTargets(sess map[string]*session.Session, config config, targetHostIPs []string, targetGroupARNs map[string][]string) error {
	for region := range targetGroupARNs {
		for _, tg := range targetGroupARNs[region] {
			var ips []string
			var regNewTargetIPs []string
			var regNewTargets []*elbv2.TargetDescription
			var deregOldTargetIPs []string
			var deregOldTargets []*elbv2.TargetDescription
			var changes bool
			elbv2svc := elbv2.New(sess[region])
			params := &elbv2.DescribeTargetHealthInput{
				TargetGroupArn: aws.String(tg),
			}
			resp, err := elbv2svc.DescribeTargetHealth(params)
			if err != nil {
				return err
			}

			for _, targetHealth := range resp.TargetHealthDescriptions {
				ips = append(ips, aws.StringValue(targetHealth.Target.Id))
			}
			// source of truth is targetIPs. if targetIPs has something ips doesnt, add it.
			// otherwise, remove it.
			for _, trueIP := range targetHostIPs {
				if !contains(ips, trueIP) {
					target := &elbv2.TargetDescription{
						AvailabilityZone: aws.String("all"),
						Id:               aws.String(trueIP),
						Port:             aws.Int64(config.TargetPort),
					}
					regNewTargets = append(regNewTargets, target)
					regNewTargetIPs = append(regNewTargetIPs, trueIP)
				}
			}

			if len(regNewTargets) > 0 {
				regTargets := &elbv2.RegisterTargetsInput{
					TargetGroupArn: aws.String(tg),
					Targets:        regNewTargets,
				}
				_, err := elbv2svc.RegisterTargets(regTargets)
				if err != nil {
					return err
				}
				changes = true
			}

			// And the opposite: if something is in ips that isnt in trueIPs lets unregister it.
			for _, falseIP := range ips {
				if !contains(targetHostIPs, falseIP) {
					target := &elbv2.TargetDescription{
						AvailabilityZone: aws.String("all"),
						Id:               aws.String(falseIP),
						Port:             aws.Int64(config.TargetPort),
					}
					deregOldTargets = append(deregOldTargets, target)
					deregOldTargetIPs = append(deregOldTargetIPs, falseIP)
				}
			}
			if len(deregOldTargets) > 0 {
				deregTargets := &elbv2.DeregisterTargetsInput{
					TargetGroupArn: aws.String(tg),
					Targets:        deregOldTargets,
				}
				_, err := elbv2svc.DeregisterTargets(deregTargets)
				if err != nil {
					return err
				}
				changes = true
			}

			if changes {
				fmt.Printf("INFO : ELB Target Update: %s ", tg)
				if len(regNewTargets) > 0 && len(deregOldTargets) > 0 {
					fmt.Printf("added %s, removed %s\n", regNewTargetIPs, deregOldTargetIPs)
				} else if len(regNewTargets) > 0 && len(deregOldTargets) == 0 {
					fmt.Printf("added %s\n", regNewTargetIPs)
				} else if len(regNewTargets) == 0 && len(deregOldTargets) > 0 {
					fmt.Printf("removed %s\n", deregOldTargetIPs)
				}
			}
		}
	}
	return nil
}

func getTargetGroupARNs(sess map[string]*session.Session, config config, targetGroupRegions []string) (map[string][]string, error) {
	var pfTargetGroupARNs map[string][]string
	pfTargetGroupARNs = make(map[string][]string)
	for _, region := range targetGroupRegions {
		elbv2svc := elbv2.New(sess[region])
		params := &elbv2.DescribeTargetGroupsInput{}
		resp, err := elbv2svc.DescribeTargetGroups(params)
		if err != nil {
			return nil, fmt.Errorf("DescribeTargetGroups failed in %s: %s", region, err)
		}
		var allTargetGroups []string
		for _, tg := range resp.TargetGroups {
			allTargetGroups = append(allTargetGroups, aws.StringValue(tg.TargetGroupArn))
		}

		if len(allTargetGroups) > 0 {
			// can req 20 at a time. some orgs will need a loop here.
			tagsParams := &elbv2.DescribeTagsInput{
				ResourceArns: aws.StringSlice(allTargetGroups),
			}
			tagsResp, err := elbv2svc.DescribeTags(tagsParams)
			if err != nil {
				return nil, fmt.Errorf("DescribeTags failed in %s: %s", region, err)
			}
			for _, allTags := range tagsResp.TagDescriptions {
				for _, tag := range allTags.Tags {
					if aws.StringValue(tag.Key) == "pipefitter" && aws.StringValue(tag.Value) == config.ID {
						pfTargetGroupARNs[region] = append(pfTargetGroupARNs[region], aws.StringValue(allTags.ResourceArn))
					}
				}
			}
		}
	}
	return pfTargetGroupARNs, nil
}
