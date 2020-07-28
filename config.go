package main

// config.go - config functions
// Copyright 2020 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE.md for more information.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

var version string

type config struct {
	AllRegions       []string
	ID               string   // PIPEFITTER_ID
	PLAllowedPeers   []string // PIPEFITTER_PL_ALLOWED_PEERS
	PLRegions        []string // PIPEFITTER_PL_REGIONS
	TargetPort       int64    // PIPEFITTER_TARGET_PORT
	TargetRegions    []string // PIPEFITTER_TARGET_REGIONS
	TargetTag        string   // PIPEFITTER_TARGET_TAG
	TargetValue      string   // PIPEFITTER_TARGET_VALUE
	UpdateAllIPs     bool     // PIPEFITTER_UPDATE_ALL_IPS
	SatelliteRegions []string
}

func buildConfig() config {
	rawID := os.Getenv("PIPEFITTER_ID")
	rawPLAllowedPeers := os.Getenv("PIPEFITTER_PL_ALLOWED_PEERS")
	rawPLRegions := os.Getenv("PIPEFITTER_PL_REGIONS")
	rawTargetPort := os.Getenv("PIPEFITTER_TARGET_PORT")
	targetPort, err := strconv.ParseInt(rawTargetPort, 10, 64)
	if err != nil {
		fmt.Printf("PIPEFITTER_TARGET_PORT is not a number\n")
		os.Exit(1)
	}
	if targetPort < 1 || targetPort > 65535 {
		fmt.Printf("PIPEFITTER_TARGET_PORT not between 1-65535 (I got %d)\n", targetPort)
		os.Exit(1)
	}
	rawTargetRegions := os.Getenv("PIPEFITTER_TARGET_REGIONS")
	rawTargetTag := os.Getenv("PIPEFITTER_TARGET_TAG")
	rawTargetValue := os.Getenv("PIPEFITTER_TARGET_VALUE")
	rawUpdateAllIPs, err := strconv.ParseBool(os.Getenv("PIPEFITTER_UPDATE_ALL_IPS"))
	if err != nil {
		rawUpdateAllIPs = false
	}

	var missing []string

	if rawID == "" {
		missing = append(missing, "PIPEFITTER_ID")
	}
	if rawPLAllowedPeers == "" {
		missing = append(missing, "PIPEFITTER_PL_ALLOWED_PEERS")
	}
	if rawPLRegions == "" {
		missing = append(missing, "PIPEFITTER_PL_REGIONS")
	}
	if rawTargetPort == "" {
		missing = append(missing, "PIPEFITTER_TARGET_PORT")
	}
	if rawTargetRegions == "" {
		missing = append(missing, "PIPEFITTER_TARGET_REGIONS")
	}
	if rawTargetTag == "" {
		missing = append(missing, "PIPEFITTER_TARGET_TAG")
	}
	if rawTargetValue == "" {
		missing = append(missing, "PIPEFITTER_TARGET_VALUE")
	}

	if len(missing) > 0 {
		fmt.Printf("Missing configuration environment vars: %v\n", missing)
		os.Exit(1)
	}

	plRegions := strings.Split(rawPLRegions, ",")
	targetRegions := strings.Split(rawTargetRegions, ",")

	var allRegions []string
	allRegions = append(allRegions, plRegions...)
	allRegions = append(allRegions, targetRegions...)
	allRegions = uniq(allRegions)

	// Satellite Regions are ones where there's a PL presence but not a
	// TargetHost presence.
	var satelliteRegions []string
	for _, region := range allRegions {
		if !contains(targetRegions, region) {
			satelliteRegions = append(satelliteRegions, region)
		}
	}

	return config{
		AllRegions:       allRegions,
		ID:               rawID,
		PLAllowedPeers:   strings.Split(rawPLAllowedPeers, ","),
		PLRegions:        plRegions,
		SatelliteRegions: satelliteRegions,
		TargetPort:       targetPort,
		TargetRegions:    targetRegions,
		TargetTag:        fmt.Sprintf("tag:%s", rawTargetTag),
		TargetValue:      rawTargetValue,
		UpdateAllIPs:     rawUpdateAllIPs,
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func uniq(elements []string) []string {
	encountered := map[string]bool{}

	for v := range elements {
		encountered[elements[v]] = true
	}

	result := []string{}
	for key := range encountered {
		result = append(result, key)
	}
	return result
}
