package main

import (
	"flag"
	"fmt"
	"inkspire/internal/osint"
	"inkspire/internal/scanner"
	"inkspire/internal/utils"
	"inkspire/internal/vulns"
	"path/filepath"
	"time"
)

func main() {
	ipPtr := flag.String("ip", "", "Target IP or CIDR")
	portPtr := flag.String("ports", "1-1024", "Port range")
	workerPtr := flag.Int("w", 100, "Workers")
	forcePtr := flag.Bool("force", false, "Scan even if host is down")
	flag.Parse()

	if *ipPtr == "" {
		flag.Usage()
		return
	}

	portDBPath := filepath.Join("..", "data", "known_ports.json")
	portDB, err := utils.LoadKnownPorts(portDBPath)
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not load known_ports.json: %v\n", err)
		portDB = make(map[int]string)
	}

	fmt.Printf("🕵️‍♂️ Starting Inkspire OSINT for %s...\n", *ipPtr)

	hostnames := osint.LookupDNS(*ipPtr)
	fmt.Printf("🌐 DNS: %v\n", hostnames)

	geo, _ := osint.GetGeo(*ipPtr)
	if geo != nil {
		fmt.Printf("📍 Location: %s, %s (%s)\n", geo.City, geo.Country, geo.ISP)
	}

	whoisData, _ := osint.GetWhois(*ipPtr)
	if whoisData != nil {
		fmt.Printf("🏢 Org: %s | Registrar: %s\n", whoisData.Org, whoisData.Registrar)
	}

	fmt.Printf("📡 Checking host status... ")
	if !utils.IsAlive(*ipPtr) && !*forcePtr {
		fmt.Println("❌ Host is DOWN (or blocks ICMP). Use -force to scan anyway.")
		return
	}
	fmt.Println("✅ Host is UP")

	portList, _ := utils.ParsePorts(*portPtr)
	fmt.Printf("🚀 Scanning %d ports (TCP/UDP)...\n", len(portList))

	results := scanner.Scan(*ipPtr, portList, *workerPtr, time.Second, portDB)

	for _, res := range results {
		cves := vulns.Check(res.Service)
		fmt.Printf("✅ [%5s] Port %-5d is %-10s (%s)\n", res.Proto, res.Port, res.State, res.Service)
		if len(cves) > 0 {
			for _, cve := range cves {
				fmt.Printf("      ⚠️  Vulnerability: %s\n", cve)
			}
		}
	}

	err = utils.SaveReport(results, *ipPtr)
	if err != nil {
		fmt.Printf("❌ Error saving report: %v\n", err)
	} else {
		fmt.Println("✅ Report saved successfully.")
	}
}
