package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/noahzmr/testudo/internal/doctor"
)

// cmdDoctor runs the layered connectivity diagnosis and prints a bottom-up
// PASS/FAIL ladder with the first failing layer highlighted as the root cause.
// This turns Testudo's existing probe/netlink primitives into a single
// "what's wrong with my network" command.
func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	opts := doctor.DefaultOptions()
	targetIP := fs.String("target-ip", opts.WANTargetIP, "WAN IP to ICMP-probe for raw reachability")
	targetName := fs.String("target-name", opts.WANTargetName, "hostname resolved by the DNS check")
	captiveURL := fs.String("captive-url", opts.CaptiveURL, "URL expected to return HTTP 204 (captive-portal detection)")
	timeout := fs.Duration("timeout", opts.CheckTimeout, "per-check timeout")
	noCaptive := fs.Bool("no-captive", false, "skip the captive-portal probe (offline/air-gapped use)")
	asJSON := fs.Bool("json", false, "emit the full report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts.WANTargetIP = *targetIP
	opts.WANTargetName = *targetName
	opts.CaptiveURL = *captiveURL
	opts.CheckTimeout = *timeout
	opts.SkipCaptive = *noCaptive

	// Outer budget: every check is individually bounded, but cap the whole run
	// so a wedged probe can't hang the command indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rep := doctor.NewDefault(opts).Run(ctx)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	printDoctorReport(rep)

	// Non-zero exit when connectivity is broken, so the command is usable in
	// scripts and CI health gates.
	if rep.Verdict == doctor.VerdictBroken {
		os.Exit(2)
	}
	return nil
}

func printDoctorReport(rep doctor.Report) {
	fmt.Println("Testudo connectivity diagnosis")
	fmt.Println("------------------------------")
	for _, r := range rep.Results {
		marker := "•"
		switch r.Status {
		case doctor.StatusPass:
			marker = "✔"
		case doctor.StatusWarn:
			marker = "!"
		case doctor.StatusFail:
			marker = "✗"
		case doctor.StatusSkip:
			marker = "·"
		}
		root := ""
		if rep.RootCause != nil && rep.RootCause.Name == r.Name && r.Status == doctor.StatusFail {
			root = "  <-- ROOT CAUSE"
		}
		fmt.Printf("  %s [%-7s] %-14s %s%s\n", marker, r.Layer, r.Name, r.Summary, root)
		if r.Status != doctor.StatusPass && r.Status != doctor.StatusSkip && r.Remedy != "" {
			fmt.Printf("      fix: %s\n", r.Remedy)
		}
	}
	fmt.Println()
	fmt.Printf("Verdict: %s   Score: %d/100\n", rep.Verdict, rep.Score)
	if rep.RootCause != nil {
		fmt.Printf("Root cause at the %s layer: %s\n", rep.RootCause.Layer, rep.RootCause.Summary)
	}
}
