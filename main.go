package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func subenum() {
	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		DomainsFile:        "domains",
		ResolverList:       "all-resolvers",
		OutputFile:         "subfinder_output",
		All:                true,
	}

	// disable timestamps in logs / configure logger
	log.SetFlags(0)

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		log.Fatalf("failed to create subfinder runner: %v", err)
	}

	output := &bytes.Buffer{}
	file, err := os.Open(subfinderOpts.DomainsFile)
	if err != nil {
		log.Fatalf("failed to open domains file: %v", err)
	}
	defer file.Close()
	if err = subfinder.EnumerateMultipleDomainsWithCtx(context.Background(), file, []io.Writer{output}); err != nil {
		log.Fatalf("failed to enumerate subdomains from file: %v", err)
	}
	// print the output
	log.Println(output.String())

}

func sub_takeover() {
    // ANSI color codes
    green := "\033[32m"
    red := "\033[31m"
    reset := "\033[0m"

    // Open the input file
    file, err := os.Open("subfinder_output")
    if err != nil {
        fmt.Println("Error opening input file:", err)
        return
    }
    defer file.Close()

    // Open the output file (use O_APPEND to append to the file if it exists)
    output_file, err := os.OpenFile("subdomain_Takeover", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Println("Error creating/opening output file:", err)
        return
    }
    defer output_file.Close()

    // Create a scanner to read from the input file
    scanner := bufio.NewScanner(file)

    // Iterate over each line in the input file
    for scanner.Scan() {
        domain := scanner.Text() // Read the domain
        cname, err := net.LookupCNAME(domain) // Lookup CNAME for the domain
        if err != nil {
            // If there's an error, print in red and continue to the next domain
            fmt.Printf("%sThe CNAME for %s is not found%s\n", red, domain, reset)
            continue
        }
        // If CNAME is found, print in green
        fmt.Printf("%sThe CNAME for %s is %s%s\n", green, domain, cname, reset)

        // Write the CNAME result to the output file
        _, err = output_file.WriteString(fmt.Sprintf("The CNAME for %s is %s\n", domain, cname))
        if err != nil {
            fmt.Println("Error writing to file:", err)
        }
    }

    // Check for errors during scanning
    if err := scanner.Err(); err != nil {
        fmt.Println("Error reading from input file:", err)
    }
}


func main() {
	subenum()
	sub_takeover()
}
