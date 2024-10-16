package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	httpx "github.com/projectdiscovery/httpx/runner"
	subfinder "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func subenum() error {
	fmt.Println("##################### Subdomain Enumeration Starts : #####################")
	subfinderOpts := &subfinder.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		DomainsFile:        "domains",
		ResolverList:       "all-resolvers",
		OutputFile:         "subfinder_output",
		All:                true,
		Silent:             true,
	}

	// disable timestamps in logs / configure logger
	log.SetFlags(0)

	subfinder, err := subfinder.NewRunner(subfinderOpts)
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
	fmt.Println("##################### Subdomain Enumeration Ends : #####################")
	return nil

}

func filtered() error {
	fmt.Println("##################### Filter Starts : #####################")
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)

	options := httpx.Options{
		Retries:            3,
		Methods:            "GET",
		InputFile:          "subfinder_output",
		FollowRedirects:    true,
		TechDetect:         true,
		VHost:              true,
		Output:             "httpx_file",
		StatusCode:         true,
		RandomAgent:        true,
		ExtractTitle:       true,
		OutputIP:           true,
		OutputServerHeader: true,
		TLSGrab:            true,
		Silent:             true,
	}

	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := httpx.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
	fmt.Println("##################### Filter Ends : #####################")
	return nil
}

func spliter() error {
	// Define the input file
	inputFile := "httpx_file"

	// Define the output files for different status codes
	statusCodes := map[string]string{
		"200": "alive_subs",
		"403": "forbidden",
		"30":  "redirect_subs",
		"404": "takeover_subs",
		"50":  "server_errors",
		"":    "all_in_one",
	}

	// Open the input file
	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Create or open the file that will hold all domains
	allDomainsFile, err := os.Create("all_in_one")
	if err != nil {
		return fmt.Errorf("failed to create all_in_one file: %v", err)
	}
	defer allDomainsFile.Close()

	// Prepare file writers for each status code output
	outputFiles := make(map[string]*os.File)
	for _, outputFile := range statusCodes {
		outFile, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer outFile.Close()
		outputFiles[outputFile] = outFile
	}

	scanner := bufio.NewScanner(file)

	// Read each line from the input file
	for scanner.Scan() {
		line := scanner.Text()

		// Extract the domain (the first field) and write it to the all_in_one file
		fields := strings.Fields(line)
		if len(fields) > 0 {
			_, err := allDomainsFile.WriteString(fields[0] + "\n")
			if err != nil {
				return fmt.Errorf("failed to write to all_in_one file: %v", err)
			}
		}

		// Check each status code and write the matching line to its respective file
		for code, outputFile := range statusCodes {
			if strings.Contains(line, code) {
				if len(fields) > 0 {
					_, err := outputFiles[outputFile].WriteString(fields[0] + "\n")
					if err != nil {
						return fmt.Errorf("failed to write to file: %v", err)
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	return nil
}

func sub_takeover()error {
	fmt.Println("##################### Subdomain Takeover Starts : #####################")
	// ANSI color codes
	green := "\033[32m"
	red := "\033[31m"
	reset := "\033[0m"

	// Open the input file
	file, err := os.Open("takeover_subs")
	if err != nil {
		fmt.Println("Error opening input file:", err)
		
	}
	defer file.Close()

	// Check if the input file is empty
	stat, err := file.Stat()
	if err != nil {
		fmt.Println("Error getting input file info:", err)
		
	}
	if stat.Size() == 0 {
		fmt.Println("The input file 'takeover_subs' is empty.")
		
	}

	// Open the output file (use O_APPEND to append to the file if it exists)
	output_file, err := os.OpenFile("subdomain_Takeover", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error creating/opening output file:", err)
		
	}
	defer output_file.Close()

	// Create a scanner to read from the input file
	scanner := bufio.NewScanner(file)

	// Iterate over each line in the input file
	for scanner.Scan() {
		domain := scanner.Text() // Read the domain

		// Check if the domain is empty
		if domain == "" {
			fmt.Println("Skipping empty line in the input file.")
			continue
		}

		// Remove "http://" or "https://" from the domain
		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.TrimPrefix(domain, "https://")

		// Perform CNAME lookup for the domain
		cname, err := net.LookupCNAME(domain)
		if err != nil {
			// Print error with more detail in red and continue to the next domain
			fmt.Printf("%sError looking up CNAME for %s: %s%s\n", red, domain, err.Error(), reset)
			continue
		}

		// If CNAME is found, print it in green
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
	fmt.Println("##################### Subdomain Takeover Ends : #####################")
	return nil 
}


func extractUniqueIPs() error {
	filename := "httpx_file"

	// Define the IP address regular expression pattern
	ipRegex := `\b([0-9]{1,3}\.){3}[0-9]{1,3}\b`
	re := regexp.MustCompile(ipRegex)

	// Open the input file
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Create a map to store unique IP addresses
	ipMap := make(map[string]bool)

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Find all IP addresses in the line
		ips := re.FindAllString(line, -1)
		for _, ip := range ips {
			ipMap[ip] = true // Store the IP in the map to ensure uniqueness
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	// Convert the map keys (IP addresses) to a slice
	var uniqueIPs []string
	for ip := range ipMap {
		uniqueIPs = append(uniqueIPs, ip)
	}

	// Sort the IP addresses
	sort.Strings(uniqueIPs)

	// Create or open the output file
	outputFile, err := os.Create("IPs.txt")
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Write the unique IP addresses to the output file
	for _, ip := range uniqueIPs {
		_, err := outputFile.WriteString(ip + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}

	// Print the unique IP addresses to the console
	for _, ip := range uniqueIPs {
		fmt.Println(ip)
	}

	return nil
}

// Function to send notifications
func notification(success bool, errorMsg string) {
	const (
		discordWebhookURL = "https://discord.com/api/webhooks/1295833677091307612/bIFlhaoQwRO4blcorMEoI2rIv0McRxdDpMGQ4tA44FMQsx0OdymwyLgc_N_GahvyUrTz"
	)

	var message string
	if success {
		message = "✅ Success: Task completed successfully."
	} else {
		message = fmt.Sprintf("❌ Error: %s", errorMsg)
	}

	payload := map[string]string{"content": message}
	payloadBytes, _ := json.Marshal(payload)

	// Function to post to webhook
	postToWebhook := func(webhookURL string) error {
		req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(payloadBytes))
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("non-ok HTTP status: %v", resp.StatusCode)
		}

		return nil
	}

	// Send notifications
	if err := postToWebhook(discordWebhookURL); err != nil {
		fmt.Println("Error sending to Discord:", err)
	}
}

// Wrapper to execute functions and send notifications
func executeWithNotification(task func() error) {
	if err := task(); err != nil {
		notification(false, err.Error()) // Notify with error
	} else {
		notification(true, "") // Notify success
	}
}


func main() {
	// subenum()
	// filtered()
	// spliter()
	// extractUniqueIPs()
	//sub_takeover()
	// executeWithNotification(subenum)
	// executeWithNotification(filtered)
	// executeWithNotification(spliter)
	// executeWithNotification(extractUniqueIPs)
	executeWithNotification(sub_takeover)
}
