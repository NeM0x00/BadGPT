package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"net/url"


	gau_output "github.com/lc/gau/v2/pkg/output"
	gau_runner "github.com/lc/gau/v2/runner"
	"github.com/lc/gau/v2/runner/flags"


	"github.com/cyinnove/logify"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"

	//"github.com/containrrr/shoutrrr/shoutrrr/cmd/verify"
	//	"github.com/cyinnove/logify"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"

	//"github.com/projectdiscovery/naabu/v2/pkg/runner"

	//"github.com/projectdiscovery/gologger"
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

func sub_takeover() error {
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
		discordWebhookURL = "https://discord.com/api/webhooks/1303587381340934265/AgNSPYOFOX2qDT5A6aW_ZDoH23ixx6iy_62rDdJpIcjH-hpnxih54FOv4eYi_VuNJWcx"
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

type KatanaOption func(*types.Options)

// WithMaxDepth sets the maximum depth for crawling
func WithMaxDepth(depth int) KatanaOption {
	return func(o *types.Options) {
		o.MaxDepth = depth
	}
}

// WithConcurrency sets the number of concurrent crawling goroutines
func WithConcurrency(concurrency int) KatanaOption {
	return func(o *types.Options) {
		o.Concurrency = concurrency
	}
}

// WithTimeout sets the request timeout
func WithTimeout(timeout int) KatanaOption {
	return func(o *types.Options) {
		o.Timeout = timeout
	}
}

// ReadDomains reads domains from a file and returns them as a slice of strings
func ReadDomains(filename string) ([]string, error) {
	var domains []string
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

// WriteURLsToFile writes the found URLs to a specified output file
func WriteURLsToFile(filename string, urls []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, url := range urls {
		_, err := writer.WriteString(fmt.Sprintf("%s\n", url))
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

// RunKatana runs the Katana crawler concurrently on multiple targets
func RunKatana(inputs []string, maxConcurrentCrawls int, opts ...KatanaOption) ([]string, error) {
	// Default options
	options := &types.Options{
		MaxDepth:     30,
		FieldScope:   "rdn",
		BodyReadSize: math.MaxInt,
		Timeout:      10,
		Concurrency:  20,
		Parallelism:  10,
		Delay:        0,
		RateLimit:    150,
		Strategy:     "depth-first",
		NoColors:     true,
	}

	// Apply optional configurations
	for _, opt := range opts {
		opt(options)
	}

	// Prepare output collection and concurrency control
	var urls []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentCrawls) // Semaphore to limit concurrent crawls

	// Callback to gather URLs
	options.OnResult = func(result output.Result) {
		mu.Lock()
		defer mu.Unlock()
		urls = append(urls, result.Request.URL)
		logify.Infof("Found URL: %s", result.Request.URL) // Log each found URL
	}

	// Initialize crawler options (once)
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return nil, err
	}
	defer crawlerOptions.Close()

	// Function to handle the crawling of a single target
	crawlTarget := func(input string) {
		defer wg.Done()
		defer func() { <-sem }() // Release a semaphore slot when done

		// Create and run the crawler
		crawler, err := standard.New(crawlerOptions)
		if err != nil {
			logify.Errorf("Error creating crawler for %s: %v", input, err)
			return
		}
		defer crawler.Close()

		logify.Infof("Crawling: %s", input) // Log the target being crawled
		err = crawler.Crawl(input)
		if err != nil {
			logify.Warningf("Failed to crawl %s: %v", input, err)
		}
	}

	// Start crawling for each input concurrently
	for _, input := range inputs {
		wg.Add(1)
		sem <- struct{}{} // Acquire a semaphore slot
		go crawlTarget(input)
	}

	// Wait for all crawls to finish
	wg.Wait()

	return urls, nil // Return all found URLs
}
func portScan() error {

	// Initialize options directly
	options := &runner.Options{
		Ports:             "22, 23, 25, 53, 80, 110, 135, 137, 139, 143, 443, 445, 465, 993, 995, 3306, 3389, 5900, 8080, 8443, 27017",
		HostsFile:         "IPs.txt",
		Output:            "Open_Ports",
		Nmap:              true,
		Ping:              true,
		Verify:            true,
		EnableProgressBar: true,
		OutputCDN:         true,
		ServiceDiscovery:  true,
		Threads:           150,
		Version:           true,
		ServiceVersion:    true,
	}

	// Initialize the runner with options
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	// Run the enumeration
	err = naabuRunner.RunEnumeration(context.TODO())
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}

	// Cleanup resume file if the run was successful
	options.ResumeCfg.CleanupResumeConfig()
	fmt.Println("Scan completed successfully.")
	return nil
}


func gau()error {
	cfg, err := flags.New().ReadInConfig()
	if err != nil {
		log.Printf("error reading config: %v", err)
	}

	config, err := cfg.ProviderConfig()
	if err != nil {
		log.Fatal(err)
	}

	gau := new(gau_runner.Runner)

	if err = gau.Init(config, cfg.Providers, cfg.Filters); err != nil {
		log.Printf("error initializing runner: %v", err)
	}

	results := make(chan string)

	// Set the output file to "gau_output"
	out, err := os.OpenFile("gau_output", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("Could not open output file: %v\n", err)
	}
	defer out.Close()

	var writeWg sync.WaitGroup
	writeWg.Add(1)
	go func(out io.Writer, JSON bool) {
		defer writeWg.Done()
		if JSON {
			gau_output.WriteURLsJSON(out, results, config.Blacklist, config.RemoveParameters)
		} else if err = gau_output.WriteURLs(out, results, config.Blacklist, config.RemoveParameters); err != nil {
			log.Fatalf("error writing results: %v\n", err)
		}
	}(out, config.JSON)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workChan := make(chan gau_runner.Work)
	gau.Start(ctx, workChan, results)

	// Open the input file "all_in_one" for reading
	inputFile, err := os.Open("domains")
	if err != nil {
		log.Fatalf("Could not open input file: %v\n", err)
	}
	defer inputFile.Close()

	sc := bufio.NewScanner(inputFile)
	for sc.Scan() {
		domain := sc.Text()
		for _, provider := range gau.Providers {
			workChan <- gau_runner.NewWork(domain, provider)
		}
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}
	close(workChan)

	// Wait for providers to fetch URLs
	gau.Wait()

	// Close results channel
	close(results)

	// Wait for writer to finish output
	writeWg.Wait()

	return nil ;
}
func url_filteration(katanaFile, gauFile string)error {
// ProcessURLs takes the two input files, processes URLs, and performs the following tasks:
// 1. Merges the URLs from both files into one list.
// 2. Filters out duplicate URLs.
// 3. Extracts URLs with parameters and writes them to "injection_test".
// 4. Extracts JavaScript URLs and writes them to "js".

	// Reading URLs from the files
	urls, err := readURLsFromFile(katanaFile)
	if err != nil {
		return err
	}
	
	// Read URLs from the gau_output file and append
	gauURLs, err := readURLsFromFile(gauFile)
	if err != nil {
		return err
	}
	urls = append(urls, gauURLs...)

	// Filter duplicates and categorize URLs
	uniqueURLs := make(map[string]struct{})
	var injectionURLs, jsURLs []string
	var wg sync.WaitGroup

	// Use goroutines for concurrent processing
	for _, rawURL := range urls {
		wg.Add(1)
		go func(rawURL string) {
			defer wg.Done()
			// Validate and parse the URL
			parsedURL, err := url.Parse(rawURL)
			if err != nil {
				return
			}

			// Normalize the URL (lowercase host and remove fragments)
			parsedURL.Host = strings.ToLower(parsedURL.Host)
			parsedURL.Fragment = ""

			// Remove query parameters for deduplication
			cleanURL := parsedURL.String()
			if _, exists := uniqueURLs[cleanURL]; !exists {
				uniqueURLs[cleanURL] = struct{}{}
				
				// Check if the URL has query parameters
				if len(parsedURL.Query()) > 0 {
					injectionURLs = append(injectionURLs, cleanURL)
				}
				
				// Check if the URL points to a JS file
				if strings.HasSuffix(parsedURL.Path, ".js") {
					jsURLs = append(jsURLs, cleanURL)
				}
			}
		}(rawURL)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Write the results to the respective files
	if err := writeURLsToFile("injection_test", injectionURLs); err != nil {
		return err
	}

	if err := writeURLsToFile("js", jsURLs); err != nil {
		return err
	}

	return nil
}

// readURLsFromFile reads URLs from the given file and returns them as a slice.
func readURLsFromFile(fileName string) ([]string, error) {
	var urls []string
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %v", fileName, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", fileName, err)
	}

	return urls, nil
}

// writeURLsToFile writes the given URLs to the specified output file.
func writeURLsToFile(fileName string, urls []string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("could not create file %s: %v", fileName, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, url := range urls {
		_, err := writer.WriteString(url + "\n")
		if err != nil {
			return fmt.Errorf("error writing to file %s: %v", fileName, err)
		}
	}

	return writer.Flush()
}




func main() {

	// 	// subenum()
	// 	// filtered()
	// 	// spliter()
	// 	// extractUniqueIPs()
	// 	// sub_takeover()
	executeWithNotification(subenum)
	executeWithNotification(filtered)
	executeWithNotification(spliter)
	executeWithNotification(extractUniqueIPs)
	executeWithNotification(sub_takeover)
	executeWithNotification(portScan)
	executeWithNotification(gau)
	
	

	// Call the ProcessURLs function with the appropriate input files
	
// Read domains from the alive_domains file
	inputFile := "all_in_one"
	domains, err := ReadDomains(inputFile)
	if err != nil {
		logify.Fatalf("Error reading domains: %v", err)
	}
	// Log the number of domains read
	logify.Infof("Read %d domains from %s.", len(domains), inputFile)

	// Run the Katana crawler with a maximum of 2 concurrent crawls
	urls, err := RunKatana(domains, 2,
		WithMaxDepth(3),
		WithConcurrency(20),
		WithTimeout(15),
	)
	if err != nil {
		logify.Fatalf("Error: %v", err)
	}

	// Write the found URLs to the urls_katana file
	outputFile := "urls_katana"
	err = WriteURLsToFile(outputFile, urls)
	if err != nil {
		logify.Fatalf("Error writing URLs to file: %v", err)
	}

	logify.Infof("Crawled %d URLs. Results saved to %s.", len(urls), outputFile)

	err = url_filteration("urls_katana", "gau_output")
	if err != nil {
		fmt.Printf("Error processing URLs: %v\n", err)
	} else {
		fmt.Println("URLs processed successfully.")
	}
}
