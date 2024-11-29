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
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	getJs "github.com/003random/getJS/v2/runner"
	//"github.com/PuerkitoBio/goquery"
	gau_output "github.com/lc/gau/v2/pkg/output"
	gau_runner "github.com/lc/gau/v2/runner"
	"github.com/lc/gau/v2/runner/flags"
	//"github.com/likexian/whois"

	"github.com/cyinnove/logify"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	httpx "github.com/projectdiscovery/httpx/runner"
	subfinder "github.com/projectdiscovery/subfinder/v2/pkg/runner"

)
func Logo() error {
	asciiArt := `
                                                 dddddddd                                                               
BBBBBBBBBBBBBBBBB                                d::::::d       GGGGGGGGGGGGGPPPPPPPPPPPPPPPPP   TTTTTTTTTTTTTTTTTTTTTTT
B::::::::::::::::B                               d::::::d    GGG::::::::::::GP::::::::::::::::P  T:::::::::::::::::::::T
B::::::BBBBBB:::::B                              d::::::d  GG:::::::::::::::GP::::::PPPPPP:::::P T:::::::::::::::::::::T
BB:::::B     B:::::B                             d:::::d  G:::::GGGGGGGG::::GPP:::::P     P:::::PT:::::TT:::::::TT:::::T
  B::::B     B:::::B  aaaaaaaaaaaaa      ddddddddd:::::d G:::::G       GGGGGG  P::::P     P:::::PTTTTTT  T:::::T  TTTTTT
  B::::B     B:::::B  a::::::::::::a   dd::::::::::::::dG:::::G                P::::P     P:::::P        T:::::T        
  B::::BBBBBB:::::B   aaaaaaaaa:::::a d::::::::::::::::dG:::::G                P::::PPPPPP:::::P         T:::::T        
  B:::::::::::::BB             a::::ad:::::::ddddd:::::dG:::::G    GGGGGGGGGG  P:::::::::::::PP          T:::::T        
  B::::BBBBBB:::::B     aaaaaaa:::::ad::::::d    d:::::dG:::::G    G::::::::G  P::::PPPPPPPPP            T:::::T        
  B::::B     B:::::B  aa::::::::::::ad:::::d     d:::::dG:::::G    GGGGG::::G  P::::P                    T:::::T        
  B::::B     B:::::B a::::aaaa::::::ad:::::d     d:::::dG:::::G        G::::G  P::::P                    T:::::T        
  B::::B     B:::::Ba::::a    a:::::ad:::::d     d:::::d G:::::G       G::::G  P::::P                    T:::::T        
BB:::::BBBBBB::::::Ba::::a    a:::::ad::::::ddddd::::::dd G:::::GGGGGGGG::::GPP::::::PP                TT:::::::TT      
B:::::::::::::::::B a:::::aaaa::::::a d:::::::::::::::::d  GG:::::::::::::::GP::::::::P                T:::::::::T      
B::::::::::::::::B   a::::::::::aa:::a d:::::::::ddd::::d    GGG::::::GGG:::GP::::::::P                T:::::::::T      
BBBBBBBBBBBBBBBBB     aaaaaaaaaa  aaaa  ddddddddd   ddddd       GGGGGG   GGGGPPPPPPPPPP                TTTTTTTTTTT 
       
												by Youssef Elsheikh`
	fmt.Println(asciiArt)
	return nil 
}

func subenum() error {
	fmt.Println("##################### Subdomain Enumeration Starts : #####################")
	subfinderOpts := &subfinder.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		DomainsFile:        "domains",
		ResolverList:       "all-resolvers",
		OutputFile:         "subfinder_output",
		All:                true,
		Silent:             true,
	}

	log.SetFlags(0)

	subfinder, err := subfinder.NewRunner(subfinderOpts)
	if err != nil {
		return fmt.Errorf("failed to create subfinder runner: %v", err)
	}

	output := &bytes.Buffer{}
	file, err := os.Open(subfinderOpts.DomainsFile)
	if err != nil {
		return fmt.Errorf("failed to open domains file: %v", err)
	}
	defer file.Close()

	if err = subfinder.EnumerateMultipleDomainsWithCtx(context.Background(), file, []io.Writer{output}); err != nil {
		return fmt.Errorf("failed to enumerate subdomains from file: %v", err)
	}

	log.Println(output.String())
	fmt.Println("##################### Subdomain Enumeration Ends : #####################")
	return nil
}

func filtered() error {
	fmt.Println("##################### Filter Starts : #####################")
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

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
		return err
	}

	httpxRunner, err := httpx.New(&options)
	if err != nil {
		return err
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
	fmt.Println("##################### Filter Ends : #####################")
	return nil
}

func spliter() error {
	inputFile := "httpx_file"
	statusCodes := map[string]string{
		"200": "alive_subs",
		"403": "forbidden",
		"30":  "redirect_subs",
		"404": "takeover_subs",
		"50":  "server_errors",
		"":    "all_in_one",
	}

	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	allDomainsFile, err := os.Create("all_in_one")
	if err != nil {
		return fmt.Errorf("failed to create all_in_one file: %v", err)
	}
	defer allDomainsFile.Close()

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
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 {
			_, err := allDomainsFile.WriteString(fields[0] + "\n")
			if err != nil {
				return fmt.Errorf("failed to write to all_in_one file: %v", err)
			}
		}

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
	green := "\033[32m"
	red := "\033[31m"
	reset := "\033[0m"

	file, err := os.Open("takeover_subs")
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("error getting input file info: %v", err)
	}
	if stat.Size() == 0 {
		fmt.Println("The input file 'takeover_subs' is empty.")
		return nil
	}

	output_file, err := os.OpenFile("subdomain_Takeover", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error creating/opening output file: %v", err)
	}
	defer output_file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		if domain == "" {
			fmt.Println("Skipping empty line in the input file.")
			continue
		}

		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.TrimPrefix(domain, "https://")

		cname, err := net.LookupCNAME(domain)
		if err != nil {
			fmt.Printf("%sError looking up CNAME for %s: %s%s\n", red, domain, err.Error(), reset)
			continue
		}

		fmt.Printf("%sThe CNAME for %s is %s%s\n", green, domain, cname, reset)
		_, err = output_file.WriteString(fmt.Sprintf("The CNAME for %s is %s\n", domain, cname))
		if err != nil {
			return fmt.Errorf("error writing to file: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading from input file: %v", err)
	}
	fmt.Println("##################### Subdomain Takeover Ends : #####################")
	return nil
}

func extractUniqueIPs() error {
	filename := "httpx_file"
	ipRegex := `\b([0-9]{1,3}\.){3}[0-9]{1,3}\b`
	re := regexp.MustCompile(ipRegex)

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	ipMap := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		ips := re.FindAllString(line, -1)
		for _, ip := range ips {
			ipMap[ip] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	var uniqueIPs []string
	for ip := range ipMap {
		uniqueIPs = append(uniqueIPs, ip)
	}

	sort.Strings(uniqueIPs)

	outputFile, err := os.Create("IPs.txt")
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	for _, ip := range uniqueIPs {
		_, err := outputFile.WriteString(ip + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file: %v", err)
		}
	}

	for _, ip := range uniqueIPs {
		fmt.Println(ip)
	}

	return nil
}

func notification(success bool, errorMsg string) {
	discordWebhookURL := "https://discord.com/api/webhooks/1303587381340934265/AgNSPYOFOX2qDT5A6aW_ZDoH23ixx6iy_62rDdJpIcjH-hpnxih54FOv4eYi_VuNJWcx"

	var message string
	if success {
		message = "✅ Success: Task completed successfully."
	} else {
		message = fmt.Sprintf("❌ Error: %s", errorMsg)
	}

	payload := map[string]string{"content": message}
	payloadBytes, _ := json.Marshal(payload)

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

	if err := postToWebhook(discordWebhookURL); err != nil {
		fmt.Println("Error sending to Discord:", err)
	}
}

func executeWithNotification(task func() error) {
	if err := task(); err != nil {
		notification(false, err.Error())
	} else {
		notification(true, "")
	}
}

type KatanaOption func(*types.Options)

func WithMaxDepth(depth int) KatanaOption {
	return func(o *types.Options) {
		o.MaxDepth = depth
	}
}

func WithConcurrency(concurrency int) KatanaOption {
	return func(o *types.Options) {
		o.Concurrency = concurrency
	}
}

func WithTimeout(timeout int) KatanaOption {
	return func(o *types.Options) {
		o.Timeout = timeout
	}
}

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

func RunKatana(inputs []string, maxConcurrentCrawls int, opts ...KatanaOption) ([]string, error) {
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

	for _, opt := range opts {
		opt(options)
	}

	var urls []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentCrawls)

	options.OnResult = func(result output.Result) {
		mu.Lock()
		defer mu.Unlock()
		urls = append(urls, result.Request.URL)
		logify.Infof("Found URL: %s", result.Request.URL)
	}

	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return nil, err
	}
	defer crawlerOptions.Close()

	crawlTarget := func(input string) {
		defer wg.Done()
		defer func() { <-sem }()

		crawler, err := standard.New(crawlerOptions)
		if err != nil {
			logify.Errorf("Error creating crawler for %s: %v", input, err)
			return
		}
		defer crawler.Close()

		logify.Infof("Crawling: %s", input)
		err = crawler.Crawl(input)
		if err != nil {
			logify.Warningf("Failed to crawl %s: %v", input, err)
		}
	}

	for _, input := range inputs {
		wg.Add(1)
		sem <- struct{}{}
		go crawlTarget(input)
	}

	wg.Wait()

	return urls, nil
}

func portScan() error {
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

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	err = naabuRunner.RunEnumeration(context.TODO())
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}

	options.ResumeCfg.CleanupResumeConfig()
	fmt.Println("Scan completed successfully.")
	return nil
}

func gau() error {
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

	gau.Wait()

	close(results)

	writeWg.Wait()

	return nil
}
func url_filteration(katanaFile, gauFile string) error {
	urls, err := readURLsFromFile(katanaFile)
	if err != nil {
		return err
	}

	gauURLs, err := readURLsFromFile(gauFile)
	if err != nil {
		return err
	}
	urls = append(urls, gauURLs...)

	uniqueURLs := make(map[string]struct{})
	var injectionURLs, jsURLs []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, rawURL := range urls {
		wg.Add(1)
		go func(rawURL string) {
			defer wg.Done()

			parsedURL, err := url.Parse(rawURL)
			if err != nil {
				return
			}

			parsedURL.Host = strings.ToLower(parsedURL.Host)
			parsedURL.Fragment = ""
			cleanURL := parsedURL.String()

			mu.Lock()
			defer mu.Unlock()

			if _, exists := uniqueURLs[cleanURL]; !exists {
				uniqueURLs[cleanURL] = struct{}{}

				if len(parsedURL.Query()) > 0 {
					injectionURLs = append(injectionURLs, cleanURL)
				}

				if strings.HasSuffix(parsedURL.Path, ".js") {
					jsURLs = append(jsURLs, cleanURL)
				}
			}
		}(rawURL)
	}

	wg.Wait()

	if err := writeURLsToFile("injection_test", injectionURLs); err != nil {
		return err
	}

	if err := writeURLsToFile("js", jsURLs); err != nil {
		return err
	}

	return nil
}


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

func readJSUrls(filename string) ([]string, error) {
	var urls []string

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %v", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := scanner.Text()
		if url != "" {
			urls = append(urls, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filename, err)
	}

	return urls, nil
}

func processJavaScriptSources(inputFile, outputFile string) error {
	// Configure runner.Options
	options := &getJs.Options{
		Complete: false,
		Resolve:  false,
		Threads:  50,
		Verbose:  true,
	}

	// Read input domains from the file `all-in-one`
	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file %s: %w", inputFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}
		// Add each domain as an input for the runner
		options.Inputs = append(options.Inputs, getJs.Input{
			Type: getJs.InputURL,
			Data: strings.NewReader(domain),
		})
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	// Open output file `Js` for writing results
	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file %s: %w", outputFile, err)
	}
	defer output.Close()

	// Set the output writer
	options.Outputs = []io.Writer{output}

	// Run the JavaScript extraction
	if err := getJs.New(options).Run(); err != nil {
		return fmt.Errorf("error running the JavaScript extraction: %w", err)
	}

	fmt.Printf("JavaScript extraction completed. Results written to %s\n", outputFile)
	return nil
}

// MergeAndDeduplicateJS merges two files and removes duplicates, saving the result to a new file.
func MergeAndDeduplicateJS(file1Path, file2Path, outputPath string) error {
	// Create a map to store unique lines
	uniqueLines := make(map[string]struct{})

	// Function to process a file and add lines to the map
	processFile := func(filePath string) error {
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", filePath, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				uniqueLines[line] = struct{}{}
			}
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading file %s: %w", filePath, err)
		}

		return nil
	}

	// Process both files
	if err := processFile(file1Path); err != nil {
		return err
	}
	if err := processFile(file2Path); err != nil {
		return err
	}

	// Create the output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	defer outputFile.Close()

	// Write unique lines to the output file
	writer := bufio.NewWriter(outputFile)
	for line := range uniqueLines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("failed to write to output file: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush data to output file: %w", err)
	}

	return nil
}


func Js_Extractor() error {

	// Input file containing URLs
	inputFile := "JavaScript_files"

	// Output file for results
	outputFile := "Js_results"

	// Compile regular expressions
	rePath := regexp.MustCompile(`\/[a-zA-Z0-9_\-/]+`)       // Matches all paths
	reParams := regexp.MustCompile(`[?&]([a-zA-Z0-9_\-]+)=`) // Matches query parameters

	// HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second, // Set timeout for requests
	}

	// Open input file
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Failed to open input file: %v\n", err)

	}
	defer file.Close()

	// Channel for tasks and results
	tasks := make(chan string, 10)
	results := make(chan map[string][]string, 10)

	var wg sync.WaitGroup

	// Start workers
	workerCount := 5
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range tasks {
				result := make(map[string][]string)
				result["Url"] = []string{url}

				// Fetch JavaScript file content with timeout
				resp, err := client.Get(url)
				if err != nil {
					result["Error"] = []string{fmt.Sprintf("failed to fetch URL: %s, Error: %v", url, err)}
					results <- result
					continue
				}
				defer resp.Body.Close()

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					result["Error"] = []string{fmt.Sprintf("failed to read body for URL: %s, Error: %v", url, err)}
					results <- result
					continue
				}

				// Extract all paths
				result["Paths"] = rePath.FindAllString(string(body), -1)

				// Extract all parameters
				rawParams := reParams.FindAllStringSubmatch(string(body), -1)
				uniqueParams := make(map[string]bool)
				for _, match := range rawParams {
					if len(match) > 1 {
						uniqueParams[match[1]] = true
					}
				}
				for param := range uniqueParams {
					result["Parameters"] = append(result["Parameters"], param)
				}

				results <- result
			}
		}()
	}

	// Read URLs from input file and send tasks
	go func() {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" {
				tasks <- url
			}
		}
		close(tasks)
	}()

	// Close results channel after workers complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Write results to output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Failed to create output file: %v\n", err)

	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	for result := range results {
		if errorMsg, ok := result["Error"]; ok {
			fmt.Fprintf(writer, "Error: %s\n", errorMsg[0])
			continue
		}

		// Write results
		fmt.Fprintf(writer, "URL: %s\n", result["Url"][0])

		// Write all paths
		fmt.Fprintln(writer, "Found Paths:")
		for _, path := range result["Paths"] {
			fmt.Fprintf(writer, "- %s\n", path)
		}

		// Write all parameters
		fmt.Fprintln(writer, "Parameters:")
		for _, param := range result["Parameters"] {
			fmt.Fprintf(writer, "- %s\n", param)
		}
		fmt.Fprintln(writer, "--------------------------------")
	}

	fmt.Println("Processing complete. Results saved to", outputFile)
	return nil

}

var tools = []string{
	"katana", "subfinder", "httpx", "naabu", "gau",
}

func checkAndInstallTools() {
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			fmt.Printf("%s not found, attempting installation...\n", tool)
			installCmd := exec.Command("go", "install", fmt.Sprintf("github.com/projectdiscovery/%s@latest", tool))
			if err := installCmd.Run(); err != nil {
				fmt.Printf("error installing %s: %v\n", tool, err)
			} else {
				fmt.Printf("%s installed successfully.\n", tool)
			}
		} else {
			fmt.Printf("%s is already installed.\n", tool)
		}
	}
}

func updateTools() {
	for _, tool := range tools {
		fmt.Printf("Updating %s...\n", tool)
		updateCmd := exec.Command("go", "install", fmt.Sprintf("github.com/projectdiscovery/%s@latest", tool))
		if err := updateCmd.Run(); err != nil {
			fmt.Printf("error updating %s: %v\n", tool, err)
		} else {
			fmt.Printf("%s updated successfully.\n", tool)
		}
	}
}


func main() {
	executeWithNotification(Logo)
	executeWithNotification(subenum)
	executeWithNotification(filtered)
	executeWithNotification(spliter)
	executeWithNotification(extractUniqueIPs)
	executeWithNotification(sub_takeover)
	executeWithNotification(portScan)
	executeWithNotification(gau)

	// // Read domains from file
	domains, err := ReadDomains("all_in_one")
	if err != nil {
		logify.Fatalf("Error reading domains: %v", err)
	}

	// Run Katana with specified options
	urls, err := RunKatana(domains, 10,
		WithMaxDepth(30),
		WithConcurrency(20),
		WithTimeout(15),
	)
	if err != nil {
		logify.Fatalf("Error: %v", err)
	}

	// Write URLs to file
	outputFile := "urls_katana"
	err = WriteURLsToFile(outputFile, urls)
	if err != nil {
		logify.Fatalf("Error writing URLs to file: %v", err)
	}

	logify.Infof("Crawled %d URLs. Results saved to %s.", len(urls), outputFile)
	// Process JavaScript sources from "all-in-one" and write to "Js"
	if err := processJavaScriptSources("all_in_one", "Js"); err != nil {
		log.Fatalf("Error processing JavaScript sources: %v", err)
	}
	// Filter URLs
	err = url_filteration("urls_katana", "gau_output")
	if err != nil {
		fmt.Printf("Error processing URLs: %v\n", err)
	} else {
		fmt.Println("URLs processed successfully.")
	}
	MergeAndDeduplicateJS("js","Js","JavaScript_files")
	// Process JavaScript sources from "all-in-one" and write to "Js"
	executeWithNotification(Js_Extractor)

	// Check and install tools
	// checkAndInstallTools()

	// // Update tools
	// updateTools()
}