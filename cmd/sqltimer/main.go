package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	sleepTime         = 10
	negDrift          = 0.1
	posDrift          = 0.5
	timeoutMultiplier = 6
	timeoutBuffer     = 10
	maxWorkers        = 10
	notify            = false
	doDebug           = false
	noColor           = false
	cleanOutput       = false
	shouldEncode      = false
	usePost           = false
	delaySeconds      = 0

	customHeaders headerList

	payloadsFile     string
	proxyURL         string
	replayProxyURL   string
	userAgent        string
	payloads         []string
	preparedPayloads []string
	version          = "v0.2.9"
	maxResponseTime  = 30.0

	client       *http.Client
	replayClient *http.Client

	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorGray    = "\033[90m"

	prefixSet = colorBlue + "[SET]" + colorReset
	prefixInp = colorWhite + "[INP]" + colorReset
	prefixIni = colorYellow + "[INI]" + colorReset
	prefixTst = colorMagenta + "[TST]" + colorReset
	prefixPay = colorCyan + "[PAY]" + colorReset
	prefixWrn = colorRed + "[WRN]" + colorReset
	prefixSlp = colorGray + "[SLP]" + colorReset
)

type headerList []string

func (h *headerList) String() string {
	return fmt.Sprint(*h)
}

func (h *headerList) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%s invalid header format: must be Key:Value%s", colorRed, colorReset)
	}
	*h = append(*h, value)
	return nil
}

type job struct {
	url string
}

func printLegend() {
	fmt.Println()
	fmt.Println("Legend (Prefixes):")
	fmt.Printf("  %s [SET]%s   = Setting / Configuration Info\n", colorBlue, colorReset)
	fmt.Printf("  %s [INP]%s   = Input URL received\n", colorWhite, colorReset)
	fmt.Printf("  %s [INI]%s   = Initialization / Base request timing\n", colorYellow, colorReset)
	fmt.Printf("  %s [TST]%s   = Test result (delta timing)\n", colorMagenta, colorReset)
	fmt.Printf("  %s [PAY]%s   = Sending a payload\n", colorCyan, colorReset)
	fmt.Printf("  %s [SLP]%s   = Sleeping (delay between requests)\n", colorGray, colorReset)
	fmt.Printf("  %s [WRN]%s   = Warning (errors, issues)\n", colorRed, colorReset)
	fmt.Println()
}

func printBanner() {
	method := "GET"
	if usePost {
		method = "POST"
	}

	if noColor {
		fmt.Fprintf(os.Stderr, "🚀 sqltimer %s | sleep=%d | drift=±%.1f/%.1f | maxtime=%.1fs | delay=%ds | method=%s\n",
			version, sleepTime, negDrift, posDrift, maxResponseTime, delaySeconds, method)
	} else {
		fmt.Fprintf(os.Stderr, "%s🚀 sqltimer %s%s | sleep=%s%d%s | drift=±%s%.1f/%.1f%s | maxtime=%s%.1fs%s | delay=%s%ds%s | method=%s%s%s\n",
			colorCyan, version, colorReset,
			colorYellow, sleepTime, colorReset,
			colorCyan, negDrift, posDrift, colorReset,
			colorMagenta, maxResponseTime, colorReset,
			colorBlue, delaySeconds, colorReset,
			colorGreen, method, colorReset)
	}
}

func disableColors() {
	colorReset = ""
	colorRed = ""
	colorGreen = ""
	colorYellow = ""
	colorBlue = ""
	colorMagenta = ""
	colorCyan = ""
	colorWhite = ""

	prefixSet = "[SET]"
	prefixInp = "[INP]"
	prefixIni = "[INI]"
	prefixTst = "[TST]"
	prefixWrn = "[WRN]"
	prefixPay = "[PAY]"
	prefixSlp = "[SLP]"
}

func buildInjectedURL(rawURL, param, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	params := u.Query()
	if _, ok := params[param]; !ok {
		return "", nil
	}
	params.Set(param, payload)
	var rawQuery []string
	for k, v := range params {
		rawQuery = append(rawQuery, fmt.Sprintf("%s=%s", k, v[0]))
	}
	u.RawQuery = strings.Join(rawQuery, "&")
	return u.String(), nil
}

func measureResponse(u string) (float64, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	for _, hdr := range customHeaders {
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return time.Since(start).Seconds(), nil
}

func notifyUser(msg string) {
	if notify {
		_, err := exec.LookPath("notify")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s 'notify' binary not found\n", prefixWrn)
			return
		}
		cmd := exec.Command("notify")
		cmd.Stdin = strings.NewReader(msg)
		err = cmd.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error calling notify: %v\n", prefixWrn, err)
		}
	}
}

func sendRequest(targetURL, param, payload string) (float64, error) {
	var req *http.Request
	var err error

	if usePost {
		var bodyData string
		if shouldEncode {
			bodyData = param + "=" + payload
		} else {
			data := url.Values{}
			data.Set(param, payload)
			bodyData = data.Encode()
		}
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(bodyData))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return 0, err
		}
	}

	req.Header.Set("User-Agent", userAgent)
	for _, hdr := range customHeaders {
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return time.Since(start).Seconds(), nil
}

func worker(jobs <-chan job, wg *sync.WaitGroup, mu *sync.Mutex, seen map[string]bool, ticker *time.Ticker) {
	defer wg.Done()
	for j := range jobs {
		u, err := url.Parse(j.url)
		if err != nil {
			continue
		}
		base := u.Scheme + "://" + u.Host + u.Path

		if delaySeconds > 0 && ticker != nil {
			if doDebug {
				fmt.Printf("%s %sDelay %ds before base request to %s%s\n",
					prefixSlp, colorGray, delaySeconds, u.Host, colorReset)
			}
			<-ticker.C
		}

		mu.Lock()
		if seen[base] {
			mu.Unlock()
			continue
		}
		mu.Unlock()

		baseTime, err := measureResponse(j.url)
		if err != nil {
			continue
		}

		if doDebug {
			fmt.Printf("%s Base response time measured: %s%.2fs%s for %s%s%s\n",
				prefixIni,
				colorCyan, baseTime, colorReset,
				colorYellow, j.url, colorReset)
		}

		params := u.Query()
		for param := range params {
			for _, payload := range preparedPayloads {
				injURL, err := buildInjectedURL(j.url, param, payload)
				if err != nil || injURL == "" {
					continue
				}

				if delaySeconds > 0 && ticker != nil {
					if doDebug {
						fmt.Printf("%s %sDelay %ds before payload injection: param=%s payload=%s%s\n",
							prefixSlp, colorGray, delaySeconds, param, payload, colorReset)
					}
					<-ticker.C
				}

				if doDebug {
					fmt.Printf("%s Sending payload request: param=%s%s%s url=%s%s%s\n",
						prefixPay, colorMagenta, param, colorReset, colorYellow, injURL, colorReset)
				}

				injTime, err := sendRequest(injURL, param, payload)
				if err != nil {
					continue
				}

				delta := injTime - baseTime

				if doDebug {
					fmt.Printf("%s Payload delta: %sΔ=%.2fs%s param=%s%s%s url=%s%s%s\n",
						prefixTst,
						colorCyan, delta, colorReset,
						colorMagenta, param, colorReset,
						colorYellow, injURL, colorReset)
				}

				if delta > maxResponseTime {
					continue
				}

				maxRepeats := 10
				for i := 1; i <= maxRepeats; i++ {
					expected := float64(sleepTime) * float64(i)
					if delta >= expected-negDrift && delta <= expected+posDrift {
						vulnerableParam := param
						vulnerablePayload := payload
						vulnerableURL := injURL

						fullMessage := fmt.Sprintf(
							"%s🔥 SQLi suspicion%s in param %s'%s'%s with payload %s'%s'%s → %s%s%s → (%sΔ=%.2fs%s ≈ %s%dx sleep%s ±%s%.1fs/%.1fs%s)",
							colorRed, colorReset,
							colorCyan, vulnerableParam, colorReset,
							colorMagenta, vulnerablePayload, colorReset,
							colorWhite, vulnerableURL, colorReset,
							colorCyan, delta, colorReset,
							colorMagenta, i, colorReset,
							colorCyan, negDrift, posDrift, colorReset,
						)

						if cleanOutput {
							fmt.Printf("%s [param:%s]\n", vulnerableURL, vulnerableParam)
						} else {
							fmt.Println(fullMessage)
						}

						if notify {
							notifyUser(fullMessage)
						}

						if replayProxyURL != "" && replayClient != nil {
							var replayReq *http.Request
							if usePost {
								data := url.Values{}
								data.Set(vulnerableParam, vulnerablePayload)
								replayReq, err = http.NewRequest("POST", vulnerableURL, strings.NewReader(data.Encode()))
								if err == nil {
									replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
								}
							} else {
								replayReq, err = http.NewRequest("GET", vulnerableURL, nil)
							}
							if err != nil {
								if doDebug {
									fmt.Printf("%s Failed to create replay request: %v\n", prefixSet, err)
								}
							} else {
								replayReq.Header.Set("User-Agent", userAgent)
								for _, hdr := range customHeaders {
									parts := strings.SplitN(hdr, ":", 2)
									if len(parts) == 2 {
										replayReq.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
									}
								}

								if doDebug {
									fmt.Printf("%s Sending replay request: %s%s%s\n", prefixSet, colorBlue, vulnerableURL, colorReset)
								}
								resp, err := replayClient.Do(replayReq)
								if err != nil {
									if doDebug {
										fmt.Printf("%s Replay request failed: %v\n", prefixSet, err)
									}
								} else {
									resp.Body.Close()
									if doDebug {
										fmt.Printf("%s Replay request succeeded: %s%s%s\n", prefixSet, colorYellow, vulnerableURL, colorReset)
									}
								}
							}
						}

						mu.Lock()
						seen[base] = true
						mu.Unlock()
						break
					}
				}
			}
		}
	}
}

func loadPayloads(file string) ([]string, error) {
	var lines []string
	f, err := os.Open(file)
	if err != nil {
		return lines, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func preparePayloads() []string {
	var prepared []string
	for _, payload := range payloads {
		injection := strings.ReplaceAll(payload, "{SLEEP}", fmt.Sprintf("%d", sleepTime))
		if shouldEncode {
			injection = url.QueryEscape(injection)
		}
		prepared = append(prepared, injection)
	}
	return prepared
}

func setupHTTPClient() {
	timeout := time.Duration((sleepTime*timeoutMultiplier)+timeoutBuffer) * time.Second

	transport := &http.Transport{}
	if proxyURL != "" {
		parsedProxy, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Invalid proxy URL: %v\n", prefixSet, err)
			os.Exit(1)
		}
		host := parsedProxy.Host
		conn, err := net.DialTimeout("tcp", host, 5*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Proxy unreachable or invalid: %v\n", prefixSet, err)
			os.Exit(1)
		}
		conn.Close()

		transport.Proxy = http.ProxyURL(parsedProxy)

		if doDebug {
			fmt.Printf("%s Proxy connectivity verified: %s%s%s\n", prefixSet, colorYellow, proxyURL, colorReset)
		}
	}

	client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	if doDebug {
		fmt.Printf("%s HTTP client initialized: sleep=%s%d%s * multiplier=%s%d%s + buffer=%s%d%s → timeout=%s%s%s\n",
			prefixSet,
			colorYellow, sleepTime, colorReset,
			colorMagenta, timeoutMultiplier, colorReset,
			colorCyan, timeoutBuffer, colorReset,
			colorGreen, timeout, colorReset)
	}
}

func setupReplayProxyClient() {
	if replayProxyURL == "" || proxyURL != "" {
		return
	}

	parsedProxy, err := url.Parse(replayProxyURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Invalid replay proxy URL: %v\n", prefixSet, err)
		os.Exit(1)
	}
	host := parsedProxy.Host
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Replay proxy unreachable or invalid: %v\n", prefixSet, err)
		os.Exit(1)
	}
	conn.Close()

	transport := &http.Transport{Proxy: http.ProxyURL(parsedProxy)}
	replayClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	if doDebug {
		fmt.Printf("%s Replay proxy verified successfully: %s%s%s\n", prefixSet, colorYellow, replayProxyURL, colorReset)
	}
}

func main() {
	// General Options
	showVersion := flag.Bool("version", false, "Show version")
	flag.StringVar(&payloadsFile, "payloads", "", "File with SQLi payloads (one per line, with {SLEEP} placeholder)")

	// Scan/Timing Options
	flag.IntVar(&sleepTime, "sleep", 10, "SQLi sleep delay in seconds")
	flag.Float64Var(&negDrift, "negdrift", 0.1, "Allowable negative drift around sleep time")
	flag.Float64Var(&posDrift, "posdrift", 0.5, "Allowable positive drift around sleep time")
	flag.Float64Var(&maxResponseTime, "maxtime", 30.0, "Maximum allowed delta response time before skipping (seconds)")
	flag.IntVar(&timeoutMultiplier, "timeoutmultiplier", 6, "Multiplier for calculating HTTP timeout")
	flag.IntVar(&timeoutBuffer, "timeoutbuffer", 10, "Buffer (seconds) added to HTTP timeout")
	flag.IntVar(&maxWorkers, "threads", 10, "Maximum number of concurrent workers")

	// Request/Proxy Options
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL, e.g. http://127.0.0.1:8080")
	flag.StringVar(&replayProxyURL, "replay-proxy", "", "Replay vulnerable URLs through proxy (only hits)")
	flag.StringVar(&userAgent, "user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0", "User-Agent header to use")
	flag.Var(&customHeaders, "header", "Custom header to add to requests, format: Key:Value")
	flag.BoolVar(&usePost, "post", false, "Send payloads as POST requests instead of GET")
	flag.BoolVar(&shouldEncode, "encode", false, "URL encode SQL payloads")
	flag.IntVar(&delaySeconds, "delay", 0, "Delay between requests in seconds")

	// Output/Debugging Options
	flag.BoolVar(&notify, "notify", false, "Send desktop notification on finding")
	flag.BoolVar(&doDebug, "debug", false, "Enable debug output")
	flag.BoolVar(&noColor, "nocolor", false, "Disable colored output")
	flag.BoolVar(&cleanOutput, "clean", false, "Output only vulnerable URLs (stdout only)")

	// Flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		printLegend()
	}

	flag.Parse()

	printBanner()

	if noColor {
		disableColors()
	}

	if *showVersion {
		fmt.Println("sqltimer version:", version)
		os.Exit(0)
	}

	if payloadsFile == "" {
		fmt.Fprintln(os.Stderr, "[!] You must specify a -payloads file.")
		os.Exit(1)
	}

	setupHTTPClient()
	setupReplayProxyClient()

	if doDebug {
		fmt.Printf("%s Delay between requests: %s%d seconds%s\n", prefixSet, colorYellow, delaySeconds, colorReset)
		if len(customHeaders) > 0 {
			fmt.Printf("%s Custom headers set:%s\n", prefixSet, colorReset)
			for _, hdr := range customHeaders {
				fmt.Printf("  %s%s%s\n", colorMagenta, hdr, colorReset)
			}
		}
	}

	var err error
	payloads, err = loadPayloads(payloadsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to read payloads file: %v\n", err)
		os.Exit(1)
	}

	preparedPayloads = preparePayloads()

	scanner := bufio.NewScanner(os.Stdin)
	jobs := make(chan job, 100)
	seen := make(map[string]bool)
	var wg sync.WaitGroup
	var mu sync.Mutex

	var ticker *time.Ticker
	if delaySeconds > 0 {
		ticker = time.NewTicker(time.Duration(delaySeconds) * time.Second)
		defer ticker.Stop()
	}

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go worker(jobs, &wg, &mu, seen, ticker)
	}

	for scanner.Scan() {
		rawURL := scanner.Text()
		if doDebug {
			fmt.Printf("%s Received URL: %s%s%s\n", prefixInp, colorYellow, rawURL, colorReset)
		}
		jobs <- job{url: rawURL}
	}
	close(jobs)
	wg.Wait()

	method := "GET"
	if usePost {
		method = "POST"
	}

	if !cleanOutput {
		fmt.Printf("%s✅ sqltimer finished%s | sleep=%s%d%s | drift=±%s%.1fs/%.1fs%s | maxtime=%s%.1fs%s | delay=%s%ds%s | method=%s%s%s\n",
			colorGreen, colorReset,
			colorYellow, sleepTime, colorReset,
			colorCyan, negDrift, posDrift, colorReset,
			colorMagenta, maxResponseTime, colorReset,
			colorBlue, delaySeconds, colorReset,
			colorGreen, method, colorReset)
	}
}
