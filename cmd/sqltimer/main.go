package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
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

	delaySeconds float64

	customHeaders headerList

	stopAtFirstMatch    bool
	useUserAgentPayload bool

	payloadsFile     string
	proxyURL         string
	replayProxyURL   string
	userAgent        string
	payloads         []string
	preparedPayloads []string
	version          = "v0.4.3"
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

const maxRepeats = 10

type headerList []string

func (h *headerList) String() string {
	return fmt.Sprint(*h)
}

func (h *headerList) Set(value string) error {
	if strings.IndexByte(value, ':') < 0 {
		return fmt.Errorf("%s invalid header format: must be Key:Value%s", colorRed, colorReset)
	}
	*h = append(*h, value)
	return nil
}

type job struct {
	url string
}

type recordedRequest struct {
	Request *http.Request
	Body    string
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
	method := getMethod()

	if noColor {
		fmt.Fprintf(os.Stderr, "🚀 sqltimer %s | sleep=%d | drift=±%.1f/%.1f | maxtime=%.1fs | delay=%.1fs | method=%s\n",
			version, sleepTime, negDrift, posDrift, maxResponseTime, delaySeconds, method)
	} else {
		fmt.Fprintf(os.Stderr, "%s🚀 sqltimer %s%s | sleep=%s%d%s | drift=±%s%.1f/%.1f%s | maxtime=%s%.1fs%s | delay=%s%.1fs%s | method=%s%s%s\n",
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

func colorize(s, color string) string {
	if noColor {
		return s
	}
	return color + s + colorReset
}

func getMethod() string {
	if usePost {
		return "POST"
	}
	return "GET"
}

func (h *headerList) ApplyTo(req *http.Request) {
	for _, hdr := range *h {
		name, value, ok := strings.Cut(hdr, ":")
		if !ok {
			continue
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
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
	customHeaders.ApplyTo(req)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return time.Since(start).Seconds(), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
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

		if doDebug {
			fmt.Printf("%s %sNotify sent:%s %s\n", prefixSet, colorYellow, colorReset, colorize(truncate(msg, 80), colorGray))
		}

		err = cmd.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s Error calling notify: %v\n", prefixWrn, err)
		}
	}
}

func sendRequest(targetURL, param, payload string) (float64, *recordedRequest, error) {
	var req *http.Request
	var err error
	var bodyData string

	if usePost {
		if shouldEncode {
			bodyData = param + "=" + payload
		} else {
			data := url.Values{}
			data.Set(param, payload)
			bodyData = data.Encode()
		}
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(bodyData))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return 0, nil, err
		}
	}

	req.Header.Set("User-Agent", userAgent)
	customHeaders.ApplyTo(req)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	duration := time.Since(start).Seconds()
	return duration, &recordedRequest{Request: req, Body: bodyData}, nil
}

func doReplayFromRequest(r *recordedRequest) {
	if replayProxyURL == "" || replayClient == nil || r == nil || r.Request == nil {
		return
	}

	clone := r.Request.Clone(context.Background())
	if r.Body != "" {
		clone.Body = io.NopCloser(strings.NewReader(r.Body))
	}

	if doDebug {
		fmt.Printf("%s Sending replay via proxy %s%s%s to: %s%s%s\n",
			prefixSet,
			colorYellow, replayProxyURL, colorReset,
			colorBlue, r.Request.URL.String(), colorReset)
	}

	resp, err := replayClient.Do(clone)
	if err != nil {
		if doDebug {
			fmt.Printf("%s Replay failed: %v\n", prefixSet, err)
		}
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if doDebug {
		fmt.Printf("%s Replay request succeeded: %s%s%s\n", prefixSet, colorYellow, r.Request.URL.String(), colorReset)
	}
}

func reportFinding(url, param, payload string, delta float64, repeat int, uaMode bool) {
	method := getMethod()

	var fullMessage string
	contextInfo := fmt.Sprintf(
		"via User-Agent%s with payload %s'%s'%s",
		colorReset, colorMagenta, payload, colorReset,
	)

	if !uaMode {
		contextInfo = fmt.Sprintf(
			"in param %s'%s'%s with payload %s'%s'%s",
			colorCyan, param, colorReset,
			colorMagenta, payload, colorReset,
		)
	}

	fullMessage = fmt.Sprintf(
		"%s🔥 SQLi suspicion %s → %s%s%s → (%sΔ=%.2fs%s ≈ %s%dx sleep%s ±%s%.1fs/%.1fs%s | method=%s%s%s)",
		colorRed, contextInfo,
		colorWhite, url, colorReset,
		colorCyan, delta, colorReset,
		colorMagenta, repeat, colorReset,
		colorCyan, negDrift, posDrift, colorReset,
		colorGreen, method, colorReset,
	)

	if cleanOutput {
		if uaMode {
			fmt.Printf("%s [param:user-agent] [method:%s] [payload:%s]\n", url, method, payload)
		} else {
			fmt.Printf("%s [param:%s] [method:%s] [payload:%s]\n", url, param, method, payload)
		}
	} else {
		fmt.Println(fullMessage)
	}

	if notify {
		notifyUser(fullMessage)
	}
}

func worker(jobs <-chan job, wg *sync.WaitGroup, mu *sync.Mutex, seen map[string]bool, ticker *time.Ticker) {
	defer wg.Done()
	for j := range jobs {
		u, err := url.Parse(j.url)
		if err != nil {
			continue
		}
		base := u.Scheme + "://" + u.Host + u.Path

		var baseTime float64

		params := u.Query()
		if len(params) == 0 && !useUserAgentPayload {
			if doDebug {
				fmt.Printf("%s %sSkipping URL (no params, no add-ua):%s %s%s%s\n",
					prefixWrn, colorGray, colorReset, colorYellow, j.url, colorReset)
			}
			continue
		}

		if delaySeconds > 0 && ticker != nil {
			if doDebug {
				fmt.Printf("%s %s\n", prefixSlp,
					colorize(fmt.Sprintf("Delay %.1fs before base request to %s", delaySeconds, u.Host), colorGray))
			}
			<-ticker.C
		}

		mu.Lock()
		if seen[base] {
			mu.Unlock()
			continue
		}
		mu.Unlock()

		baseTime, err = measureResponse(j.url)
		if err != nil {
			continue
		}

		if doDebug {
			fmt.Printf("%s Base response time measured: %s%.2fs%s for %s%s%s\n",
				prefixIni, colorCyan, baseTime, colorReset, colorYellow, j.url, colorReset)
		}

		found := false

		for param := range params {
			for _, payload := range preparedPayloads {
				injURL, err := buildInjectedURL(j.url, param, payload)
				if err != nil || injURL == "" {
					continue
				}

				if delaySeconds > 0 && ticker != nil {
					if doDebug {
						fmt.Printf("%s %s\n", prefixSlp,
							colorize(fmt.Sprintf("Delay %.1fs before payload injection: param=%s payload=%s", delaySeconds, param, payload), colorGray))
					}
					<-ticker.C
				}

				if doDebug {
					fmt.Printf("%s Sending payload request: param=%s%s%s url=%s%s%s\n",
						prefixPay, colorMagenta, param, colorReset, colorYellow, injURL, colorReset)
				}

				injTime, recorded, err := sendRequest(injURL, param, payload)
				if err != nil {
					continue
				}

				delta := injTime - baseTime
				if doDebug {
					fmt.Printf("%s Payload delta: %sΔ=%.2fs%s param=%s%s%s url=%s%s%s\n",
						prefixTst, colorCyan, delta, colorReset, colorMagenta, param, colorReset, colorYellow, injURL, colorReset)
				}

				if delta > maxResponseTime {
					continue
				}

				for i := 1; i <= maxRepeats; i++ {
					expected := float64(sleepTime) * float64(i)
					if delta >= expected-negDrift && delta <= expected+posDrift {
						doReplayFromRequest(recorded)
						reportFinding(injURL, param, payload, delta, i, false)
						mu.Lock()
						seen[base] = true
						mu.Unlock()
						found = true
						break
					}
				}

				if stopAtFirstMatch && found {
					if doDebug {
						fmt.Printf("%s Stopping after first successful payload (param=%s%s%s) due to %s-spm%s\n",
							prefixSet, colorMagenta, param, colorReset, colorYellow, colorReset)
					}
					break
				}
			}
			if stopAtFirstMatch && found {
				break
			}
		}

		if useUserAgentPayload {
			if stopAtFirstMatch && found {
				if doDebug {
					fmt.Printf("%s Skipping User-Agent payloads due to %s-spm%s (already matched)\n",
						prefixSet, colorYellow, colorReset)
				}
				continue
			}

			for _, payload := range preparedPayloads {
				modUserAgent := strings.TrimSpace(userAgent) + " " + payload

				var req *http.Request
				var bodyData string
				param := "id"
				for p := range u.Query() {
					param = p
					break
				}

				if usePost {
					data := url.Values{}
					data.Set(param, payload)
					bodyData = data.Encode()
					req, err = http.NewRequest("POST", j.url, strings.NewReader(bodyData))
					if err == nil {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
				} else {
					req, err = http.NewRequest("GET", j.url, nil)
				}
				if err != nil {
					continue
				}

				req.Header.Set("User-Agent", modUserAgent)
				customHeaders.ApplyTo(req)

				if doDebug {
					fmt.Printf("%s Testing payload in User-Agent header: %s%s%s\n",
						prefixPay, colorMagenta, payload, colorReset)
				}

				if delaySeconds > 0 && ticker != nil {
					if doDebug {
						fmt.Printf("%s %s\n", prefixSlp,
							colorize(fmt.Sprintf("Delay %.1fs before UA payload injection: payload=%s", delaySeconds, payload), colorGray))
					}
					<-ticker.C
				}

				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()

				delta := time.Since(start).Seconds() - baseTime
				if doDebug {
					fmt.Printf("%s UA-Payload delta: %sΔ=%.2fs%s user-agent='%s'\n",
						prefixTst, colorCyan, delta, colorReset, modUserAgent)
				}

				for i := 1; i <= maxRepeats; i++ {
					expected := float64(sleepTime) * float64(i)
					if delta >= expected-negDrift && delta <= expected+posDrift {
						recorded := &recordedRequest{
							Request: req,
							Body:    bodyData,
						}
						doReplayFromRequest(recorded)
						reportFinding(j.url, "user-agent", payload, delta, i, true)
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
	lineNumber := 0
	ignored := 0
	total := 0

	for scanner.Scan() {
		lineNumber++
		total++
		line := strings.TrimSpace(scanner.Text())

		switch {
		case line == "":
			if doDebug {
				fmt.Fprintf(os.Stderr, "%s %sIgnoring empty line [%d]%s\n", prefixWrn, colorGray, lineNumber, colorReset)
			}
			ignored++
			continue
		case strings.HasPrefix(line, "#"):
			if doDebug {
				fmt.Fprintf(os.Stderr, "%s %sIgnoring comment line [%d]:%s %s\n", prefixWrn, colorGray, lineNumber, colorReset, line)
			}
			ignored++
			continue
		case !strings.Contains(line, "{SLEEP}"):
			if doDebug {
				fmt.Fprintf(os.Stderr, "%s %sIgnoring line without {SLEEP} [%d]:%s %s\n", prefixWrn, colorGray, lineNumber, colorReset, line)
			}
			ignored++
			continue
		default:
			lines = append(lines, line)
		}
	}

	if doDebug {
		fmt.Fprintf(os.Stderr, "%s Loaded %s%d%s payload(s), %s%d%s ignored from %s%d%s total lines\n",
			prefixSet,
			colorGreen, len(lines), colorReset,
			colorRed, ignored, colorReset,
			colorCyan, total, colorReset,
		)
	}

	return lines, scanner.Err()
}

func preparePayloads() []string {
	var prepared []string
	for _, payload := range payloads {
		if !strings.Contains(payload, "{SLEEP}") {
			continue
		}

		original := strings.ReplaceAll(payload, "{SLEEP}", fmt.Sprintf("%d", sleepTime))
		injection := original

		if shouldEncode {
			injection = url.QueryEscape(injection)
		} else if strings.Contains(injection, " ") {
			encoded := url.QueryEscape(injection)
			if doDebug {
				fmt.Fprintf(os.Stderr, "%s %s\n", prefixWrn,
					colorize(fmt.Sprintf("Auto-encoding payload due to space: %s → %s",
						colorize(original, colorMagenta),
						colorize(encoded, colorCyan),
					), colorGray))
			}
			injection = encoded
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
			fmt.Printf("%s %s\n", prefixSet, colorize(fmt.Sprintf("Proxy connectivity verified: %s", proxyURL), colorYellow))
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
		fmt.Printf("%s %s\n", prefixSet, colorize(fmt.Sprintf("Replay proxy verified successfully: %s", replayProxyURL), colorYellow))
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
	flag.BoolVar(&stopAtFirstMatch, "spm", false, "Stop at first matching payload per URL")
	flag.BoolVar(&useUserAgentPayload, "add-ua", false, "Also test payloads via User-Agent header")

	// Request/Proxy Options
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL, e.g. http://127.0.0.1:8080")
	flag.StringVar(&replayProxyURL, "replay-proxy", "", "Replay vulnerable URLs through proxy (only hits)")
	flag.StringVar(&userAgent, "user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0", "User-Agent header to use")
	flag.Var(&customHeaders, "header", "Custom header to add to requests, format: Key:Value")
	flag.BoolVar(&usePost, "post", false, "Send payloads as POST requests instead of GET")
	flag.BoolVar(&shouldEncode, "encode", false, "URL encode SQL payloads")
	flag.Float64Var(&delaySeconds, "delay", 0, "Delay between requests in seconds")

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

	if noColor {
		disableColors()
	}

	if *showVersion {
		fmt.Println("sqltimer version:", version)
		os.Exit(0)
	}

	printBanner()

	if payloadsFile == "" {
		fmt.Fprintln(os.Stderr, "[!] You must specify a -payloads file.")
		os.Exit(1)
	}

	setupHTTPClient()
	setupReplayProxyClient()

	if doDebug {
		fmt.Printf("%s Delay between requests: %s%.1fs%s\n", prefixSet, colorYellow, delaySeconds, colorReset)
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
		ticker = time.NewTicker(time.Duration(delaySeconds * float64(time.Second)))
		defer ticker.Stop()
	}

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go worker(jobs, &wg, &mu, seen, ticker)
	}

	for scanner.Scan() {
		rawURL := strings.TrimSpace(scanner.Text())

		if rawURL == "" {
			continue
		}

		_, err := url.ParseRequestURI(rawURL)
		if err != nil {
			if doDebug {
				fmt.Fprintf(os.Stderr, "%s %s\n", prefixWrn,
					colorize(fmt.Sprintf("Invalid URL skipped: %s", rawURL), colorGray))
			}
			continue
		}

		if doDebug {
			fmt.Printf("%s Received URL: %s%s%s\n", prefixInp, colorYellow, rawURL, colorReset)
		}
		jobs <- job{url: rawURL}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to read stdin: %v\n", err)
		os.Exit(1)
	}
	close(jobs)
	wg.Wait()

	method := getMethod()

	if !cleanOutput {
		fmt.Printf("%s✅ sqltimer finished%s | sleep=%s%d%s | drift=±%s%.1fs/%.1fs%s | maxtime=%s%.1fs%s | delay=%s%.1fs%s | method=%s%s%s\n",
			colorGreen, colorReset,
			colorYellow, sleepTime, colorReset,
			colorCyan, negDrift, posDrift, colorReset,
			colorMagenta, maxResponseTime, colorReset,
			colorBlue, delaySeconds, colorReset,
			colorGreen, method, colorReset)
	}
}
