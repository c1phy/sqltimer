
# sqltimer 🕵️‍♂️

A fast, minimalistic scanner for **time-based SQL injection (SQLi)** detection – built in Go.

---

![Proof of Concept](./assets/poc.gif)

---

## ✨ Features

- ⚡ Detects SQLi via **timing differences** (`sleep(n)`) with drift-based precision
- 🎯 Supports **dynamic `{SLEEP}` placeholder** injection into payloads
- 🌐 Optional **URL encoding** of injected payloads (`-encode`)
- 🧵 **Multi-threaded** scanning with configurable workers (`-threads`)
- 🧐 **Drift-based detection** to handle network jitter (`-negdrift` / `-posdrift`)
- ❌ **Maximum response time limit** to reduce false positives (`-maxtime`)
- ⏳ **Adaptive HTTP timeout** calculated dynamically (`-timeoutmultiplier` / `-timeoutbuffer`)
- 🔗 **Proxy support** for routing all traffic via `-proxy`
- 🛠 **Replay-proxy support** to send only vulnerable payloads via `-replay-proxy`
- 👤 **Custom User-Agent support** with `-user-agent`
- 📂 **Custom HTTP headers** with multiple `-header "Key:Value"` options
- 💤 **Delay between requests** configurable with `-delay`
- 🔔 **Integration with [ProjectDiscovery notify](https://github.com/projectdiscovery/notify)** for real-time alerts (`-notify`)
- 🧹 **Clean mode**: output only vulnerable URLs for chaining into other tools (`-clean`)
- 🔧 **Extensive debug output** with color-coded logs (`-debug`)
- 📦 **Go install ready** — easy to build, no external dependencies

---

## 📦 Installation

Requires **Go 1.18+**

```bash
go install github.com/c1phy/sqltimer/cmd/sqltimer@latest
```

The binary `sqltimer` will be available in your `$GOBIN` directory.

---

## 🚀 Quick Start

### 1. Prepare a list of target URLs

Each URL must contain at least one GET parameter:

```txt
https://target.com/page?id=1
https://site.org/search?q=test
```

Save as `urls.txt`.

---

### 2. Create your payloads (with `{SLEEP}` placeholder)

```txt
(select*from(select(sleep({SLEEP}))a)
' OR sleep({SLEEP}) --
1') AND SLEEP({SLEEP}) AND ('1'='1
" OR sleep({SLEEP})) --
```

Save as `payloads.txt`.

> `{SLEEP}` will be replaced dynamically based on the `-sleep` parameter, e.g., `sleep(10)`

---

### 3. Run the scan

```bash
cat urls.txt | sqltimer -payloads payloads.txt -sleep 10 -threads 20 -encode -notify
```

---

## 📁 Example Directory Structure

```
sqltimer/
├── payloads.txt
├── urls.txt
└── sqltimer (binary from go install or build)
```

---

## ✅ Example Output

```bash
🔥 SQLi suspicion in param 'q' with payload '(select*from(select(sleep(10)))a)' → https://example.com/search?q=test (Δ=10.2s ≈ 1x sleep ±0.1s/0.5s)
```

---

## 🛠 Options

| Flag                  | Description                                                | Default      |
|------------------------|-------------------------------------------------------------|--------------|
| **General Options**    |                                                             |              |
| `-payloads`            | Path to payload list (required)                             | –            |
| `-version`             | Show current sqltimer version and exit                      | `false`      |
| **Scan/Timing Options**|                                                             |              |
| `-sleep`               | Sleep duration in seconds                                   | `10`         |
| `-negdrift`            | Allowed negative drift from sleep time                      | `0.1`        |
| `-posdrift`            | Allowed positive drift from sleep time                      | `0.5`        |
| `-maxtime`             | Maximum allowed delta response time before skipping (s)     | `30.0`       |
| `-timeoutmultiplier`   | Multiplier for sleep time to calculate HTTP timeout          | `6`          |
| `-timeoutbuffer`       | Buffer (seconds) added to HTTP timeout                      | `10`         |
| `-threads`             | Number of concurrent workers                                | `10`         |
| `-delay`               | Delay between individual HTTP requests (seconds)            | `0`         |
| **Request/Proxy Options**|                                                          |              |
| `-proxy`               | Send all traffic through HTTP proxy                         | –            |
| `-replay-proxy`        | Only send vulnerable payloads through proxy                 | –            |
| `-user-agent`          | Custom User-Agent string                                    | Firefox 124  |
| `-header`              | Add custom header(s) (`Key:Value`) – can be used multiple times | –         |
| `-encode`              | URL-encode payloads before injecting                        | `false`      |
| **Output/Debugging Options**|                                                      |              |
| `-notify`              | Send matches to [notify](https://github.com/projectdiscovery/notify) | `false` |
| `-debug`               | Enable verbose debug output                                 | `false`      |
| `-nocolor`             | Disable colored terminal output                             | `false`      |
| `-clean`               | Output only vulnerable URLs to stdout                       | `false`      |

---

## 🎯 How Drift Works (`-negdrift` and `-posdrift`)

The `-negdrift` and `-posdrift` options define how much timing deviation is tolerated when matching the sleep time against the server's real delay.

### ✍️ Example

- `-sleep 2`
- `-negdrift 0.1`
- `-posdrift 0.5`

### 📊 Drift Detection Table

| Expected Sleep | Match Range    | Observed Delta | Detected? | Reason                          |
|----------------|----------------|----------------|-----------|---------------------------------|
| 2×1 (2s)       | 1.9s - 2.5s     | 2.3s           | ✅         | within 1x sleep window          |
| 2×2 (4s)       | 3.9s - 4.5s     | 3.9s           | ✅         | within 2x sleep window          |
| 2×2 (4s)       | 3.9s - 4.5s     | 4.3s           | ✅         | within 2x sleep window          |
| 2×3 (6s)       | 5.9s - 6.5s     | 5.7s           | ❌         | too far off, not matching       |
| 2×3 (6s)       | 5.9s - 6.5s     | 6.4s           | ✅         | within 3x sleep window          |
| 2×4 (8s)       | 7.9s - 8.5s     | 7.5s           | ❌         | too far off, not matching       |

---

## ⏳ How HTTP Timeout Works

Sqltimer dynamically sets the HTTP client timeout based on your `-sleep` parameter:

```
timeout = (sleep × timeoutmultiplier) + timeoutbuffer
```

Example:
- `-sleep 2`
- `-timeoutmultiplier 6`
- `-timeoutbuffer 10`

Resulting Timeout:
```bash
(2 × 6) + 10 = 22 seconds
```

This ensures slow SQLi payloads are not cut off prematurely but keeps the scanner responsive.

---

## 🔔 Integration with `notify` (optional)

Install [`notify`](https://github.com/projectdiscovery/notify):

```bash
go install github.com/projectdiscovery/notify/cmd/notify@latest
```

Configure it (Slack, Discord, Telegram) via `~/.config/notify/provider-config.yaml`.

Then simply use:

```bash
cat urls.txt | sqltimer -payloads payloads.txt -notify
```

All matches will be piped into your `notify` pipeline automatically.

---

## ❤️ Tips

- Use a higher `-sleep` (e.g. 10s) for more stable detections.
- For stable servers, use defaults `-negdrift 0.1` and `-posdrift 0.5`.
- Combine sqltimer with tools like `waybackurls`, `gau`, `ffuf`, etc.
- Use `-debug` to analyze timing behavior and understand anomalies.
- In noisy environments, increase `-posdrift` slightly (e.g., 0.6).
- Set `-clean` if you only want vuln URLs, ideal for chaining into other tools (e.g., `sqltimer ... -clean | awk '{print $1}'` for clean output).
- Use `-proxy` to route **all** traffic through an HTTP proxy.
- Use `-replay-proxy` if you only want to replay **vulnerable payloads** through a different proxy (e.g., for logging or exploitation).
- When both `-proxy` and `-replay-proxy` are set, **-proxy takes priority** and all traffic will use the main proxy.
- Customize HTTP requests fully with `-user-agent` and `-header` to bypass basic WAF protections.
- Introduce a `-delay` between requests (e.g., `-delay 2`) to slow down scan speed for unstable targets or rate-limited servers.

---

## 🪪 License

MIT License – use it, improve it, share it.

---

## 🙋 About the Author

Marc-Oliver Munz – [munz4u.de](https://munz4u.de)

- 🌐 Website: [https://munz4u.de](https://munz4u.de)
- 🐦 Twitter/X: [@marcolivermunz](https://x.com/marcolivermunz)
- 🌀 Bluesky: [@munz4u.de](https://bsky.app/profile/munz4u.de)
- 💼 LinkedIn: [linkedin.com/in/marc-oliver-munz](https://www.linkedin.com/in/marc-oliver-munz/)

Feel free to connect, contribute, or give feedback!
