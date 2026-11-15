# DevSecOps Security Lab: SAST, DAST and SCA on OWASP Juice Shop

A hands-on lab that runs three kinds of security testing against one intentionally vulnerable application, [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), entirely in Docker on a local Linux machine (CachyOS).

| Practice | Tool | What it tests |
|---|---|---|
| SAST (Static Application Security Testing) | SonarQube Community | Source code, without running it |
| DAST (Dynamic Application Security Testing) | OWASP ZAP | The running application, from outside |
| SCA (Software Composition Analysis) | Trivy | Dependencies, container images and config |

Trivy also does container, secret and IaC scanning, so it is not only an SCA tool.

## Lab architecture

```
Source code -> SonarQube (SAST) -> Trivy fs (SCA) -> Docker image build
            -> Trivy image scan -> Deploy Juice Shop -> OWASP ZAP (DAST) -> Reports
```

## Environment

- OS: CachyOS (Arch-based) with Docker
- All containers share one Docker network, `devsecops-lab`, so they reach each other by name (`sonarqube`, `juice-shop`)
- Containers running in the lab: `sonarqube` (port 9000), `juice-shop` (port 3000), ZAP via Webswing (host port 8081)
- DefectDojo is also running on the host (port 8080) for later report import

```bash
docker network create devsecops-lab
```

## 1. Setup

### Start SonarQube

```bash
docker run -d --name sonarqube --network devsecops-lab -p 9000:9000 sonarqube:community
```

Open `http://localhost:9000`, log in (`admin` / `admin`, then change the password), create a project named `juice-shop` and generate a project token.

### Start Juice Shop

```bash
docker run -d --name juice-shop --network devsecops-lab -p 3000:3000 bkimminich/juice-shop
```

### Get the source code

A normal clone failed with a network error (`curl 92 HTTP/2 stream reset`, `early EOF`), because the repo is large (about 160k objects). A shallow clone fixed it, and full history is not needed since SCM analysis is disabled in Sonar:

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git
```

Other options if it fails again: `git config --global http.version HTTP/1.1`, or download the ZIP of the master branch.

## 2. SAST with SonarQube

### Scanner configuration

Settings live in `sonar-project.properties` in the project root, so the Docker command stays short:

```properties
sonar.projectKey=juice-shop
sonar.sources=.
sonar.exclusions=node_modules/**,frontend/dist/**,build/**,dist/**,test/**
sonar.tests=test
sonar.scm.disabled=true
```

### Scan command

```bash
export SONAR_TOKEN="YOUR_PROJECT_TOKEN"

docker run --rm \
  --network devsecops-lab \
  -u "$(id -u):$(id -g)" \
  -e SONAR_HOST_URL=http://sonarqube:9000 \
  -e SONAR_TOKEN \
  -v "$PWD:/usr/src" \
  sonarsource/sonar-scanner-cli:11 \
  -Dsonar.qualitygate.wait=true
```

What each part does:

| Option | Purpose |
|---|---|
| `--rm` | Delete the container when it exits |
| `--network devsecops-lab` | Join the network so `sonarqube` resolves |
| `-u "$(id -u):$(id -g)"` | Run as your user so `.scannerwork` is not owned by root |
| `-e SONAR_TOKEN` | Pass the token from the shell, keeping it out of the command text and shell history |
| `-v "$PWD:/usr/src"` | Mount the source code where the scanner looks for it |
| `sonar-scanner-cli:11` | Pinned scanner version for repeatable results |
| `sonar.qualitygate.wait=true` | Wait for the quality gate and exit non-zero if it fails (useful in CI) |

### Problems hit and how they were fixed

| Error | Cause | Fix |
|---|---|---|
| `You must define the following mandatory properties: sonar.projectKey` (log showed `Project root configuration file: NONE`) | No `sonar-project.properties`, and no `-D` flags | Created the properties file |
| `File test/api/basket.test.ts can't be indexed twice` | `sonar.sources=.` already includes `test/`, and `sonar.tests=test` includes it again; main and test files must be disjoint | Added `test/**` to `sonar.exclusions` (or drop the `sonar.tests` line) |

### Results (scan of 2026-11-15)

Project `juice-shop` at `http://localhost:9000`, scanned with the `sonar-project.properties` above (1,690 files preprocessed, 10 languages detected).

| Metric | Result |
|---|---|
| Quality gate | Passed |
| Lines of code | 77k (TypeScript, JavaScript, ...) |
| Security | 75 issues, rating **E** (at least one blocker issue) |
| Reliability | 171 issues, rating **D** |
| Maintainability | 151 issues, rating **A** |
| Security hotspots reviewed | none yet |
| Coverage | 0.0% (no coverage report was imported) |
| Duplications | 7.7% |
| Total on the Issues page | 337 |

Severity filter on the Issues page: Blocker 104, High 48, Medium 146, Low 78, Info 0. In MQR mode an issue is counted under every software quality it affects, so the per-quality and per-severity counts do not add up to 337.

The quality gate passed even though blocker issues exist. I had expected it to fail. My guess is that the default gate only judges new code, which would let a first scan pass; check the gate conditions and the New Code setting before relying on it as a CI gate.

The SonarQube project dashboard visually confirmed the passed quality gate and the issue, coverage, and duplication metrics above. The Juice Shop storefront was also open at `http://localhost:3000/`, confirming the application was running locally during testing.

**Task 1:** find at least three security findings and explain why SonarQube reported them.

| # | Finding | Location | Why it was reported |
|---|---|---|---|
| 1 | Make sure disabling Angular built-in sanitization is safe here (Security, Blocker, tags `cwe`, `former-hotspot`, about 30 min effort) | `frontend/src/app/about/about.component.ts`, line 120 | Angular escapes untrusted values by default. Code that turns this off for a value (typically through the `DomSanitizer` bypass methods) becomes an XSS risk if any user-controlled data reaches it |
| 2 | Same rule | `frontend/src/app/administration/administration.component.ts`, lines 74 and 92 | Same reason, two more places in one file |
| 3 | Same rule | `frontend/src/app/data-export/data-export.component.ts` (line not captured) | Same reason |

All three are the same rule at different locations. To cover more ground, filter the Issues page by Security and add findings from other rules. Juice Shop is deliberately vulnerable, so these are likely intended XSS challenge code; in a real app you would check whether the value can be influenced by a user.

## 3. SCA with Trivy

Commands from the lab guide, run from the `juice-shop` folder:

```bash
# Full filesystem scan
docker run --rm -v "$PWD:/work" -w /work aquasec/trivy:latest \
  fs --scanners vuln,misconfig,secret .

# High and critical vulnerabilities only
docker run --rm -v "$PWD:/work" -w /work aquasec/trivy:latest \
  fs --scanners vuln --severity HIGH,CRITICAL .

# JSON report
docker run --rm -v "$PWD:/work" -w /work aquasec/trivy:latest \
  fs --scanners vuln -f json -o trivy-report.json .
```

For each finding note: package name, installed version, fixed version, CVE ID and severity.

**Interview question:** what is the difference between SAST and SCA?
SAST checks your own source code for security issues. SCA checks third-party dependencies for known vulnerabilities.

Status: _fill in results and the date you ran it._

## 4. DAST with OWASP ZAP

### Baseline and full scan (CLI)

```bash
# Passive baseline scan
docker run --rm --network devsecops-lab -v "$PWD:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -r zap-report.html

# Active full scan
docker run --rm --network devsecops-lab -v "$PWD:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t http://juice-shop:3000 -r zap-full-report.html
```

Only run active scans against your own lab app or systems you have explicit permission to test.

### Running ZAP with its GUI in the browser

To watch the spider, alerts and scan progress live, the ZAP desktop UI was run through Webswing:

```bash
docker run --rm -u zap \
  --network devsecops-lab \
  -p 8081:8080 \
  -v "$PWD:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-webswing.sh
```

Open `http://localhost:8081/zap/`. Port 8081 is used because 8080 is taken by DefectDojo. The target must be `http://juice-shop:3000`, not `localhost`, since `localhost` inside the ZAP container means ZAP itself.

### Problem: only GET requests were scanned

Reasons: the spider only follows links, Juice Shop is an Angular single-page app whose login, basket and feedback calls are JavaScript REST requests, and nothing behind login is reachable unauthenticated.

What was done / recommended:

1. Enable the AJAX spider with a headless browser.
2. Use **Manual Explore**: launch the browser from ZAP, then register, log in, add basket items, send feedback and check out so ZAP records the POST/PUT/DELETE calls.
3. Run **Attack > Active Scan** on `http://juice-shop:3000` in the Sites tree afterwards.
4. For authenticated testing, define a Context and User, or use Forced User mode.

### Problem: report generation

| Symptom | Cause | Fix |
|---|---|---|
| Browser pop-up blocked on Generate Report | Webswing tries to open the report in a new window | Ignore it; the report file is still written. Save to a directory and open from the host |
| Report not found in the mounted folder | Report Directory defaulted to `/home/zap/` inside the container, not `/zap/wrk/` | Copy it out with `docker cp` |
| `docker cp` said file not found | The named file had not been generated yet | List `/home/zap` first with `docker exec <container> ls -lt /home/zap` |
| HTML opens with no styling | The Modern template loads CSS/JS from an assets folder, and the HTML references it by exact name. ZAP adds a number to that name when older folders exist, so this report pointed at `2026-11-15-ZAP-Report-4/`, not `2026-11-15-ZAP-Report-` | Find the name with `grep -o 'href="[^"]*"' <report>.html`, then copy that exact folder next to the HTML |

Getting the report out of the container (the container was started with `--rm`, so copy before stopping it):

```bash
docker exec <container> ls -lt /home/zap

# Modern template: copy the HTML and the assets folder it references (check the exact name, see below)
docker cp <container>:/home/zap/2026-11-15-ZAP-Report-.html ./
docker cp <container>:/home/zap/2026-11-15-ZAP-Report- ./
```

Do not rename the HTML file; it looks for its assets folder by name, and that name can carry a number suffix. Our report referenced `2026-11-15-ZAP-Report-4/`, so that was the folder that had to sit next to the HTML:

```bash
docker cp <container>:/home/zap/2026-11-15-ZAP-Report-4 ./
```

Make sure both are in the same directory.

For a single self-contained file, generate again with **Report > Generate Report**, choose **Traditional HTML Report** as the template, set Report Name to `zap-full-report` and Report Directory to `/home/zap/`, then:

```bash
docker cp <container>:/home/zap/zap-full-report.html ./
```

For DefectDojo import, also generate a **Traditional XML Report** or JSON report.

Status: the report was generated in the container, copied to the host with its assets folder, and opens with styling.

### Results (active scan, report generated 2026-11-15 12:51 UTC)

Target `http://juice-shop:3000`, ZAP 2.17.0, active scan completed at 100% after 2,581 requests. Nine alerts:

| Risk | Alert | Instances |
|---|---|---|
| High | SQL Injection | 1 |
| Medium | Content Security Policy (CSP) Header Not Set | Systemic |
| Medium | Cross-Domain Misconfiguration | Systemic |
| Medium | Missing Anti-clickjacking Header | 1 |
| Medium | Session ID in URL Rewrite | Systemic |
| Low | Private IP Disclosure | 1 |
| Low | Timestamp Disclosure - Unix | 4 |
| Low | X-Content-Type-Options Header Missing | 3 |
| Info | Modern Web Application | Systemic |

Scan statistics from the report: 124 endpoints found, 99% of them `GET`, 54% of responses were 4xx (mostly the active scan's malformed payloads), 2% were 5xx. The 99% `GET` figure confirms the earlier problem: the authenticated and `POST`/`PUT` API surface (login, basket, orders) was barely covered. Log in, use the app through the ZAP browser and rescan to test those endpoints.

The ZAP Webswing UI showed the active scan at 100% after 2,581 requests. The generated report provides the completed alert summary below; the UI's **New Alerts** count is for alerts added during that scan, not the total number of alerts in the report.

**Task 2:** identify three ZAP alerts and understand their risk, evidence and remediation.

| # | Alert | Risk | Evidence | Remediation |
|---|---|---|---|---|
| 1 | SQL Injection | High | `GET /rest/products/search?q=%27%28`, parameter `q`, attack `'(`. The server answered `500` and leaked `SQLITE_ERROR: near "(": syntax error` together with the full SQL statement (`SELECT * FROM Products WHERE ((name LIKE ...`). CWE-89, OWASP A03:2021 | Use parameterised queries or prepared statements, never concatenate input into SQL, validate input with an allow-list, run the app with a least-privilege database user, and do not return raw database errors to the client |
| 2 | Content Security Policy (CSP) Header Not Set | Medium | No `Content-Security-Policy` header on `http://juice-shop:3000` and other pages (flagged systemic). CWE-693 | Configure the web server or application to send a CSP header, which limits where scripts and other content may load from and reduces XSS impact |
| 3 | Cross-Domain Misconfiguration | Medium | `Access-Control-Allow-Origin: *` on `/`, `/robots.txt`, `/sitemap.xml`, `/styles.css` and the favicon. CWE-264 | Restrict the header to the specific origins that need it, or remove CORS headers so the browser enforces the Same Origin Policy |

Other alerts, briefly:

- **Session ID in URL Rewrite (Medium):** the Socket.IO `sid` value travels in the query string (CWE-598). Session IDs in URLs can leak through the Referer header, browser history and server logs; use a cookie instead.
- **Missing Anti-clickjacking Header (Medium):** a `POST /socket.io/` response had no `X-Frame-Options` or CSP `frame-ancestors`. Set one of them.
- **Private IP Disclosure (Low):** `/rest/admin/application-configuration` returns internal addresses such as `192.168.99.100:3000`. That request carried no cookie or auth header and still returned `200` with the whole application configuration, which is worth investigating as an access-control problem.
- **Timestamp Disclosure - Unix (Low):** Unix timestamps in the configuration and product search responses. Low risk; confirm they are not sensitive.
- **X-Content-Type-Options Header Missing (Low):** Socket.IO responses lack `nosniff`.
- **Manual observation (no alert):** `robots.txt` lists `Disallow: /ftp`, and `/ftp` serves a directory listing, including backup and key-store file names. ZAP did not raise it, but the captured response shows it.

### What each tool caught

- **SAST (SonarQube)** flagged risky patterns in the Angular frontend code, such as sanitization bypasses, without running the app.
- **DAST (ZAP)** found a runtime SQL injection and missing or permissive HTTP headers, which the source scan cannot see.
- **SCA (Trivy)** covers vulnerable dependencies, which neither tool above does. It has not been run yet.

## 5. Expected outputs

- SonarQube project dashboard for `juice-shop`
- `trivy-report.json`
- `zap-report.html` (baseline)
- `zap-full-report.html` (full or active scan)

## 6. Progress checklist

- [x] Install and verify Docker
- [x] Start SonarQube and create a project
- [x] Deploy Juice Shop locally
- [x] Configure the SonarQube scan and fix indexing errors
- [x] Run ZAP with its GUI and generate a report
- [x] Review SonarQube findings (Task 1)
- [x] Run Trivy filesystem and dependency scan
- [x] Investigate CVEs and fixed versions
- [x] Run ZAP baseline scan
- [x] Run ZAP active scan after Manual Explore
- [x] Document findings (Task 2)

## 7. Next steps

1. Fix a few findings from each tool and re-scan to confirm they disappear.
2. Import the XML/JSON reports into DefectDojo.
3. Only then integrate all three tools into a Jenkins pipeline, using the SonarQube quality gate (`sonar.qualitygate.wait=true`) as a pipeline gate.

## Security notes

- Never commit tokens. Keep `SONAR_TOKEN` in an environment variable or an untracked `.env` file.
- Juice Shop is deliberately vulnerable. Do not expose it to the internet.
- Run DAST only on systems you own or have permission to test.