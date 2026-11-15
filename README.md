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

### What to review in SonarQube

Open `http://localhost:9000` and check the `juice-shop` project: security vulnerabilities, security hotspots, bugs, code smells and the quality gate. Juice Shop is intentionally vulnerable, so a failing quality gate is expected.


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
| HTML opens with no styling | The Modern template keeps CSS/JS in a sibling folder with the same name as the HTML, and only the HTML was copied | Copy both, or use the Traditional HTML Report template (see below) |

Getting the report out of the container (the container was started with `--rm`, so copy before stopping it):

```bash
docker exec <container> ls -lt /home/zap

# Modern template: copy the HTML and its same-named folder together
docker cp <container>:/home/zap/2026-11-15-ZAP-Report-.html ./
docker cp <container>:/home/zap/2026-11-15-ZAP-Report- ./
```

Do not rename the HTML file; it looks for its assets folder by name. Also make sure no old copy of the folder exists on the host (`rm -rf` it first) and that both are in the same directory.

For a single self-contained file, generate again with **Report > Generate Report**, choose **Traditional HTML Report** as the template, set Report Name to `zap-full-report` and Report Directory to `/home/zap/`, then:

```bash
docker cp <container>:/home/zap/zap-full-report.html ./
```

For DefectDojo import, also generate a **Traditional XML Report** or JSON report.

Status: the ZAP report was generated inside the container, and a styled copy on the host was still being sorted out at the time of writing.


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
- [ ] Review SonarQube findings (Task 1)
- [ ] Run Trivy filesystem and dependency scan
- [ ] Investigate CVEs and fixed versions
- [ ] Run ZAP baseline scan
- [ ] Run ZAP active scan after Manual Explore
- [ ] Document findings (Task 2)

## 7. Next steps

1. Fix a few findings from each tool and re-scan to confirm they disappear.
2. Import the XML/JSON reports into DefectDojo.
3. Only then integrate all three tools into a Jenkins pipeline, using the SonarQube quality gate (`sonar.qualitygate.wait=true`) as a pipeline gate.

## Security notes

- Never commit tokens. Keep `SONAR_TOKEN` in an environment variable or an untracked `.env` file.
- Juice Shop is deliberately vulnerable. Do not expose it to the internet.
- Run DAST only on systems you own or have permission to test.
