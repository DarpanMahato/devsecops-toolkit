# DevSecOps Toolkit for Jenkins

> A language-agnostic, policy-driven CI/CD security framework that unifies container scanning, static analysis, and dynamic testing into a single reusable pipeline deployable by any team in under one hour.

---

## About This Project

This toolkit was developed as an industry group project for **SCI700 - Research/Industry Dissertation 1** at the **University of the Sunshine Coast (UniSC)**, Trimester 1, 2026.

### Group 3

| Member | Role | Responsibility |
|---|---|---|
| **Sagar Thapa Magar** | Project Lead | SAST & Pipeline Orchestration - Semgrep integration, Jenkinsfile template, stage sequencing |
| **Darpan Mahato** | Developer | Container & Dependency Scanning - Trivy integration, YAML policy-as-code, severity gate logic |
| **Gowtham Sai Sridhar Addhanki** | Developer | DAST & Reporting - OWASP ZAP integration, unified HTML dashboard, multi-tool report aggregation |

---

## What This Is

The DevSecOps Toolkit for Jenkins automatically runs three layers of security scanning on every code push - no manual steps, no security expertise required. If a vulnerability is found, the build stops. If everything is clean, the code ships. A unified HTML security report is generated after every run.

```
Developer pushes code
        ↓
Jenkins pipeline triggers automatically
        ↓
Build → Trivy → Semgrep → OWASP ZAP → Report
        ↓
PASS - code proceeds  |  FAIL - build blocked, report generated
```

---

## Tools Integrated

| Tool | Role | What It Catches |
|---|---|---|
| **Trivy** | Container & Dependency Scan | CVEs in OS packages, vulnerable libraries, Dockerfile misconfigurations |
| **Semgrep** | Static Analysis (SAST) | SQL injection, XSS, hardcoded secrets, insecure patterns |
| **OWASP ZAP** | Dynamic Testing (DAST) | Runtime vulnerabilities, missing security headers, endpoint attacks |

---

## Novel Contributions

**1. Language-agnostic Jenkinsfile templates**
Pipeline templates are parameterised so they work for any programming language or framework. Teams supply only a config file - they never modify the template itself.

**2. Policy-as-code via YAML**
Each project defines its own severity thresholds and exceptions in a single `policy.yml` file. A startup and a financial institution can enforce different standards using the same toolkit.

**3. Unified HTML security dashboard**
Findings from all three tools are aggregated into one HTML report published by Jenkins after each run. No external platform (DefectDojo, Snyk, etc.) is required.

---

## Project Structure

```
devsecops-toolkit/
├── jenkins.Dockerfile        # Custom Jenkins image with all tools baked in
├── docker-compose.yml        # Full stack configuration
├── policy.yml                # Severity policy config - the only file teams edit
├── generate-report.py        # Unified HTML dashboard generator
├── Jenkinsfile               # Pipeline template - copy into any project repo
├── shared-library/           # Reusable Groovy pipeline steps
│   └── vars/
│       └── devsecops.groovy
└── sample-app/               # Intentionally vulnerable demo application
    ├── app.py
    ├── requirements.txt
    └── Dockerfile
```

---

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- 4GB RAM and 20GB disk space
- Ports `8080` and `50000` open

### 1. Clone the repository

```bash
git clone https://github.com/DarpanMahato/devsecops-toolkit.git
cd devsecops-toolkit
```

### 2. Build and start Jenkins

```bash
docker compose build
docker compose up -d
```

### 3. Unlock Jenkins

Open `http://localhost:8080` and paste the initial admin password:

```bash
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

Click **Install suggested plugins** and create your admin account.

### 4. Install required plugins

Go to **Manage Jenkins → Plugins → Available plugins** and install:
- Docker Pipeline
- HTML Publisher

Restart Jenkins after installing.

### 5. Copy the report generator

```bash
docker cp generate-report.py jenkins:/var/jenkins_home/generate-report.py
```

### 6. Create a pipeline job

1. Click **New Item** → name it → choose **Pipeline** → OK
2. Under **Pipeline** set Definition to **Pipeline script from SCM**
3. SCM: **Git** → enter your repo URL → branch `*/main`
4. Script Path: `Jenkinsfile`
5. Check **GitHub hook trigger for GITScm polling**
6. Click **Save** → **Build Now**

### 7. Add a GitHub webhook

In your GitHub repo go to **Settings → Webhooks → Add webhook**:

- Payload URL: `http://YOUR-SERVER-IP:8080/github-webhook/`
- Content type: `application/json`
- Events: **Just the push event**

From this point, every push triggers the pipeline automatically.

---

## Configuration

The only file a team needs to edit is `policy.yml`:

```yaml
# Severity level that blocks the build: CRITICAL, HIGH, MEDIUM, LOW
failOnSeverity: CRITICAL

# Toggle individual scanners on or off
trivyEnabled:   true
semgrepEnabled: true
zapEnabled:     true

# Semgrep ruleset: auto, p/python, p/owasp-top-ten, etc.
semgrepRuleset: auto

# ZAP scan type: baseline (passive) or full (active attack)
zapScanType: baseline
```

No pipeline code changes are required. Different projects can enforce different standards using the same toolkit.

---

## Pipeline Stages

### Stage 1 - Build
Builds a Docker image from the application source code. Every build produces a uniquely tagged image (`app-name:BUILD_NUMBER`).

### Stage 2 - Trivy (Container & Dependency Scan)
Scans the Docker image for:
- Known CVEs in OS packages
- Vulnerable libraries in `requirements.txt`, `package.json`, `pom.xml`
- Dockerfile misconfigurations

Fails the build if findings exceed `failOnSeverity` in `policy.yml`.

### Stage 3 - Semgrep (SAST)
Performs static analysis on the source code without running it. Detects:
- SQL injection
- Cross-site scripting (XSS)
- Hardcoded secrets and API keys
- Insecure coding patterns
- Debug mode left enabled

Fails the build if blocking issues are found.

### Stage 4 - OWASP ZAP (DAST)
Starts the application in a Docker container and simulates an attacker. Detects:
- Missing security headers (CSP, X-Frame-Options, etc.)
- Runtime vulnerabilities invisible to static analysis
- Endpoint exposure and injection points

Fails the build if high-risk alerts are found (exit code 2).

### Stage 5 - Unified Report
Aggregates findings from all three tools into a single HTML dashboard published by Jenkins. Accessible via the **Security Report** link in the Jenkins sidebar after each build.

---

## How Teams Adopt This Toolkit

Any team building a web application adds two files to their repo:

```
my-project/
├── Jenkinsfile      ← copied from this toolkit, never edited
├── policy.yml       ← the only file the team configures
└── ... (existing project files)
```

That is the entire setup. The team continues pushing code as normal. Security scanning runs automatically on every push.

---

## DevSecOps Principles Implemented

| Principle | Implementation |
|---|---|
| **Shift left** | Security runs at build time on every commit, not as a final release gate |
| **Fail fast** | Build stops immediately when a policy violation is found |
| **Automate everything** | No human intervention required to trigger or run scans |
| **Continuous feedback** | Developers receive a security report on every push |
| **Security as code** | All configuration is version-controlled alongside application code |

---

## Comparison with Traditional DevSecOps

| | Traditional DevSecOps | This Toolkit |
|---|---|---|
| Setup time | Weeks | Under one hour |
| Security expertise needed | Yes | No |
| Language support | Stack-specific | Any language |
| Reporting | Three separate reports | One unified dashboard |
| Policy configuration | Hardcoded | YAML per project |
| Platform | GitHub Actions / GitLab CI | Jenkins (enterprise-ready) |

---

## Requirements

| Requirement | Version |
|---|---|
| Jenkins | LTS |
| Docker | 20.x or later |
| Trivy | 0.69.x |
| Semgrep | Latest |
| OWASP ZAP | 2.17.0 |
| Python | 3.x |
| Java | 21 (for ZAP) |

---

## Acknowledgements

Developed as part of **SCI700 - Research/Industry Dissertation 1**
University of the Sunshine Coast (UniSC), Adelaide Campus, Trimester 1, 2026

---

*A language-agnostic, policy-driven Jenkins DevSecOps toolkit — requiring no external platform and deployable by any team in under one hour.*