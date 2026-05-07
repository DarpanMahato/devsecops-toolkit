/**
 * DevSecOps Toolkit — Shared Library
 * Main pipeline orchestrator. Call devsecops.fullScan() from any Jenkinsfile.
 */

def fullScan(Map config = [:]) {

    // Load policy file
    def policy = loadPolicy(config.policyFile ?: 'policy.yml')

    stage('Build') {
        echo "=== [DevSecOps] Building application image ==="
        sh "docker build -t ${config.imageName}:${env.BUILD_NUMBER} ${config.dockerContext ?: '.'}"
    }

    stage('Trivy — Container & Dependency Scan') {
        echo "=== [DevSecOps] Running Trivy scan ==="
        trivyScan(config.imageName, env.BUILD_NUMBER, policy)
    }

    stage('Semgrep — SAST') {
        echo "=== [DevSecOps] Running Semgrep static analysis ==="
        semgrepScan(config.srcDir ?: '.', policy)
    }

    stage('OWASP ZAP — DAST') {
        echo "=== [DevSecOps] Running OWASP ZAP dynamic scan ==="
        zapScan(config.imageName, env.BUILD_NUMBER, config.appPort ?: '5000', policy)
    }

    stage('Report') {
        echo "=== [DevSecOps] Generating unified security report ==="
        generateReport(config.imageName)
    }
}

// ── Policy loader ──────────────────────────────────────────────
def loadPolicy(String policyFile) {
    def defaults = [
        failOnSeverity: 'CRITICAL',
        trivyEnabled:   true,
        semgrepEnabled: true,
        zapEnabled:     true
    ]
    if (!fileExists(policyFile)) {
        echo "No policy.yml found — using defaults."
        return defaults
    }
    def raw = readFile(policyFile)
    def policy = [:]
    raw.readLines().each { line ->
        def parts = line.split(':', 2)
        if (parts.size() == 2) {
            policy[parts[0].trim()] = parts[1].trim()
        }
    }
    return defaults + policy
}

// ── Placeholder steps (filled in Phases 3 & 4) ────────────────
def trivyScan(String imageName, String tag, Map policy) {
    echo "[Trivy] Placeholder — will be implemented in Phase 3"
    echo "[Trivy] Will scan: ${imageName}:${tag}"
    echo "[Trivy] Fail on severity: ${policy.failOnSeverity}"
}

def semgrepScan(String srcDir, Map policy) {
    echo "[Semgrep] Placeholder — will be implemented in Phase 4"
    echo "[Semgrep] Will scan directory: ${srcDir}"
}

def zapScan(String imageName, String tag, String port, Map policy) {
    echo "[ZAP] Placeholder — will be implemented in Phase 4"
    echo "[ZAP] Will attack: ${imageName}:${tag} on port ${port}"
}

def generateReport(String imageName) {
    echo "[Report] Placeholder — will be implemented in Phase 5"
    echo "[Report] Will aggregate findings for: ${imageName}"
}