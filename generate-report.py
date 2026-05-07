#!/usr/bin/env python3
"""
DevSecOps Toolkit — Unified Security Report Generator
Reads Trivy JSON, Semgrep JSON, and ZAP XML reports and produces
a single HTML dashboard.
"""

import json
import xml.etree.ElementTree as ET
import sys
import os
from datetime import datetime

def load_trivy(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        data = json.load(f)
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            findings.append({
                "id":       vuln.get("VulnerabilityID", ""),
                "pkg":      vuln.get("PkgName", ""),
                "severity": vuln.get("Severity", ""),
                "title":    vuln.get("Title", ""),
                "fixed":    vuln.get("FixedVersion", "Not fixed"),
                "installed":vuln.get("InstalledVersion", ""),
            })
    return findings

def load_semgrep(path):
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path) as f:
        data = json.load(f)
    for r in data.get("results", []):
        findings.append({
            "rule":     r.get("check_id", ""),
            "file":     r.get("path", ""),
            "line":     r.get("start", {}).get("line", ""),
            "message":  r.get("extra", {}).get("message", ""),
            "severity": r.get("extra", {}).get("severity", "").upper(),
        })
    return findings

def load_zap(path):
    findings = []
    if not os.path.exists(path):
        return findings
    tree = ET.parse(path)
    root = tree.getroot()
    for site in root.findall(".//site"):
        for alert in site.findall(".//alertitem"):
            findings.append({
                "name":     alert.findtext("alert", ""),
                "risk":     alert.findtext("riskdesc", ""),
                "url":      alert.findtext("uri", ""),
                "desc":     alert.findtext("desc", "")[:200],
                "solution": alert.findtext("solution", "")[:200],
            })
    return findings

def severity_color(sev):
    s = sev.upper()
    if s == "CRITICAL": return "#dc2626"
    if s == "HIGH":      return "#ea580c"
    if s == "MEDIUM":    return "#d97706"
    if s == "LOW":       return "#65a30d"
    return "#6b7280"

def severity_badge(sev):
    color = severity_color(sev)
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">{sev}</span>'

def generate(trivy_path, semgrep_path, zap_path, output_path, image_name, build_number):
    trivy   = load_trivy(trivy_path)
    semgrep = load_semgrep(semgrep_path)
    zap     = load_zap(zap_path)

    trivy_crit  = sum(1 for f in trivy   if f["severity"] == "CRITICAL")
    trivy_high  = sum(1 for f in trivy   if f["severity"] == "HIGH")
    semgrep_err = sum(1 for f in semgrep if f["severity"] in ("ERROR","WARNING","CRITICAL","HIGH"))
    zap_high    = sum(1 for f in zap     if "High" in f["risk"])

    status       = "PASSED" if trivy_crit == 0 and zap_high == 0 else "FAILED"
    status_color = "#16a34a" if status == "PASSED" else "#dc2626"

    def trivy_rows():
        if not trivy:
            return "<tr><td colspan='5' style='text-align:center;color:#6b7280'>No vulnerabilities found</td></tr>"
        rows = ""
        for f in trivy:
            rows += f"""<tr>
                <td>{f['id']}</td>
                <td>{f['pkg']}</td>
                <td>{severity_badge(f['severity'])}</td>
                <td>{f['installed']}</td>
                <td>{f['fixed']}</td>
            </tr>"""
        return rows

    def semgrep_rows():
        if not semgrep:
            return "<tr><td colspan='4' style='text-align:center;color:#6b7280'>No findings</td></tr>"
        rows = ""
        for f in semgrep:
            short_rule = f['rule'].split('.')[-1]
            rows += f"""<tr>
                <td style='font-family:monospace;font-size:12px'>{f['file'].split('/')[-1]}:{f['line']}</td>
                <td>{severity_badge(f['severity']) if f['severity'] else severity_badge('INFO')}</td>
                <td>{short_rule}</td>
                <td style='font-size:13px'>{f['message'][:120]}</td>
            </tr>"""
        return rows

    def zap_rows():
        if not zap:
            return "<tr><td colspan='3' style='text-align:center;color:#6b7280'>No alerts found</td></tr>"
        rows = ""
        for f in zap:
            risk = f['risk'].split()[0] if f['risk'] else "Info"
            rows += f"""<tr>
                <td>{f['name']}</td>
                <td>{severity_badge(risk)}</td>
                <td style='font-size:13px'>{f['desc'][:150]}</td>
            </tr>"""
        return rows

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DevSecOps Security Report — Build #{build_number}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: Arial, sans-serif; background: #f3f4f6; color: #111; }}
  .header {{ background: #1e3a5f; color: #fff; padding: 28px 40px; }}
  .header h1 {{ font-size: 24px; font-weight: 700; }}
  .header p  {{ font-size: 14px; opacity: 0.8; margin-top: 6px; }}
  .badge {{ display:inline-block; padding: 6px 18px; border-radius: 6px;
            font-size: 15px; font-weight: 700; color: #fff;
            background: {status_color}; margin-top: 12px; }}
  .container {{ max-width: 1100px; margin: 32px auto; padding: 0 24px; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
  .card {{ background: #fff; border-radius: 8px; padding: 20px 24px;
           box-shadow: 0 1px 3px rgba(0,0,0,0.08); border-top: 4px solid #2563eb; }}
  .card .num {{ font-size: 32px; font-weight: 700; color: #1e3a5f; }}
  .card .label {{ font-size: 13px; color: #6b7280; margin-top: 4px; }}
  .section {{ background: #fff; border-radius: 8px; margin-bottom: 24px;
              box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; }}
  .section-header {{ background: #1e3a5f; color: #fff; padding: 14px 24px;
                     font-size: 15px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #f9fafb; padding: 10px 14px; text-align: left;
        font-size: 12px; color: #6b7280; text-transform: uppercase;
        border-bottom: 1px solid #e5e7eb; }}
  td {{ padding: 10px 14px; font-size: 13px; border-bottom: 1px solid #f3f4f6;
        vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: #f9fafb; }}
  .footer {{ text-align: center; color: #9ca3af; font-size: 12px;
             padding: 24px 0 40px; }}
</style>
</head>
<body>
<div class="header">
  <h1>DevSecOps Security Report</h1>
  <p>Image: <strong>{image_name}</strong> &nbsp;|&nbsp;
     Build: <strong>#{build_number}</strong> &nbsp;|&nbsp;
     Generated: <strong>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</strong></p>
  <div class="badge">Overall Status: {status}</div>
</div>

<div class="container">
  <div class="summary">
    <div class="card">
      <div class="num">{len(trivy)}</div>
      <div class="label">Trivy — Total CVEs</div>
    </div>
    <div class="card">
      <div class="num" style="color:{'#dc2626' if trivy_crit > 0 else '#16a34a'}">{trivy_crit}</div>
      <div class="label">Trivy — Critical CVEs</div>
    </div>
    <div class="card">
      <div class="num" style="color:{'#ea580c' if semgrep_err > 0 else '#16a34a'}">{len(semgrep)}</div>
      <div class="label">Semgrep — Code Findings</div>
    </div>
    <div class="card">
      <div class="num" style="color:{'#dc2626' if zap_high > 0 else '#16a34a'}">{len(zap)}</div>
      <div class="label">ZAP — DAST Alerts</div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">Trivy — Container &amp; Dependency Scan ({len(trivy)} findings)</div>
    <table>
      <tr><th>CVE ID</th><th>Package</th><th>Severity</th><th>Installed</th><th>Fixed Version</th></tr>
      {trivy_rows()}
    </table>
  </div>

  <div class="section">
    <div class="section-header">Semgrep — Static Analysis ({len(semgrep)} findings)</div>
    <table>
      <tr><th>Location</th><th>Severity</th><th>Rule</th><th>Message</th></tr>
      {semgrep_rows()}
    </table>
  </div>

  <div class="section">
    <div class="section-header">OWASP ZAP — Dynamic Scan ({len(zap)} alerts)</div>
    <table>
      <tr><th>Alert</th><th>Risk</th><th>Description</th></tr>
      {zap_rows()}
    </table>
  </div>
</div>

<div class="footer">DevSecOps Toolkit for Jenkins &mdash; Generated automatically on every build</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"Report written to {output_path}")

if __name__ == "__main__":
    generate(
        trivy_path   = sys.argv[1] if len(sys.argv) > 1 else "/var/jenkins_home/reports/trivy-report.json",
        semgrep_path = sys.argv[2] if len(sys.argv) > 2 else "/var/jenkins_home/reports/semgrep-report.json",
        zap_path     = sys.argv[3] if len(sys.argv) > 3 else "/var/jenkins_home/reports/zap-report.xml",
        output_path  = sys.argv[4] if len(sys.argv) > 4 else "/var/jenkins_home/reports/security-report.html",
        image_name   = sys.argv[5] if len(sys.argv) > 5 else "sample-app",
        build_number = sys.argv[6] if len(sys.argv) > 6 else "0",
    )