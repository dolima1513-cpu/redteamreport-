# redteamreport-
"Simulated Reconnaissance Report for Penetration Testing Project" 
📝 Executive Summary

This report outlines a simulated red team operation, focusing on the reconnaissance phase against a fictional organization, “Acme Corp”. The objective was to gather actionable intelligence that could be used in later phases of a penetration test. The report includes tools used, techniques applied, findings, and recommendations for improving Acme Corp’s security posture.


---

🔍 1. Introduction

Objective:
To simulate the Reconnaissance Phase of a Red Team Operation and identify potential vulnerabilities in Acme Corp's online infrastructure.

Scope:

External recon only (no internal access)

Passive and active recon methods

No actual exploitation


Methodology:

Passive Recon: OSINT, WHOIS, DNS

Active Recon: Ping sweeps, port scans, banner grabbing



---

🌐 2. Target Overview

Parameter	Value

Target Name	Acme Corp
Domain	acmecorp.fake
IP Range	192.168.1.0/24 (simulated)
Employees Found	6 (via LinkedIn, ZoomInfo)
Subdomains Found	3



---

🧰 3. Tools Used

Tool	Purpose

Recon-ng	Framework for web-based recon
theHarvester	Email and employee harvesting
Shodan	Discover exposed devices
Nmap	Port scanning, OS fingerprinting
WHOIS	Domain information lookup
NSLookup	DNS records enumeration
Google Dorking	Public data leakage discovery



---

🕵 4. Reconnaissance Findings

A. WHOIS Lookup

Registrar: GoDaddy

Created: Jan 2020

Email: admin@acmecorp.fake


B. DNS & Subdomain Enumeration

www.acmecorp.fake

mail.acmecorp.fake

dev.acmecorp.fake


C. Shodan Results

Exposed device: Nginx server on port 80

Detected CVE: CVE-2022-23943 (Nginx DoS)


D. theHarvester

Emails found:

john.doe@acmecorp.fake

support@acmecorp.fake



E. LinkedIn Employee OSINT

Found 4 employees with job titles:

CTO, Software Engineer, DevOps, Intern


Public posts about tech stack (React, AWS)


F. Nmap Scan

nmap -sS -sV -T4 -Pn 192.168.1.10

Open Ports Found:

Port	Service	Version

22	SSH	OpenSSH 7.9
80	HTTP	Nginx 1.14.2
443	HTTPS	Apache/2.4.29



---

⚠ 5. Vulnerabilities Identified

Type	Detail	Risk Level

Outdated Server	Nginx 1.14.2	Medium
Public Employee Info	Emails and job roles exposed	Medium
Open Ports	Port 22 exposed externally	High



---

💡 6. Recommendations

1. Restrict access to SSH (port 22) via firewall rules or VPN.


2. Update Nginx to the latest stable version.


3. Perform employee awareness training on data leakage.


4. Consider using cloud WAF (Web Application Firewall).


5. Monitor Shodan and similar platforms for exposed assets.




---

📚 7. Appendix

A. Scripts and Commands Used

Recon-ng Module Example:

recon-ng
> marketplace install recon/domains-hosts/bing_domain_web
> use recon/domains-hosts/bing_domain_web
> set SOURCE acmecorp.fake
> run

theHarvester Command:

theharvester -d acmecorp.fake -b google


---

B. References

Recon-ng Docs

Shodan API 
🔗 Part 1: GitHub Repositories for Reconnaissance Tools

Here are some powerful open-source tools you can explore:

Tool Name	GitHub Link	Description

theHarvester	🔗 Link	Collects emails, subdomains, hosts, employee names from public sources
Recon-ng	🔗 Link	Web-based recon framework
SpiderFoot	🔗 Link	Automated OSINT tool
Amass	🔗 Link	Performs DNS enumeration
Sublist3r	🔗 Link	Fast subdomain enumeration


You can clone them like this:

git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements.txt
python3 theHarvester.py -d example.com -b google


---

🐍 Part 2: Sample Python Recon Script (Using subprocess + requests)

Here’s an easy Python script that uses subprocess and basic requests to perform recon:

import subprocess
import requests

# Function to run Nmap scan
def run_nmap(ip):
    print(f"[*] Running Nmap scan on {ip}")
    result = subprocess.getoutput(f"nmap -sS -T4 -Pn {ip}")
    print(result)

# Function to do WHOIS Lookup
def whois_lookup(domain):
    print(f"[*] Performing WHOIS lookup for {domain}")
    result = subprocess.getoutput(f"whois {domain}")
    print(result)

# Function to get HTTP Headers
def get_http_headers(url):
    print(f"[*] Fetching headers for {url}")
    headers = requests.get(url).headers
    for k, v in headers.items():
        print(f"{k}: {v}")

# MAIN
domain = "example.com"
ip = "93.184.216.34"  # You can resolve using socket.gethostbyname(domain)
url = f"http://{domain}"

whois_lookup(domain)
get_http_headers(url)
run_nmap(ip)

> ⚠ Note: You must have nmap and whois installed on your system. Run using:



python3 recon_script.py


---

🏗 Part 3: Structure as a Major Project (GitHub)

To make this a complete GitHub-based major project, create the following:

📁 GitHub Folder Structure

RedTeam-Recon-Project/
├── README.md
├── recon_script.py
├── requirements.txt
├── /screenshots
│   └── nmap_output.png
├── /reports
│   └── RedTeam_Report.pdf

📄 Sample README.md

# 🔍 Red Team Reconnaissance Project

This project simulates the reconnaissance phase of a Red Team penetration test on a fictional target.

## 🧰 Tools Used
- Nmap
- Whois
- Python (requests, subprocess)
- theHarvester
- Shodan

Nmap Guide

CVE Info: https://cve.mitre.org/
