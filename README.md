# redteamreport-
"Simulated Reconnaissance Report for Penetration Testing Project" 

 Sample Python Recon Script (Using subprocess + requests)

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


CVE Info: https://cve.mitre.org/
