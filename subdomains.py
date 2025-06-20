#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Subdomain Enumeration Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module performs subdomain enumeration for domains.
"""

import dns.resolver
import socket
import json
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Configure logging
logger = logging.getLogger("sayer.modules.subdomains")

# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "dns", "host", "mail1", "mx", "support", "dev", "web", "api", "cdn",
    "app", "proxy", "admin", "news", "connect", "ns", "download", "demo",
    "docs", "status", "static", "media", "beta", "forum", "img", "mobile",
    "search", "ww1", "intranet", "store", "files", "direct", "info", "access",
    "backup", "gateway", "services", "login", "cloud", "stage", "git", "wiki",
    "help", "db", "dashboard", "data", "auth", "cp", "exchange", "office",
    "monitor", "stats", "internal", "server1", "server2", "staging", "video",
    "images", "analytics", "assets", "content", "ads", "legacy", "new", "old",
    "chat", "crm", "autodiscover", "autoconfig", "meet", "calendar", "games",
    "tv", "translate", "careers", "research", "whm", "panel", "cvs", "svn",
    "git", "jenkins", "redmine", "jira", "confluence", "lists", "spam", "mx1",
    "mx2", "ns3", "ns4", "dns1", "dns2", "dns3", "dns4", "ldap", "puppet",
    "chef", "gw", "sip", "voip", "traffic", "events", "accounts", "customers"
]

def resolve_subdomain(subdomain, timeout=5):
    """
    Resolve a subdomain to an IP address
    
    Args:
        subdomain (str): Subdomain to resolve
        timeout (int): Timeout in seconds
        
    Returns:
        str or None: IP address if resolved, None otherwise
    """
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except (socket.gaierror, socket.herror, socket.timeout):
        return None

def check_subdomain_exists(subdomain):
    """
    Check if a subdomain exists by resolving it
    
    Args:
        subdomain (str): Subdomain to check
        
    Returns:
        tuple or None: (subdomain, ip) if exists, None otherwise
    """
    ip = resolve_subdomain(subdomain)
    if ip:
        logger.info(f"Found subdomain: {subdomain} ({ip})")
        return (subdomain, ip)
    return None

def run(target, options):
    """
    Run subdomain enumeration on the target
    
    Args:
        target (str): Target domain
        options (dict): Additional options
        
    Returns:
        dict: Results of the subdomain enumeration
    """
    logger.info(f"Running subdomain enumeration for {target}")
    
    results = {
        "module": "subdomains",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "subdomains": [],
        "summary": {}
    }
    
    try:
        # Check if target is a domain (not an IP)
        try:
            socket.inet_aton(target)
            logger.warning(f"Target {target} is an IP address, not a domain. Skipping subdomain enumeration.")
            results["error"] = "Target is an IP address, not a domain."
            return results
        except socket.error:
            # It's not an IP, continue
            pass
        
        # Remove http/https prefix if present
        if target.startswith("http://"):
            target = target[7:]
        elif target.startswith("https://"):
            target = target[8:]
        
        # Remove path if present
        target = target.split("/")[0]
        
        # Get max threads from options or use default
        max_threads = options.get("config", {}).get("general", {}).get("threads", 10)
        
        # Get wordlist from options or use default
        wordlist = options.get("wordlist", COMMON_SUBDOMAINS)
        
        # Generate subdomains to check
        subdomains_to_check = [f"{sub}.{target}" for sub in wordlist]
        
        # Add the base domain
        subdomains_to_check.append(target)
        
        # Try to get additional subdomains from Certificate Transparency logs
        try:
            ct_url = f"https://crt.sh/?q=%.{target}&output=json"
            response = requests.get(ct_url, timeout=10)
            if response.status_code == 200:
                try:
                    cert_data = response.json()
                    for entry in cert_data:
                        if "name_value" in entry:
                            domains = entry["name_value"].split("\n")
                            for domain in domains:
                                if domain.endswith(f".{target}") or domain == target:
                                    if domain not in subdomains_to_check:
                                        subdomains_to_check.append(domain)
                except Exception as e:
                    logger.warning(f"Error parsing certificate data: {str(e)}")
        except Exception as e:
            logger.warning(f"Error fetching certificate data: {str(e)}")
        
        # Check subdomains in parallel
        found_subdomains = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            results_iter = executor.map(check_subdomain_exists, subdomains_to_check)
            for result in results_iter:
                if result:
                    found_subdomains.append(result)
        
        # Process results
        for subdomain, ip in found_subdomains:
            subdomain_info = {
                "name": subdomain,
                "ip": ip
            }
            results["subdomains"].append(subdomain_info)
        
        # Generate summary
        results["summary"] = {
            "total_subdomains": len(results["subdomains"]),
            "total_checked": len(subdomains_to_check)
        }
        
    except Exception as e:
        logger.error(f"Error performing subdomain enumeration: {str(e)}")
        results["error"] = f"Error performing subdomain enumeration: {str(e)}"
    
    return results

# For testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python subdomains.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run(target, {})
    
    print(json.dumps(results, indent=4))