#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shodan Integration Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module integrates with the Shodan API to gather additional information about targets.
"""

import json
import logging
import socket
from datetime import datetime
import requests

# Configure logging
logger = logging.getLogger("sayer.modules.shodan")

# Shodan API endpoints
SHODAN_HOST_API = "https://api.shodan.io/shodan/host/{ip}?key={api_key}"
SHODAN_SEARCH_API = "https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
SHODAN_DNS_API = "https://api.shodan.io/dns/resolve?hostnames={hostnames}&key={api_key}"
SHODAN_REVERSE_DNS_API = "https://api.shodan.io/dns/reverse?ips={ips}&key={api_key}"

def resolve_hostname(hostname):
    """
    Resolve hostname to IP address
    
    Args:
        hostname (str): Hostname to resolve
        
    Returns:
        str: IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def get_host_info(ip, api_key):
    """
    Get information about a host from Shodan
    
    Args:
        ip (str): IP address
        api_key (str): Shodan API key
        
    Returns:
        dict: Host information
    """
    try:
        url = SHODAN_HOST_API.format(ip=ip, api_key=api_key)
        response = requests.get(url)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Shodan API error: {response.status_code} - {response.text}")
            return {"error": f"Shodan API error: {response.status_code} - {response.text}"}
    
    except Exception as e:
        logger.error(f"Error getting host info from Shodan: {str(e)}")
        return {"error": f"Error getting host info from Shodan: {str(e)}"}

def search_shodan(query, api_key, limit=100):
    """
    Search Shodan for hosts matching a query
    
    Args:
        query (str): Search query
        api_key (str): Shodan API key
        limit (int): Maximum number of results to return
        
    Returns:
        dict: Search results
    """
    try:
        url = SHODAN_SEARCH_API.format(query=query, api_key=api_key)
        response = requests.get(url)
        
        if response.status_code == 200:
            results = response.json()
            
            # Limit the number of results
            if "matches" in results and len(results["matches"]) > limit:
                results["matches"] = results["matches"][:limit]
            
            return results
        else:
            logger.error(f"Shodan API error: {response.status_code} - {response.text}")
            return {"error": f"Shodan API error: {response.status_code} - {response.text}"}
    
    except Exception as e:
        logger.error(f"Error searching Shodan: {str(e)}")
        return {"error": f"Error searching Shodan: {str(e)}"}

def resolve_dns(hostnames, api_key):
    """
    Resolve hostnames to IP addresses using Shodan
    
    Args:
        hostnames (list): List of hostnames to resolve
        api_key (str): Shodan API key
        
    Returns:
        dict: Mapping of hostnames to IP addresses
    """
    try:
        # Join hostnames with comma
        hostnames_str = ",".join(hostnames)
        
        url = SHODAN_DNS_API.format(hostnames=hostnames_str, api_key=api_key)
        response = requests.get(url)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Shodan API error: {response.status_code} - {response.text}")
            return {"error": f"Shodan API error: {response.status_code} - {response.text}"}
    
    except Exception as e:
        logger.error(f"Error resolving DNS with Shodan: {str(e)}")
        return {"error": f"Error resolving DNS with Shodan: {str(e)}"}

def reverse_dns(ips, api_key):
    """
    Resolve IP addresses to hostnames using Shodan
    
    Args:
        ips (list): List of IP addresses to resolve
        api_key (str): Shodan API key
        
    Returns:
        dict: Mapping of IP addresses to hostnames
    """
    try:
        # Join IPs with comma
        ips_str = ",".join(ips)
        
        url = SHODAN_REVERSE_DNS_API.format(ips=ips_str, api_key=api_key)
        response = requests.get(url)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Shodan API error: {response.status_code} - {response.text}")
            return {"error": f"Shodan API error: {response.status_code} - {response.text}"}
    
    except Exception as e:
        logger.error(f"Error resolving reverse DNS with Shodan: {str(e)}")
        return {"error": f"Error resolving reverse DNS with Shodan: {str(e)}"}

def extract_vulnerabilities(host_info):
    """
    Extract vulnerabilities from Shodan host information
    
    Args:
        host_info (dict): Shodan host information
        
    Returns:
        list: List of vulnerabilities
    """
    vulnerabilities = []
    
    try:
        # Check if host info contains vulnerabilities
        if "vulns" in host_info:
            for vuln_id, vuln_info in host_info["vulns"].items():
                # Determine severity based on CVSS score
                cvss = vuln_info.get("cvss", 0)
                severity = "unknown"
                
                if cvss >= 9.0:
                    severity = "critical"
                elif cvss >= 7.0:
                    severity = "high"
                elif cvss >= 4.0:
                    severity = "medium"
                elif cvss > 0:
                    severity = "low"
                
                vuln = {
                    "id": vuln_id,
                    "cvss": cvss,
                    "summary": vuln_info.get("summary", ""),
                    "references": vuln_info.get("references", []),
                    "severity": severity
                }
                
                vulnerabilities.append(vuln)
    
    except Exception as e:
        logger.error(f"Error extracting vulnerabilities: {str(e)}")
    
    return vulnerabilities

def extract_services(host_info):
    """
    Extract services from Shodan host information
    
    Args:
        host_info (dict): Shodan host information
        
    Returns:
        list: List of services
    """
    services = []
    
    try:
        # Check if host info contains data
        if "data" in host_info:
            for service in host_info["data"]:
                service_info = {
                    "port": service.get("port", 0),
                    "protocol": service.get("transport", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "module": service.get("_shodan", {}).get("module", ""),
                    "hostnames": service.get("hostnames", []),
                    "domains": service.get("domains", [])
                }
                
                # Add banner if available
                if "data" in service:
                    service_info["banner"] = service["data"]
                
                services.append(service_info)
    
    except Exception as e:
        logger.error(f"Error extracting services: {str(e)}")
    
    return services

def run(target, options):
    """
    Run Shodan scanning on the target
    
    Args:
        target (str): Target hostname or IP
        options (dict): Additional options
        
    Returns:
        dict: Results of the Shodan scanning
    """
    logger.info(f"Running Shodan scanning for {target}")
    
    results = {
        "module": "shodan",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "host_info": {},
        "services": [],
        "vulnerabilities": [],
        "summary": {}
    }
    
    try:
        # Get API key from options
        api_key = options.get("config", {}).get("api_keys", {}).get("shodan", "")
        
        if not api_key:
            logger.error("Shodan API key not provided")
            results["error"] = "Shodan API key not provided"
            return results
        
        # Determine if target is an IP address or hostname
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False
        
        # If target is a hostname, resolve it to an IP address
        if not is_ip:
            ip = resolve_hostname(target)
            if not ip:
                logger.error(f"Could not resolve hostname: {target}")
                results["error"] = f"Could not resolve hostname: {target}"
                return results
        else:
            ip = target
        
        # Get host information from Shodan
        host_info = get_host_info(ip, api_key)
        
        if "error" in host_info:
            results["error"] = host_info["error"]
            return results
        
        # Extract information from host info
        results["host_info"] = {
            "ip": ip,
            "hostnames": host_info.get("hostnames", []),
            "domains": host_info.get("domains", []),
            "country": host_info.get("country_name", ""),
            "city": host_info.get("city", ""),
            "org": host_info.get("org", ""),
            "isp": host_info.get("isp", ""),
            "asn": host_info.get("asn", ""),
            "last_update": host_info.get("last_update", ""),
            "os": host_info.get("os", "")
        }
        
        # Extract services
        results["services"] = extract_services(host_info)
        
        # Extract vulnerabilities
        results["vulnerabilities"] = extract_vulnerabilities(host_info)
        
        # Generate summary
        summary = {
            "ip": ip,
            "hostnames": host_info.get("hostnames", []),
            "domains": host_info.get("domains", []),
            "country": host_info.get("country_name", ""),
            "org": host_info.get("org", ""),
            "total_services": len(results["services"]),
            "total_vulnerabilities": len(results["vulnerabilities"])
        }
        
        # Add severity counts
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0
        }
        
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity", "unknown").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        summary["severity_counts"] = severity_counts
        
        # Add open ports
        open_ports = [service["port"] for service in results["services"]]
        summary["open_ports"] = open_ports
        
        results["summary"] = summary
        
    except Exception as e:
        logger.error(f"Error performing Shodan scanning: {str(e)}")
        results["error"] = f"Error performing Shodan scanning: {str(e)}"
    
    return results

# For testing
if __name__ == "__main__":
    import sys
    import urllib3
    
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 3:
        print("Usage: python shodan.py <target> <api_key>")
        sys.exit(1)
    
    target = sys.argv[1]
    api_key = sys.argv[2]
    
    results = run(target, {"config": {"api_keys": {"shodan": api_key}}})
    
    print(json.dumps(results, indent=4))