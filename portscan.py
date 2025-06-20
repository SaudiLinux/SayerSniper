#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Port Scanning Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module performs port scanning using nmap.
"""

import nmap
import json
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger("sayer.modules.portscan")

def run(target, options):
    """
    Run port scan on the target
    
    Args:
        target (str): Target IP, domain, or CIDR range
        options (dict): Additional options
        
    Returns:
        dict: Results of the port scan
    """
    logger.info(f"Running port scan for {target}")
    
    results = {
        "module": "portscan",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "hosts": [],
        "summary": {}
    }
    
    try:
        # Initialize nmap scanner
        nm = nmap.PortScanner()
        
        # Determine scan type
        scan_type = options.get("scan_type", "basic")
        
        if scan_type == "basic":
            # Basic scan: Common ports, service detection
            logger.info("Performing basic port scan")
            nm.scan(target, arguments="-sV -F -T4")
        elif scan_type == "comprehensive":
            # Comprehensive scan: All ports, service detection, OS detection, scripts
            logger.info("Performing comprehensive port scan")
            nm.scan(target, arguments="-sV -sC -O -p- -T4")
        else:
            # Default scan
            logger.info("Performing default port scan")
            nm.scan(target, arguments="-sV")
        
        # Process results
        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "hostname": "",
                "state": "",
                "os": [],
                "ports": []
            }
            
            # Get hostname
            if 'hostnames' in nm[host] and nm[host]['hostnames']:
                for hostname in nm[host]['hostnames']:
                    if 'name' in hostname and hostname['name']:
                        host_info["hostname"] = hostname['name']
                        break
            
            # Get host state
            if 'status' in nm[host] and 'state' in nm[host]['status']:
                host_info["state"] = nm[host]['status']['state']
            
            # Get OS information
            if 'osmatch' in nm[host]:
                for os in nm[host]['osmatch']:
                    os_info = {
                        "name": os.get('name', ''),
                        "accuracy": os.get('accuracy', ''),
                        "type": ""
                    }
                    
                    if 'osclass' in os and os['osclass']:
                        os_info["type"] = os['osclass'][0].get('type', '') if os['osclass'][0] else ''
                    
                    host_info["os"].append(os_info)
            
            # Get port information
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    port_info = {
                        "port": port,
                        "state": nm[host]['tcp'][port]['state'],
                        "service": nm[host]['tcp'][port]['name'],
                        "product": nm[host]['tcp'][port].get('product', ''),
                        "version": nm[host]['tcp'][port].get('version', ''),
                        "extrainfo": nm[host]['tcp'][port].get('extrainfo', '')
                    }
                    
                    host_info["ports"].append(port_info)
            
            if 'udp' in nm[host]:
                for port in nm[host]['udp']:
                    port_info = {
                        "port": port,
                        "state": nm[host]['udp'][port]['state'],
                        "service": nm[host]['udp'][port]['name'],
                        "product": nm[host]['udp'][port].get('product', ''),
                        "version": nm[host]['udp'][port].get('version', ''),
                        "extrainfo": nm[host]['udp'][port].get('extrainfo', '')
                    }
                    
                    host_info["ports"].append(port_info)
            
            results["hosts"].append(host_info)
        
        # Generate summary
        total_hosts = len(nm.all_hosts())
        up_hosts = len([host for host in nm.all_hosts() if nm[host].state() == 'up'])
        total_ports = sum(len(host["ports"]) for host in results["hosts"])
        open_ports = sum(1 for host in results["hosts"] for port in host["ports"] if port["state"] == "open")
        
        results["summary"] = {
            "total_hosts": total_hosts,
            "up_hosts": up_hosts,
            "total_ports": total_ports,
            "open_ports": open_ports
        }
        
    except Exception as e:
        logger.error(f"Error performing port scan: {str(e)}")
        results["error"] = f"Error performing port scan: {str(e)}"
    
    return results

# For testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python portscan.py <target> [basic|comprehensive]")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "basic"
    
    options = {"scan_type": scan_type}
    results = run(target, options)
    
    print(json.dumps(results, indent=4))