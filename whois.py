#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WHOIS Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module performs WHOIS lookups for domains and IP addresses.
"""

import whois
import socket
import json
import subprocess
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger("sayer.modules.whois")

def run(target, options):
    """
    Run WHOIS lookup on the target
    
    Args:
        target (str): Target domain or IP address
        options (dict): Additional options
        
    Returns:
        dict: Results of the WHOIS lookup
    """
    logger.info(f"Running WHOIS lookup for {target}")
    
    results = {
        "module": "whois",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "data": {},
        "raw": ""
    }
    
    try:
        # Check if target is an IP address
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False
        
        if is_ip:
            # Use subprocess for IP WHOIS
            try:
                whois_data = subprocess.check_output(["whois", target], universal_newlines=True)
                results["raw"] = whois_data
                
                # Parse the output
                parsed_data = {}
                current_section = "general"
                parsed_data[current_section] = {}
                
                for line in whois_data.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('%') or line.startswith('#'):
                        continue
                    
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower().replace(' ', '_')
                        value = value.strip()
                        
                        if key and value:
                            parsed_data[current_section][key] = value
                
                results["data"] = parsed_data
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Error running WHOIS command: {str(e)}")
                results["error"] = f"Error running WHOIS command: {str(e)}"
        else:
            # Use python-whois for domain WHOIS
            domain_info = whois.whois(target)
            
            # Convert to dict and handle datetime objects
            domain_dict = {}
            for key, value in domain_info.items():
                if isinstance(value, datetime):
                    domain_dict[key] = value.isoformat()
                elif isinstance(value, list):
                    # Handle lists of datetime objects
                    new_list = []
                    for item in value:
                        if isinstance(item, datetime):
                            new_list.append(item.isoformat())
                        else:
                            new_list.append(item)
                    domain_dict[key] = new_list
                else:
                    domain_dict[key] = value
            
            results["data"] = domain_dict
            results["raw"] = str(domain_info)
    
    except Exception as e:
        logger.error(f"Error performing WHOIS lookup: {str(e)}")
        results["error"] = f"Error performing WHOIS lookup: {str(e)}"
    
    return results

# For testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python whois.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run(target, {})
    
    print(json.dumps(results, indent=4))