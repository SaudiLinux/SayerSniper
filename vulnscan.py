#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Vulnerability Scanner Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module integrates with various vulnerability scanning tools to identify security issues.
"""

import subprocess
import json
import logging
import os
import re
import tempfile
from datetime import datetime
from xml.etree import ElementTree as ET

# Configure logging
logger = logging.getLogger("sayer.modules.vulnscan")

def run_nmap_vuln_scan(target, options):
    """
    Run Nmap vulnerability scanning scripts
    
    Args:
        target (str): Target IP or hostname
        options (dict): Additional options
        
    Returns:
        dict: Results of the vulnerability scan
    """
    logger.info(f"Running Nmap vulnerability scan for {target}")
    
    results = {}
    
    try:
        # Create temporary file for output
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
        temp_file.close()
        
        # Build Nmap command
        cmd = [
            "nmap", "-sV", "--script=vuln", "-oX", temp_file.name
        ]
        
        # Add additional options
        if "ports" in options:
            cmd.append(f"-p{options['ports']}")
        else:
            cmd.append("-p1-1000")
            
        # Add target
        cmd.append(target)
        
        # Run Nmap
        logger.debug(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Nmap vulnerability scan failed: {stderr.decode()}")
            results["error"] = f"Nmap vulnerability scan failed: {stderr.decode()}"
            return results
        
        # Parse XML output
        tree = ET.parse(temp_file.name)
        root = tree.getroot()
        
        # Extract vulnerability information
        vulns = []
        
        for host in root.findall("host"):
            ip = host.find("address").get("addr")
            
            for port in host.findall("ports/port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                service = port.find("service")
                
                if service is not None:
                    service_name = service.get("name")
                    service_product = service.get("product", "")
                    service_version = service.get("version", "")
                else:
                    service_name = "unknown"
                    service_product = ""
                    service_version = ""
                
                # Find script outputs for vulnerabilities
                for script in port.findall("script"):
                    script_id = script.get("id")
                    output = script.get("output")
                    
                    # Extract CVE IDs
                    cve_ids = re.findall(r"CVE-\d{4}-\d+", output)
                    
                    # Determine severity based on script id or output
                    severity = "unknown"
                    if "CRITICAL" in output or "critical" in output:
                        severity = "critical"
                    elif "HIGH" in output or "high" in output:
                        severity = "high"
                    elif "MEDIUM" in output or "medium" in output:
                        severity = "medium"
                    elif "LOW" in output or "low" in output:
                        severity = "low"
                    elif "INFO" in output or "info" in output:
                        severity = "info"
                    
                    vuln = {
                        "ip": ip,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                        "script_id": script_id,
                        "output": output,
                        "cve_ids": cve_ids,
                        "severity": severity
                    }
                    
                    vulns.append(vuln)
        
        # Clean up temporary file
        os.unlink(temp_file.name)
        
        # Add results
        results["nmap_vuln"] = vulns
        
    except Exception as e:
        logger.error(f"Error running Nmap vulnerability scan: {str(e)}")
        results["error"] = f"Error running Nmap vulnerability scan: {str(e)}"
    
    return results

def run_nikto_scan(target, options):
    """
    Run Nikto web vulnerability scanner
    
    Args:
        target (str): Target URL
        options (dict): Additional options
        
    Returns:
        dict: Results of the Nikto scan
    """
    logger.info(f"Running Nikto scan for {target}")
    
    results = {}
    
    try:
        # Create temporary file for output
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        temp_file.close()
        
        # Ensure target has a scheme
        if not target.startswith('http'):
            target = f"http://{target}"
        
        # Build Nikto command
        cmd = [
            "nikto", "-h", target, "-Format", "json", "-output", temp_file.name
        ]
        
        # Add additional options
        if "port" in options:
            cmd.extend(["-p", str(options["port"])])
        
        # Run Nikto
        logger.debug(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            logger.error(f"Nikto scan failed: {stderr.decode()}")
            results["error"] = f"Nikto scan failed: {stderr.decode()}"
            return results
        
        # Parse JSON output
        with open(temp_file.name, 'r') as f:
            nikto_results = json.load(f)
        
        # Clean up temporary file
        os.unlink(temp_file.name)
        
        # Extract vulnerability information
        vulns = []
        
        if "vulnerabilities" in nikto_results:
            for vuln in nikto_results["vulnerabilities"]:
                # Determine severity based on OSVDB ID or description
                severity = "medium"  # Default severity
                if "HIGH" in vuln.get("message", "") or "high" in vuln.get("message", ""):
                    severity = "high"
                elif "MEDIUM" in vuln.get("message", "") or "medium" in vuln.get("message", ""):
                    severity = "medium"
                elif "LOW" in vuln.get("message", "") or "low" in vuln.get("message", ""):
                    severity = "low"
                elif "INFO" in vuln.get("message", "") or "info" in vuln.get("message", ""):
                    severity = "info"
                
                vuln_info = {
                    "id": vuln.get("id", ""),
                    "osvdb": vuln.get("osvdb", ""),
                    "message": vuln.get("message", ""),
                    "url": vuln.get("url", ""),
                    "severity": severity
                }
                
                vulns.append(vuln_info)
        
        # Add results
        results["nikto"] = vulns
        
    except Exception as e:
        logger.error(f"Error running Nikto scan: {str(e)}")
        results["error"] = f"Error running Nikto scan: {str(e)}"
    
    return results

def run_sqlmap_scan(target, options):
    """
    Run SQLMap to detect SQL injection vulnerabilities
    
    Args:
        target (str): Target URL
        options (dict): Additional options
        
    Returns:
        dict: Results of the SQLMap scan
    """
    logger.info(f"Running SQLMap scan for {target}")
    
    results = {}
    
    try:
        # Create temporary directory for output
        temp_dir = tempfile.mkdtemp()
        
        # Ensure target has a scheme
        if not target.startswith('http'):
            target = f"http://{target}"
        
        # Build SQLMap command
        cmd = [
            "sqlmap", "-u", target, "--batch", "--output-dir", temp_dir,
            "--forms", "--crawl=1", "--level=1", "--risk=1"
        ]
        
        # Run SQLMap
        logger.debug(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # Parse output
        output = stdout.decode()
        
        # Extract vulnerability information
        vulns = []
        
        # Check if SQL injection was found
        if "is vulnerable to SQL injection" in output:
            # Extract details
            for line in output.split("\n"):
                if "Parameter:" in line and "Type:" in line:
                    parameter = re.search(r"Parameter: ([^\s]+)", line)
                    injection_type = re.search(r"Type: ([^\s]+)", line)
                    
                    if parameter and injection_type:
                        vuln_info = {
                            "parameter": parameter.group(1),
                            "type": injection_type.group(1),
                            "url": target,
                            "severity": "high",  # SQL injection is typically high severity
                            "description": f"SQL injection vulnerability found in parameter {parameter.group(1)}"
                        }
                        
                        vulns.append(vuln_info)
        
        # Add results
        results["sqlmap"] = vulns
        
        # Clean up temporary directory
        import shutil
        shutil.rmtree(temp_dir)
        
    except Exception as e:
        logger.error(f"Error running SQLMap scan: {str(e)}")
        results["error"] = f"Error running SQLMap scan: {str(e)}"
    
    return results

def run(target, options):
    """
    Run vulnerability scanning on the target
    
    Args:
        target (str): Target IP, hostname, or URL
        options (dict): Additional options
        
    Returns:
        dict: Results of the vulnerability scanning
    """
    logger.info(f"Running vulnerability scanning for {target}")
    
    results = {
        "module": "vulnscan",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": [],
        "summary": {}
    }
    
    try:
        # Determine scan type based on target
        is_web = False
        if target.startswith('http') or options.get("scan_type") == "web":
            is_web = True
        
        # Run appropriate scanners
        if is_web:
            # Run web vulnerability scanners
            nikto_results = run_nikto_scan(target, options)
            if "nikto" in nikto_results:
                results["vulnerabilities"].extend(nikto_results["nikto"])
            
            sqlmap_results = run_sqlmap_scan(target, options)
            if "sqlmap" in sqlmap_results:
                results["vulnerabilities"].extend(sqlmap_results["sqlmap"])
        
        # Always run Nmap vulnerability scan
        nmap_results = run_nmap_vuln_scan(target, options)
        if "nmap_vuln" in nmap_results:
            results["vulnerabilities"].extend(nmap_results["nmap_vuln"])
        
        # Generate summary
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0
        }
        
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity", "unknown").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["unknown"] += 1
        
        results["summary"] = {
            "total_vulnerabilities": len(results["vulnerabilities"]),
            "severity_counts": severity_counts,
            "scanners_used": ["nmap_vuln"] + (["nikto", "sqlmap"] if is_web else [])
        }
        
    except Exception as e:
        logger.error(f"Error performing vulnerability scanning: {str(e)}")
        results["error"] = f"Error performing vulnerability scanning: {str(e)}"
    
    return results

# For testing
if __name__ == "__main__":
    import sys
    import urllib3
    
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python vulnscan.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run(target, {})
    
    print(json.dumps(results, indent=4))