#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSL/TLS Scanner Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module analyzes SSL/TLS configurations and certificates for security issues.
"""

import socket
import ssl
import json
import logging
import subprocess
from datetime import datetime
import tempfile
import os
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# Configure logging
logger = logging.getLogger("sayer.modules.ssl")

# Define weak ciphers and protocols
WEAK_CIPHERS = [
    "NULL", "EXPORT", "DES", "RC4", "MD5", "aNULL", "ADH", "IDEA"
]

WEAK_PROTOCOLS = [
    "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"
]

def get_certificate_info(hostname, port=443):
    """
    Get SSL certificate information
    
    Args:
        hostname (str): Target hostname
        port (int): Target port
        
    Returns:
        dict: Certificate information
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # Get certificate details
                subject = cert.subject
                issuer = cert.issuer
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
                serial = cert.serial_number
                version = cert.version
                
                # Get subject alternative names
                san = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    san = [name.value for name in san_ext.value]
                except x509.extensions.ExtensionNotFound:
                    pass
                
                # Get common name
                common_name = ""
                try:
                    common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except IndexError:
                    pass
                
                # Get issuer common name
                issuer_common_name = ""
                try:
                    issuer_common_name = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                except IndexError:
                    pass
                
                # Get signature algorithm
                signature_algorithm = cert.signature_algorithm_oid._name
                
                # Check if certificate is self-signed
                is_self_signed = (subject == issuer)
                
                # Check if certificate is expired
                now = datetime.now()
                is_expired = (now < not_before or now > not_after)
                
                # Calculate days until expiration
                days_until_expiration = (not_after - now).days
                
                # Get cipher suite
                cipher = ssock.cipher()
                
                return {
                    "common_name": common_name,
                    "issuer": issuer_common_name,
                    "subject_alternative_names": san,
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "days_until_expiration": days_until_expiration,
                    "serial_number": str(serial),
                    "version": version.name,
                    "signature_algorithm": signature_algorithm,
                    "is_self_signed": is_self_signed,
                    "is_expired": is_expired,
                    "cipher_suite": {
                        "name": cipher[0],
                        "version": cipher[1],
                        "bits": cipher[2]
                    }
                }
    except Exception as e:
        logger.error(f"Error getting certificate info: {str(e)}")
        return {"error": f"Error getting certificate info: {str(e)}"}

def run_sslscan(hostname, port=443):
    """
    Run sslscan to check for SSL/TLS vulnerabilities
    
    Args:
        hostname (str): Target hostname
        port (int): Target port
        
    Returns:
        dict: SSLScan results
    """
    try:
        # Create temporary file for output
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
        temp_file.close()
        
        # Run sslscan
        cmd = ["sslscan", "--xml=" + temp_file.name, f"{hostname}:{port}"]
        logger.debug(f"Running command: {' '.join(cmd)}")
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            logger.error(f"SSLScan failed: {stderr.decode()}")
            return {"error": f"SSLScan failed: {stderr.decode()}"}
        
        # Parse XML output
        with open(temp_file.name, 'r') as f:
            xml_content = f.read()
        
        # Clean up temporary file
        os.unlink(temp_file.name)
        
        # Extract information from XML
        results = {}
        
        # Extract supported protocols
        protocols = []
        for match in re.finditer(r'<protocol type="([^"]+)" enabled="([^"]+)"', xml_content):
            protocol_type = match.group(1)
            enabled = match.group(2) == "1"
            protocols.append({"name": protocol_type, "enabled": enabled})
        
        results["protocols"] = protocols
        
        # Extract supported ciphers
        ciphers = []
        for match in re.finditer(r'<cipher status="([^"]+)" sslversion="([^"]+)" bits="([^"]+)" cipher="([^"]+)" strength="([^"]+)"', xml_content):
            status = match.group(1)
            ssl_version = match.group(2)
            bits = match.group(3)
            cipher_name = match.group(4)
            strength = match.group(5)
            
            ciphers.append({
                "status": status,
                "ssl_version": ssl_version,
                "bits": bits,
                "name": cipher_name,
                "strength": strength
            })
        
        results["ciphers"] = ciphers
        
        # Extract vulnerabilities
        vulnerabilities = []
        
        # Check for Heartbleed
        heartbleed_match = re.search(r'<heartbleed[^>]+>(.*?)</heartbleed>', xml_content, re.DOTALL)
        if heartbleed_match and "vulnerable" in heartbleed_match.group(1).lower():
            vulnerabilities.append({
                "name": "Heartbleed",
                "severity": "critical",
                "description": "Server is vulnerable to the Heartbleed attack (CVE-2014-0160)"
            })
        
        # Check for POODLE
        if any(p["name"] == "SSLv3" and p["enabled"] for p in protocols):
            vulnerabilities.append({
                "name": "POODLE",
                "severity": "high",
                "description": "Server supports SSLv3, which is vulnerable to the POODLE attack (CVE-2014-3566)"
            })
        
        # Check for FREAK
        if any("EXPORT" in c["name"] for c in ciphers):
            vulnerabilities.append({
                "name": "FREAK",
                "severity": "high",
                "description": "Server supports export-grade ciphers, which are vulnerable to the FREAK attack (CVE-2015-0204)"
            })
        
        # Check for DROWN
        if any(p["name"] == "SSLv2" and p["enabled"] for p in protocols):
            vulnerabilities.append({
                "name": "DROWN",
                "severity": "high",
                "description": "Server supports SSLv2, which is vulnerable to the DROWN attack (CVE-2016-0800)"
            })
        
        # Check for weak ciphers
        weak_cipher_found = False
        for cipher in ciphers:
            for weak_cipher in WEAK_CIPHERS:
                if weak_cipher in cipher["name"]:
                    weak_cipher_found = True
                    break
            if weak_cipher_found:
                break
        
        if weak_cipher_found:
            vulnerabilities.append({
                "name": "Weak Ciphers",
                "severity": "medium",
                "description": "Server supports weak ciphers that may be vulnerable to attacks"
            })
        
        # Check for weak protocols
        weak_protocol_found = False
        for protocol in protocols:
            if protocol["name"] in WEAK_PROTOCOLS and protocol["enabled"]:
                weak_protocol_found = True
                break
        
        if weak_protocol_found:
            vulnerabilities.append({
                "name": "Weak Protocols",
                "severity": "medium",
                "description": "Server supports weak protocols that may be vulnerable to attacks"
            })
        
        results["vulnerabilities"] = vulnerabilities
        
        return results
    except Exception as e:
        logger.error(f"Error running sslscan: {str(e)}")
        return {"error": f"Error running sslscan: {str(e)}"}

def run(target, options):
    """
    Run SSL/TLS scanning on the target
    
    Args:
        target (str): Target hostname or IP
        options (dict): Additional options
        
    Returns:
        dict: Results of the SSL/TLS scanning
    """
    logger.info(f"Running SSL/TLS scanning for {target}")
    
    results = {
        "module": "ssl",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "certificate": {},
        "scan_results": {},
        "summary": {}
    }
    
    try:
        # Extract hostname and port
        hostname = target
        port = 443
        
        if ":" in target:
            hostname, port_str = target.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                pass
        
        # Get certificate information
        cert_info = get_certificate_info(hostname, port)
        results["certificate"] = cert_info
        
        # Run sslscan
        sslscan_results = run_sslscan(hostname, port)
        results["scan_results"] = sslscan_results
        
        # Generate summary
        summary = {
            "hostname": hostname,
            "port": port,
            "certificate_common_name": cert_info.get("common_name", ""),
            "certificate_issuer": cert_info.get("issuer", ""),
            "certificate_expiry": cert_info.get("not_after", ""),
            "days_until_expiration": cert_info.get("days_until_expiration", 0),
            "is_self_signed": cert_info.get("is_self_signed", False),
            "is_expired": cert_info.get("is_expired", False),
            "signature_algorithm": cert_info.get("signature_algorithm", ""),
            "supported_protocols": [p["name"] for p in sslscan_results.get("protocols", []) if p["enabled"]],
            "vulnerabilities": sslscan_results.get("vulnerabilities", [])
        }
        
        # Add severity counts
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in sslscan_results.get("vulnerabilities", []):
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        summary["severity_counts"] = severity_counts
        summary["total_vulnerabilities"] = sum(severity_counts.values())
        
        # Add certificate grade based on findings
        grade = "A"
        if cert_info.get("is_expired", False) or cert_info.get("is_self_signed", False):
            grade = "F"
        elif severity_counts["critical"] > 0:
            grade = "F"
        elif severity_counts["high"] > 0:
            grade = "D"
        elif severity_counts["medium"] > 0:
            grade = "C"
        elif severity_counts["low"] > 0:
            grade = "B"
        
        summary["grade"] = grade
        
        results["summary"] = summary
        
    except Exception as e:
        logger.error(f"Error performing SSL/TLS scanning: {str(e)}")
        results["error"] = f"Error performing SSL/TLS scanning: {str(e)}"
    
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
        print("Usage: python ssl.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run(target, {})
    
    print(json.dumps(results, indent=4))