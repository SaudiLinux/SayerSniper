#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WordPress Scanner Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module scans WordPress sites for vulnerabilities, plugins, and themes.
"""

import json
import logging
import subprocess
import tempfile
import os
import re
from datetime import datetime
import requests
from bs4 import BeautifulSoup

# Configure logging
logger = logging.getLogger("sayer.modules.wpscan")

def is_wordpress(url):
    """
    Check if a URL is a WordPress site
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if WordPress, False otherwise
    """
    try:
        # Ensure URL has a scheme
        if not url.startswith('http'):
            url = f"http://{url}"
        
        # Check common WordPress paths
        wp_paths = [
            "/wp-login.php",
            "/wp-admin/",
            "/wp-content/",
            "/wp-includes/"
        ]
        
        for path in wp_paths:
            check_url = url.rstrip('/') + path
            response = requests.head(check_url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                return True
        
        # Check HTML for WordPress meta tags or scripts
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for WordPress meta generator tag
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and 'wordpress' in meta_generator.get('content', '').lower():
                return True
            
            # Check for WordPress scripts
            scripts = soup.find_all('script')
            for script in scripts:
                src = script.get('src', '')
                if 'wp-' in src or 'wordpress' in src:
                    return True
            
            # Check for WordPress CSS
            links = soup.find_all('link')
            for link in links:
                href = link.get('href', '')
                if 'wp-' in href or 'wordpress' in href:
                    return True
        
        return False
    
    except Exception as e:
        logger.error(f"Error checking if site is WordPress: {str(e)}")
        return False

def run_wpscan(url, api_token=None):
    """
    Run WPScan on a WordPress site
    
    Args:
        url (str): URL to scan
        api_token (str): WPScan API token
        
    Returns:
        dict: WPScan results
    """
    try:
        # Create temporary file for output
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        temp_file.close()
        
        # Ensure URL has a scheme
        if not url.startswith('http'):
            url = f"http://{url}"
        
        # Build WPScan command
        cmd = [
            "wpscan", "--url", url, "--format", "json", "--output", temp_file.name,
            "--disable-tls-checks", "--random-user-agent"
        ]
        
        # Add API token if provided
        if api_token:
            cmd.extend(["--api-token", api_token])
        
        # Run WPScan
        logger.debug(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        # Check if WPScan ran successfully
        if process.returncode != 0 and process.returncode != 5:  # Return code 5 means vulnerabilities found
            logger.error(f"WPScan failed: {stderr.decode()}")
            return {"error": f"WPScan failed: {stderr.decode()}"}
        
        # Parse JSON output
        with open(temp_file.name, 'r') as f:
            try:
                wpscan_results = json.load(f)
            except json.JSONDecodeError:
                logger.error("Failed to parse WPScan JSON output")
                return {"error": "Failed to parse WPScan JSON output"}
        
        # Clean up temporary file
        os.unlink(temp_file.name)
        
        return wpscan_results
    
    except Exception as e:
        logger.error(f"Error running WPScan: {str(e)}")
        return {"error": f"Error running WPScan: {str(e)}"}

def extract_vulnerabilities(wpscan_results):
    """
    Extract vulnerabilities from WPScan results
    
    Args:
        wpscan_results (dict): WPScan results
        
    Returns:
        list: List of vulnerabilities
    """
    vulnerabilities = []
    
    try:
        # Check WordPress core vulnerabilities
        if "wordpress" in wpscan_results and "vulnerabilities" in wpscan_results["wordpress"]:
            for vuln in wpscan_results["wordpress"]["vulnerabilities"]:
                vuln_info = {
                    "type": "wordpress_core",
                    "title": vuln.get("title", ""),
                    "fixed_in": vuln.get("fixed_in", ""),
                    "references": vuln.get("references", {}),
                    "severity": "high"  # WordPress core vulnerabilities are typically high severity
                }
                
                vulnerabilities.append(vuln_info)
        
        # Check plugin vulnerabilities
        if "plugins" in wpscan_results:
            for plugin_name, plugin_info in wpscan_results["plugins"].items():
                if "vulnerabilities" in plugin_info:
                    for vuln in plugin_info["vulnerabilities"]:
                        vuln_info = {
                            "type": "plugin",
                            "plugin": plugin_name,
                            "title": vuln.get("title", ""),
                            "fixed_in": vuln.get("fixed_in", ""),
                            "references": vuln.get("references", {}),
                            "severity": "medium"  # Default severity for plugin vulnerabilities
                        }
                        
                        # Adjust severity based on title or description
                        title = vuln.get("title", "").lower()
                        if "rce" in title or "remote code execution" in title or "sql injection" in title:
                            vuln_info["severity"] = "critical"
                        elif "xss" in title or "cross site scripting" in title:
                            vuln_info["severity"] = "high"
                        
                        vulnerabilities.append(vuln_info)
        
        # Check theme vulnerabilities
        if "themes" in wpscan_results:
            for theme_name, theme_info in wpscan_results["themes"].items():
                if "vulnerabilities" in theme_info:
                    for vuln in theme_info["vulnerabilities"]:
                        vuln_info = {
                            "type": "theme",
                            "theme": theme_name,
                            "title": vuln.get("title", ""),
                            "fixed_in": vuln.get("fixed_in", ""),
                            "references": vuln.get("references", {}),
                            "severity": "medium"  # Default severity for theme vulnerabilities
                        }
                        
                        # Adjust severity based on title or description
                        title = vuln.get("title", "").lower()
                        if "rce" in title or "remote code execution" in title or "sql injection" in title:
                            vuln_info["severity"] = "critical"
                        elif "xss" in title or "cross site scripting" in title:
                            vuln_info["severity"] = "high"
                        
                        vulnerabilities.append(vuln_info)
    
    except Exception as e:
        logger.error(f"Error extracting vulnerabilities: {str(e)}")
    
    return vulnerabilities

def extract_plugins(wpscan_results):
    """
    Extract plugins from WPScan results
    
    Args:
        wpscan_results (dict): WPScan results
        
    Returns:
        list: List of plugins
    """
    plugins = []
    
    try:
        if "plugins" in wpscan_results:
            for plugin_name, plugin_info in wpscan_results["plugins"].items():
                plugin = {
                    "name": plugin_name,
                    "version": plugin_info.get("version", {}).get("number", ""),
                    "location": plugin_info.get("location", ""),
                    "outdated": plugin_info.get("outdated", False),
                    "has_vulnerabilities": len(plugin_info.get("vulnerabilities", [])) > 0
                }
                
                plugins.append(plugin)
    
    except Exception as e:
        logger.error(f"Error extracting plugins: {str(e)}")
    
    return plugins

def extract_themes(wpscan_results):
    """
    Extract themes from WPScan results
    
    Args:
        wpscan_results (dict): WPScan results
        
    Returns:
        list: List of themes
    """
    themes = []
    
    try:
        if "themes" in wpscan_results:
            for theme_name, theme_info in wpscan_results["themes"].items():
                theme = {
                    "name": theme_name,
                    "version": theme_info.get("version", {}).get("number", ""),
                    "location": theme_info.get("location", ""),
                    "outdated": theme_info.get("outdated", False),
                    "has_vulnerabilities": len(theme_info.get("vulnerabilities", [])) > 0
                }
                
                themes.append(theme)
    
    except Exception as e:
        logger.error(f"Error extracting themes: {str(e)}")
    
    return themes

def extract_users(wpscan_results):
    """
    Extract users from WPScan results
    
    Args:
        wpscan_results (dict): WPScan results
        
    Returns:
        list: List of users
    """
    users = []
    
    try:
        if "users" in wpscan_results:
            for username, user_info in wpscan_results["users"].items():
                user = {
                    "username": username,
                    "id": user_info.get("id", 0),
                    "found_by": user_info.get("found_by", "")
                }
                
                users.append(user)
    
    except Exception as e:
        logger.error(f"Error extracting users: {str(e)}")
    
    return users

def run(target, options):
    """
    Run WordPress scanning on the target
    
    Args:
        target (str): Target URL
        options (dict): Additional options
        
    Returns:
        dict: Results of the WordPress scanning
    """
    logger.info(f"Running WordPress scanning for {target}")
    
    results = {
        "module": "wpscan",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "is_wordpress": False,
        "wordpress_version": "",
        "plugins": [],
        "themes": [],
        "users": [],
        "vulnerabilities": [],
        "summary": {}
    }
    
    try:
        # Ensure target has a scheme
        if not target.startswith('http'):
            target = f"http://{target}"
        
        # Check if target is a WordPress site
        if not is_wordpress(target):
            logger.info(f"{target} is not a WordPress site")
            results["summary"] = {"message": f"{target} is not a WordPress site"}
            return results
        
        results["is_wordpress"] = True
        
        # Get WPScan API token from options
        api_token = options.get("config", {}).get("api_keys", {}).get("wpscan", "")
        
        # Run WPScan
        wpscan_results = run_wpscan(target, api_token)
        
        if "error" in wpscan_results:
            results["error"] = wpscan_results["error"]
            return results
        
        # Extract WordPress version
        if "wordpress" in wpscan_results and "version" in wpscan_results["wordpress"]:
            results["wordpress_version"] = wpscan_results["wordpress"]["version"].get("number", "")
        
        # Extract plugins
        results["plugins"] = extract_plugins(wpscan_results)
        
        # Extract themes
        results["themes"] = extract_themes(wpscan_results)
        
        # Extract users
        results["users"] = extract_users(wpscan_results)
        
        # Extract vulnerabilities
        results["vulnerabilities"] = extract_vulnerabilities(wpscan_results)
        
        # Generate summary
        summary = {
            "wordpress_version": results["wordpress_version"],
            "total_plugins": len(results["plugins"]),
            "total_themes": len(results["themes"]),
            "total_users": len(results["users"]),
            "total_vulnerabilities": len(results["vulnerabilities"])
        }
        
        # Add severity counts
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        summary["severity_counts"] = severity_counts
        
        # Add vulnerable plugins and themes
        vulnerable_plugins = [p["name"] for p in results["plugins"] if p["has_vulnerabilities"]]
        vulnerable_themes = [t["name"] for t in results["themes"] if t["has_vulnerabilities"]]
        
        summary["vulnerable_plugins"] = vulnerable_plugins
        summary["vulnerable_themes"] = vulnerable_themes
        
        results["summary"] = summary
        
    except Exception as e:
        logger.error(f"Error performing WordPress scanning: {str(e)}")
        results["error"] = f"Error performing WordPress scanning: {str(e)}"
    
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
        print("Usage: python wpscan.py <target> [api_token]")
        sys.exit(1)
    
    target = sys.argv[1]
    api_token = sys.argv[2] if len(sys.argv) > 2 else None
    
    options = {}
    if api_token:
        options = {"config": {"api_keys": {"wpscan": api_token}}}
    
    results = run(target, options)
    
    print(json.dumps(results, indent=4))