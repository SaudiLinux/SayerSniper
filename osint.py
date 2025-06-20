#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSINT (Open Source Intelligence) Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module gathers open source intelligence about targets.
"""

import json
import logging
import requests
import re
import socket
from datetime import datetime
from bs4 import BeautifulSoup

# Configure logging
logger = logging.getLogger("sayer.modules.osint")

def search_pastebin(query, limit=10):
    """
    Search Pastebin for information related to the target
    
    Args:
        query (str): Search query
        limit (int): Maximum number of results to return
        
    Returns:
        list: Search results
    """
    results = []
    
    try:
        # Use Google dork to search Pastebin
        search_url = f"https://www.google.com/search?q=site:pastebin.com+{query}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        response = requests.get(search_url, headers=headers)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract search results
            for result in soup.select('div.g'):
                title_elem = result.select_one('h3')
                link_elem = result.select_one('a')
                snippet_elem = result.select_one('div.IsZvec')
                
                if title_elem and link_elem and snippet_elem:
                    title = title_elem.get_text()
                    link = link_elem['href']
                    snippet = snippet_elem.get_text()
                    
                    # Clean up link
                    if link.startswith('/url?q='):
                        link = link.split('/url?q=')[1].split('&')[0]
                    
                    results.append({
                        "title": title,
                        "url": link,
                        "snippet": snippet,
                        "source": "pastebin"
                    })
                    
                    if len(results) >= limit:
                        break
    
    except Exception as e:
        logger.error(f"Error searching Pastebin: {str(e)}")
    
    return results

def search_github(query, limit=10):
    """
    Search GitHub for information related to the target
    
    Args:
        query (str): Search query
        limit (int): Maximum number of results to return
        
    Returns:
        list: Search results
    """
    results = []
    
    try:
        # Use GitHub search API
        search_url = f"https://api.github.com/search/code?q={query}"
        
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        response = requests.get(search_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            for item in data.get("items", [])[:limit]:
                results.append({
                    "name": item.get("name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "repository": item.get("repository", {}).get("full_name", ""),
                    "source": "github"
                })
    
    except Exception as e:
        logger.error(f"Error searching GitHub: {str(e)}")
    
    return results

def search_leaked_credentials(domain):
    """
    Search for leaked credentials related to the domain
    
    Args:
        domain (str): Domain to search for
        
    Returns:
        list: Search results
    """
    results = []
    
    try:
        # Use Have I Been Pwned API (note: requires API key for full functionality)
        # This is a placeholder for the actual implementation
        logger.info(f"Searching for leaked credentials for {domain}")
        
        # For demonstration purposes, we'll just return a message
        results.append({
            "message": f"To search for leaked credentials for {domain}, you need to use the Have I Been Pwned API with an API key.",
            "source": "hibp"
        })
    
    except Exception as e:
        logger.error(f"Error searching for leaked credentials: {str(e)}")
    
    return results

def search_social_media(query, limit=10):
    """
    Search social media for information related to the target
    
    Args:
        query (str): Search query
        limit (int): Maximum number of results to return
        
    Returns:
        list: Search results
    """
    results = []
    
    try:
        # Use Google dork to search social media
        social_platforms = ["linkedin.com", "twitter.com", "facebook.com", "instagram.com"]
        
        for platform in social_platforms:
            search_url = f"https://www.google.com/search?q=site:{platform}+{query}"
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            
            response = requests.get(search_url, headers=headers)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract search results
                for result in soup.select('div.g'):
                    title_elem = result.select_one('h3')
                    link_elem = result.select_one('a')
                    snippet_elem = result.select_one('div.IsZvec')
                    
                    if title_elem and link_elem and snippet_elem:
                        title = title_elem.get_text()
                        link = link_elem['href']
                        snippet = snippet_elem.get_text()
                        
                        # Clean up link
                        if link.startswith('/url?q='):
                            link = link.split('/url?q=')[1].split('&')[0]
                        
                        results.append({
                            "title": title,
                            "url": link,
                            "snippet": snippet,
                            "platform": platform,
                            "source": "social_media"
                        })
                        
                        if len(results) >= limit:
                            break
            
            # Respect rate limits
            import time
            time.sleep(2)
    
    except Exception as e:
        logger.error(f"Error searching social media: {str(e)}")
    
    return results

def search_email_addresses(domain, limit=10):
    """
    Search for email addresses related to the domain
    
    Args:
        domain (str): Domain to search for
        limit (int): Maximum number of results to return
        
    Returns:
        list: Email addresses found
    """
    email_addresses = []
    
    try:
        # Use Google dork to search for email addresses
        search_url = f"https://www.google.com/search?q=site:{domain}+email+OR+contact+OR+mailto"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        response = requests.get(search_url, headers=headers)
        
        if response.status_code == 200:
            # Extract email addresses using regex
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = re.findall(email_pattern, response.text)
            
            # Filter emails by domain
            domain_emails = [email for email in emails if domain.lower() in email.lower()]
            
            # Remove duplicates and limit results
            unique_emails = list(set(domain_emails))[:limit]
            
            for email in unique_emails:
                email_addresses.append({
                    "email": email,
                    "source": "google_search"
                })
    
    except Exception as e:
        logger.error(f"Error searching for email addresses: {str(e)}")
    
    return email_addresses

def search_subdomains(domain, limit=100):
    """
    Search for subdomains of the given domain
    
    Args:
        domain (str): Domain to search for
        limit (int): Maximum number of results to return
        
    Returns:
        list: Subdomains found
    """
    subdomains = []
    
    try:
        # Use crt.sh to find subdomains
        search_url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        response = requests.get(search_url)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract unique subdomains
            domain_names = set()
            
            for item in data:
                name_value = item.get("name_value", "")
                
                # Split by newlines and handle wildcards
                for name in name_value.split("\n"):
                    # Remove wildcards
                    if name.startswith("*."):
                        name = name[2:]
                    
                    # Ensure it's a subdomain of the target domain
                    if name.endswith(f".{domain}") and name != domain:
                        domain_names.add(name)
            
            # Convert to list and limit results
            domain_list = list(domain_names)[:limit]
            
            # Resolve IP addresses
            for subdomain in domain_list:
                try:
                    ip = socket.gethostbyname(subdomain)
                    subdomains.append({
                        "subdomain": subdomain,
                        "ip": ip,
                        "source": "crt.sh"
                    })
                except socket.gaierror:
                    subdomains.append({
                        "subdomain": subdomain,
                        "ip": None,
                        "source": "crt.sh"
                    })
    
    except Exception as e:
        logger.error(f"Error searching for subdomains: {str(e)}")
    
    return subdomains

def run(target, options):
    """
    Run OSINT gathering on the target
    
    Args:
        target (str): Target domain, IP, or organization name
        options (dict): Additional options
        
    Returns:
        dict: Results of the OSINT gathering
    """
    logger.info(f"Running OSINT gathering for {target}")
    
    results = {
        "module": "osint",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "pastebin": [],
        "github": [],
        "leaked_credentials": [],
        "social_media": [],
        "email_addresses": [],
        "subdomains": [],
        "summary": {}
    }
    
    try:
        # Determine if target is a domain, IP, or organization name
        is_domain = False
        is_ip = False
        
        # Check if target is an IP address
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            pass
        
        # Check if target is a domain
        if not is_ip and '.' in target and not target.startswith('http'):
            try:
                socket.gethostbyname(target)
                is_domain = True
            except socket.gaierror:
                pass
        
        # If target is a URL, extract the domain
        if target.startswith('http'):
            from urllib.parse import urlparse
            parsed_url = urlparse(target)
            target_domain = parsed_url.netloc
            is_domain = True
        elif is_domain:
            target_domain = target
        else:
            target_domain = None
        
        # Run appropriate OSINT gathering based on target type
        if is_domain or target_domain:
            # Search for subdomains
            results["subdomains"] = search_subdomains(target_domain)
            
            # Search for email addresses
            results["email_addresses"] = search_email_addresses(target_domain)
            
            # Search for leaked credentials
            results["leaked_credentials"] = search_leaked_credentials(target_domain)
        
        # Search Pastebin
        results["pastebin"] = search_pastebin(target)
        
        # Search GitHub
        results["github"] = search_github(target)
        
        # Search social media
        results["social_media"] = search_social_media(target)
        
        # Generate summary
        summary = {
            "target": target,
            "is_domain": is_domain,
            "is_ip": is_ip,
            "total_subdomains": len(results["subdomains"]),
            "total_email_addresses": len(results["email_addresses"]),
            "total_pastebin_results": len(results["pastebin"]),
            "total_github_results": len(results["github"]),
            "total_social_media_results": len(results["social_media"])
        }
        
        # Add domain-specific information
        if is_domain or target_domain:
            summary["domain"] = target_domain
        
        results["summary"] = summary
        
    except Exception as e:
        logger.error(f"Error performing OSINT gathering: {str(e)}")
        results["error"] = f"Error performing OSINT gathering: {str(e)}"
    
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
        print("Usage: python osint.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run(target, {})
    
    print(json.dumps(results, indent=4))