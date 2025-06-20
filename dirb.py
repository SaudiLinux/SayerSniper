#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Directory Brute Force Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module performs directory and file brute forcing for web applications.
"""

import requests
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from datetime import datetime
from fake_useragent import UserAgent

# Configure logging
logger = logging.getLogger("sayer.modules.dirb")

# Default wordlist if none provided
DEFAULT_WORDLIST = [
    "", "index.html", "index.php", "index.asp", "index.aspx", "index.jsp",
    "admin", "admin.php", "admin.html", "admin.asp", "admin.aspx",
    "login", "login.php", "login.html", "login.asp", "login.aspx",
    "wp-admin", "wp-login.php", "administrator", "phpmyadmin", "dashboard",
    "upload", "uploads", "files", "images", "img", "css", "js", "fonts",
    "api", "api/v1", "api/v2", "docs", "documentation", "blog", "wp-content",
    "backup", "backups", "bak", "old", "new", "dev", "test", "staging",
    "robots.txt", "sitemap.xml", "config", "configuration", "setup", "install",
    "readme", "readme.html", "readme.txt", "changelog", "changelog.txt",
    "license", "license.txt", "LICENSE", "CHANGELOG", "README", "README.md",
    ".git", ".svn", ".htaccess", ".env", ".DS_Store", "Thumbs.db",
    "server-status", "phpinfo.php", "info.php", "test.php", "db", "database",
    "sql", "mysql", "sqlite", "pgsql", "postgresql", "oracle", "mssql",
    "user", "users", "member", "members", "customer", "customers", "account", "accounts",
    "profile", "profiles", "register", "signup", "signin", "logout", "password", "reset",
    "cart", "checkout", "order", "orders", "payment", "payments", "transaction", "transactions",
    "download", "downloads", "media", "video", "videos", "audio", "music", "podcast",
    "forum", "forums", "board", "boards", "community", "support", "help", "faq",
    "contact", "about", "aboutus", "about-us", "privacy", "terms", "tos", "policy"
]

def check_url(url, timeout=5, allow_redirects=True):
    """
    Check if a URL exists and return its status code and size
    
    Args:
        url (str): URL to check
        timeout (int): Timeout in seconds
        allow_redirects (bool): Whether to follow redirects
        
    Returns:
        tuple: (url, status_code, content_length, content_type)
    """
    try:
        ua = UserAgent()
        headers = {
            "User-Agent": ua.random,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        response = requests.head(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)
        
        # If HEAD request fails, try GET
        if response.status_code >= 400:
            response = requests.get(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers, stream=True)
            # Read only the first 1024 bytes to determine if the page exists
            content = next(response.iter_content(1024), b"")
            response.close()
        
        content_length = int(response.headers.get("Content-Length", 0))
        content_type = response.headers.get("Content-Type", "")
        
        return (url, response.status_code, content_length, content_type)
    except requests.exceptions.RequestException as e:
        logger.debug(f"Error checking URL {url}: {str(e)}")
        return (url, 0, 0, "")

def load_wordlist(wordlist_path):
    """
    Load wordlist from file
    
    Args:
        wordlist_path (str): Path to wordlist file
        
    Returns:
        list: List of words
    """
    try:
        if not os.path.exists(wordlist_path):
            logger.warning(f"Wordlist file not found: {wordlist_path}. Using default wordlist.")
            return DEFAULT_WORDLIST
        
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        logger.warning(f"Error loading wordlist: {str(e)}. Using default wordlist.")
        return DEFAULT_WORDLIST

def run(target, options):
    """
    Run directory brute forcing on the target
    
    Args:
        target (str): Target URL
        options (dict): Additional options
        
    Returns:
        dict: Results of the directory brute forcing
    """
    logger.info(f"Running directory brute forcing for {target}")
    
    results = {
        "module": "dirb",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "directories": [],
        "summary": {}
    }
    
    try:
        # Ensure target has a scheme
        if not target.startswith('http'):
            target = f"http://{target}"
        
        # Ensure target ends with a slash
        if not target.endswith('/'):
            target += '/'
        
        # Get max threads from options or use default
        max_threads = options.get("config", {}).get("general", {}).get("threads", 10)
        
        # Get wordlist from options or use default
        wordlist_path = options.get("config", {}).get("web", {}).get("wordlist", "")
        extensions = options.get("config", {}).get("web", {}).get("extensions", [".php", ".html", ".txt"])
        
        # Load wordlist
        if wordlist_path:
            wordlist = load_wordlist(wordlist_path)
        else:
            wordlist = DEFAULT_WORDLIST
        
        # Generate URLs to check
        urls_to_check = []
        
        # Add base URL
        urls_to_check.append(target)
        
        # Add URLs with wordlist items
        for word in wordlist:
            # Skip empty words
            if not word:
                continue
                
            # Add directory
            if not word.startswith('/'):
                word = f"{word}"
            urls_to_check.append(urljoin(target, word))
            
            # Add directory with trailing slash
            if not word.endswith('/'):
                urls_to_check.append(urljoin(target, f"{word}/"))
            
            # Add with extensions
            for ext in extensions:
                if not word.endswith(ext):
                    urls_to_check.append(urljoin(target, f"{word}{ext}"))
        
        # Remove duplicates
        urls_to_check = list(set(urls_to_check))
        
        # Check URLs in parallel
        found_urls = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            results_iter = executor.map(check_url, urls_to_check)
            for result in results_iter:
                url, status_code, content_length, content_type = result
                
                # Only include URLs that return a valid status code
                if status_code > 0 and status_code < 404:
                    url_info = {
                        "url": url,
                        "status_code": status_code,
                        "size": content_length,
                        "content_type": content_type
                    }
                    found_urls.append(url_info)
                    logger.info(f"Found URL: {url} (Status: {status_code}, Size: {content_length})")
        
        # Sort by URL
        found_urls.sort(key=lambda x: x["url"])
        
        # Add to results
        results["directories"] = found_urls
        
        # Generate summary
        status_counts = {}
        content_types = {}
        total_size = 0
        
        for url_info in found_urls:
            status = url_info["status_code"]
            content_type = url_info["content_type"]
            size = url_info["size"]
            
            if status in status_counts:
                status_counts[status] += 1
            else:
                status_counts[status] = 1
                
            content_type_key = content_type.split(';')[0].strip() if content_type else "unknown"
            if content_type_key in content_types:
                content_types[content_type_key] += 1
            else:
                content_types[content_type_key] = 1
                
            total_size += size
        
        results["summary"] = {
            "total_urls": len(found_urls),
            "total_checked": len(urls_to_check),
            "status_counts": status_counts,
            "content_types": content_types,
            "total_size": total_size
        }
        
    except Exception as e:
        logger.error(f"Error performing directory brute forcing: {str(e)}")
        results["error"] = f"Error performing directory brute forcing: {str(e)}"
    
    return results

# For testing
if __name__ == "__main__":
    import sys
    import urllib3
    
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if len(sys.argv) < 2:
        print("Usage: python dirb.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run(target, {})
    
    print(json.dumps(results, indent=4))