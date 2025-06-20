#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Fingerprinting Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module performs web fingerprinting to identify web technologies and versions.
"""

import requests
import json
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from datetime import datetime
from fake_useragent import UserAgent

# Configure logging
logger = logging.getLogger("sayer.modules.webfinger")

# Technology signatures
TECH_SIGNATURES = {
    "WordPress": [
        {"type": "header", "name": "X-Powered-By", "regex": "WordPress"},
        {"type": "meta", "name": "generator", "regex": "WordPress"},
        {"type": "url", "regex": "/wp-content/"},
        {"type": "url", "regex": "/wp-includes/"},
        {"type": "url", "regex": "/wp-admin/"}
    ],
    "Joomla": [
        {"type": "meta", "name": "generator", "regex": "Joomla"},
        {"type": "url", "regex": "/components/"},
        {"type": "url", "regex": "/administrator/"}
    ],
    "Drupal": [
        {"type": "meta", "name": "generator", "regex": "Drupal"},
        {"type": "url", "regex": "/sites/default/"},
        {"type": "url", "regex": "/modules/"}
    ],
    "Magento": [
        {"type": "cookie", "name": "frontend", "regex": ""},
        {"type": "url", "regex": "/skin/frontend/"},
        {"type": "url", "regex": "/mage/"}
    ],
    "Laravel": [
        {"type": "header", "name": "X-Powered-By", "regex": "Laravel"},
        {"type": "cookie", "name": "laravel_session", "regex": ""}
    ],
    "Django": [
        {"type": "header", "name": "X-Powered-By", "regex": "Django"},
        {"type": "cookie", "name": "csrftoken", "regex": ""}
    ],
    "ASP.NET": [
        {"type": "header", "name": "X-Powered-By", "regex": "ASP.NET"},
        {"type": "header", "name": "X-AspNet-Version", "regex": ""},
        {"type": "cookie", "name": "ASP.NET_SessionId", "regex": ""}
    ],
    "PHP": [
        {"type": "header", "name": "X-Powered-By", "regex": "PHP"}
    ],
    "jQuery": [
        {"type": "script", "regex": "jquery"},
        {"type": "script", "regex": "jquery.min.js"}
    ],
    "Bootstrap": [
        {"type": "script", "regex": "bootstrap"},
        {"type": "script", "regex": "bootstrap.min.js"},
        {"type": "link", "regex": "bootstrap.min.css"}
    ],
    "React": [
        {"type": "script", "regex": "react"},
        {"type": "script", "regex": "react.min.js"},
        {"type": "script", "regex": "react-dom"}
    ],
    "Angular": [
        {"type": "script", "regex": "angular"},
        {"type": "script", "regex": "angular.min.js"},
        {"type": "attribute", "name": "ng-app", "regex": ""}
    ],
    "Vue.js": [
        {"type": "script", "regex": "vue"},
        {"type": "script", "regex": "vue.min.js"}
    ],
    "Nginx": [
        {"type": "header", "name": "Server", "regex": "nginx"}
    ],
    "Apache": [
        {"type": "header", "name": "Server", "regex": "Apache"}
    ],
    "IIS": [
        {"type": "header", "name": "Server", "regex": "IIS"}
    ],
    "Cloudflare": [
        {"type": "header", "name": "Server", "regex": "cloudflare"},
        {"type": "cookie", "name": "__cfduid", "regex": ""},
        {"type": "header", "name": "CF-RAY", "regex": ""}
    ]
}

def run(target, options):
    """
    Run web fingerprinting on the target
    
    Args:
        target (str): Target URL or domain
        options (dict): Additional options
        
    Returns:
        dict: Results of the web fingerprinting
    """
    logger.info(f"Running web fingerprinting for {target}")
    
    results = {
        "module": "webfinger",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "technologies": [],
        "headers": {},
        "cookies": {},
        "links": [],
        "scripts": [],
        "meta": [],
        "forms": [],
        "summary": {}
    }
    
    try:
        # Ensure target has a scheme
        if not target.startswith('http'):
            target = f"http://{target}"
        
        # Parse the URL
        parsed_url = urlparse(target)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Create a session with a random user agent
        session = requests.Session()
        ua = UserAgent()
        headers = {
            "User-Agent": ua.random,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        session.headers.update(headers)
        
        # Make the request
        response = session.get(target, timeout=10, verify=False, allow_redirects=True)
        
        # Store response headers
        for header, value in response.headers.items():
            results["headers"][header] = value
        
        # Store cookies
        for cookie in session.cookies:
            results["cookies"][cookie.name] = cookie.value
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'lxml')
        
        # Extract links
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                # Convert relative URLs to absolute
                if not href.startswith('http'):
                    href = urljoin(base_url, href)
                results["links"].append(href)
        
        # Extract scripts
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                # Convert relative URLs to absolute
                if not src.startswith('http'):
                    src = urljoin(base_url, src)
                results["scripts"].append(src)
        
        # Extract meta tags
        for meta in soup.find_all('meta'):
            meta_info = {}
            for attr in meta.attrs:
                meta_info[attr] = meta.get(attr)
            results["meta"].append(meta_info)
        
        # Extract forms
        for form in soup.find_all('form'):
            form_info = {
                "action": form.get('action', ''),
                "method": form.get('method', 'get'),
                "inputs": []
            }
            
            # Convert relative URLs to absolute
            if form_info["action"] and not form_info["action"].startswith('http'):
                form_info["action"] = urljoin(base_url, form_info["action"])
            
            # Extract form inputs
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    "type": input_field.name
                }
                
                for attr in input_field.attrs:
                    input_info[attr] = input_field.get(attr)
                
                form_info["inputs"].append(input_info)
            
            results["forms"].append(form_info)
        
        # Detect technologies
        detected_techs = {}
        
        for tech, signatures in TECH_SIGNATURES.items():
            for signature in signatures:
                if signature["type"] == "header" and "name" in signature:
                    header_name = signature["name"]
                    if header_name in results["headers"]:
                        header_value = results["headers"][header_name]
                        if signature["regex"] in header_value:
                            if tech not in detected_techs:
                                detected_techs[tech] = {
                                    "confidence": 0,
                                    "version": "",
                                    "evidence": []
                                }
                            detected_techs[tech]["confidence"] += 1
                            detected_techs[tech]["evidence"].append(f"Header: {header_name}: {header_value}")
                
                elif signature["type"] == "cookie" and "name" in signature:
                    cookie_name = signature["name"]
                    if cookie_name in results["cookies"]:
                        if tech not in detected_techs:
                            detected_techs[tech] = {
                                "confidence": 0,
                                "version": "",
                                "evidence": []
                            }
                        detected_techs[tech]["confidence"] += 1
                        detected_techs[tech]["evidence"].append(f"Cookie: {cookie_name}")
                
                elif signature["type"] == "meta" and "name" in signature:
                    for meta in results["meta"]:
                        if "name" in meta and meta["name"] == signature["name"] and "content" in meta:
                            if signature["regex"] in meta["content"]:
                                if tech not in detected_techs:
                                    detected_techs[tech] = {
                                        "confidence": 0,
                                        "version": "",
                                        "evidence": []
                                    }
                                detected_techs[tech]["confidence"] += 1
                                detected_techs[tech]["evidence"].append(f"Meta: {meta['name']}: {meta['content']}")
                                
                                # Try to extract version
                                if tech in ["WordPress", "Joomla", "Drupal"] and "version" in meta["content"].lower():
                                    import re
                                    version_match = re.search(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?', meta["content"])
                                    if version_match:
                                        detected_techs[tech]["version"] = version_match.group(0)
                
                elif signature["type"] == "script" and "regex" in signature:
                    for script in results["scripts"]:
                        if signature["regex"] in script.lower():
                            if tech not in detected_techs:
                                detected_techs[tech] = {
                                    "confidence": 0,
                                    "version": "",
                                    "evidence": []
                                }
                            detected_techs[tech]["confidence"] += 1
                            detected_techs[tech]["evidence"].append(f"Script: {script}")
                            
                            # Try to extract version
                            if tech in ["jQuery", "Bootstrap", "React", "Angular", "Vue.js"]:
                                import re
                                version_match = re.search(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?', script)
                                if version_match:
                                    detected_techs[tech]["version"] = version_match.group(0)
                
                elif signature["type"] == "url" and "regex" in signature:
                    if signature["regex"] in response.text:
                        if tech not in detected_techs:
                            detected_techs[tech] = {
                                "confidence": 0,
                                "version": "",
                                "evidence": []
                            }
                        detected_techs[tech]["confidence"] += 1
                        detected_techs[tech]["evidence"].append(f"URL pattern: {signature['regex']}")
                
                elif signature["type"] == "attribute" and "name" in signature:
                    if soup.find_all(attrs={signature["name"]: True}):
                        if tech not in detected_techs:
                            detected_techs[tech] = {
                                "confidence": 0,
                                "version": "",
                                "evidence": []
                            }
                        detected_techs[tech]["confidence"] += 1
                        detected_techs[tech]["evidence"].append(f"Attribute: {signature['name']}")
        
        # Convert detected_techs to list for results
        for tech, info in detected_techs.items():
            tech_info = {
                "name": tech,
                "confidence": info["confidence"],
                "version": info["version"],
                "evidence": info["evidence"]
            }
            results["technologies"].append(tech_info)
        
        # Sort technologies by confidence
        results["technologies"] = sorted(results["technologies"], key=lambda x: x["confidence"], reverse=True)
        
        # Generate summary
        results["summary"] = {
            "total_technologies": len(results["technologies"]),
            "server": results["headers"].get("Server", "Unknown"),
            "status_code": response.status_code,
            "content_type": results["headers"].get("Content-Type", "Unknown"),
            "total_links": len(results["links"]),
            "total_scripts": len(results["scripts"]),
            "total_forms": len(results["forms"])
        }
        
    except Exception as e:
        logger.error(f"Error performing web fingerprinting: {str(e)}")
        results["error"] = f"Error performing web fingerprinting: {str(e)}"
    
    return results

# For testing
if __name__ == "__main__":
    import sys
    import urllib3
    
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if len(sys.argv) < 2:
        print("Usage: python webfinger.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run(target, {})
    
    print(json.dumps(results, indent=4))