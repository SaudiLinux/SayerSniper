#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sayer - Advanced Penetration Testing Tool
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This tool automates the process of information gathering and vulnerability scanning
for penetration testing and security assessments.
"""

import os
import sys
import argparse
import time
import json
import yaml
import logging
import subprocess
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Version information
__version__ = "1.0.0"
__author__ = "Saudi Linux"
__email__ = "SaudiLinux7@gmail.com"

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.exists("/opt/sayer"):
    BASE_DIR = "/opt/sayer"

# Configure logging
log_file = os.path.join(BASE_DIR, "logs", f"sayer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("sayer")

# Banner
def print_banner():
    """
    Print the Sayer banner
    """
    banner = f"""
{Fore.CYAN}  _____                      
{Fore.CYAN} / ____|                     
{Fore.CYAN}| (___   __ _ _   _  ___ _ __
{Fore.CYAN} \___ \ / _` | | | |/ _ \ '__|
{Fore.CYAN} ____) | (_| | |_| |  __/ |   
{Fore.CYAN}|_____/ \__,_|\__, |\___|_|   
{Fore.CYAN}               __/ |          
{Fore.CYAN}              |___/           
{Fore.GREEN}[+] Sayer v{__version__} - Advanced Penetration Testing Tool
{Fore.GREEN}[+] Developed by {__author__} ({__email__})
{Style.RESET_ALL}"""
    print(banner)

# Check dependencies
def check_dependencies():
    """
    Check if all required dependencies are installed
    """
    logger.info("Checking dependencies...")
    
    required_tools = [
        "nmap",
        "nikto",
        "whois",
        "dig",
        "nbtscan",
        "sqlmap",
        "dirb",
        "wpscan",
        "hydra",
        "msfconsole"
    ]
    
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.check_output(["which", tool], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            missing_tools.append(tool)
    
    if missing_tools:
        logger.warning(f"Missing dependencies: {', '.join(missing_tools)}")
        print(f"{Fore.YELLOW}[!] Warning: The following dependencies are missing: {', '.join(missing_tools)}")
        print(f"{Fore.YELLOW}[!] Some features may not work properly.")
        print(f"{Fore.YELLOW}[!] Run './install.sh' to install all dependencies.")
        return False
    
    logger.info("All dependencies are installed.")
    return True

# Load configuration
def load_config():
    """
    Load configuration from config file
    """
    config_file = os.path.join(BASE_DIR, "config", "config.yaml")
    
    # Create default config if it doesn't exist
    if not os.path.exists(config_file):
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        default_config = {
            "general": {
                "threads": 10,
                "timeout": 60,
                "user_agent": "Sayer/{} (https://github.com/SaudiLinux/Sayer)".format(__version__)
            },
            "nmap": {
                "default_args": "-sV -sC -O -T4"
            },
            "web": {
                "extensions": [".php", ".asp", ".aspx", ".jsp", ".html", ".js", ".txt"],
                "wordlist": "/usr/share/dirb/wordlists/common.txt"
            },
            "reporting": {
                "formats": ["html", "pdf", "json"],
                "template": "default"
            },
            "api_keys": {
                "shodan": "",
                "censys_id": "",
                "censys_secret": ""
            }
        }
        
        with open(config_file, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
    
    # Load config
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        logger.info("Configuration loaded successfully.")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        print(f"{Fore.RED}[!] Error loading configuration: {str(e)}")
        return None

# Module loader
def load_modules():
    """
    Load all modules from the modules directory
    """
    modules_dir = os.path.join(BASE_DIR, "modules")
    modules = {}
    
    if not os.path.exists(modules_dir):
        os.makedirs(modules_dir)
        # Create example module
        example_module = os.path.join(modules_dir, "example.py")
        with open(example_module, 'w') as f:
            f.write("""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example Module for Sayer
"""

def run(target, options):
    """
    Run the module
    
    Args:
        target (str): Target to scan
        options (dict): Additional options
        
    Returns:
        dict: Results of the scan
    """
    print(f"[*] Running example module against {target}")
    
    # Your module code here
    
    return {
        "module": "example",
        "target": target,
        "findings": [
            {
                "type": "info",
                "message": "This is an example finding"
            }
        ]
    }
""")
    
    # Load all Python modules
    sys.path.append(modules_dir)
    for file in os.listdir(modules_dir):
        if file.endswith(".py") and file != "__init__.py":
            module_name = file[:-3]
            try:
                module = __import__(module_name)
                if hasattr(module, "run"):
                    modules[module_name] = module
                    logger.info(f"Loaded module: {module_name}")
            except Exception as e:
                logger.error(f"Error loading module {module_name}: {str(e)}")
    
    return modules

# Target validation
def validate_target(target):
    """
    Validate the target format
    
    Args:
        target (str): Target to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    import re
    
    # Check if it's an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, target):
        # Validate each octet
        octets = target.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        return True
    
    # Check if it's a CIDR notation
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if re.match(cidr_pattern, target):
        ip_part = target.split('/')[0]
        cidr_part = int(target.split('/')[1])
        
        # Validate IP part
        octets = ip_part.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        
        # Validate CIDR part
        if cidr_part < 0 or cidr_part > 32:
            return False
            
        return True
    
    # Check if it's a domain name
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return True
    
    # Check if it's a URL
    url_pattern = r'^(http|https)://([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(/[\w\-\.\~\:\/\?\#\[\]\@\!\$\&\\'\(\)\*\+\,\;\=]*)?$'
    if re.match(url_pattern, target):
        return True
    
    return False

# Recon mode
def recon_mode(target, options, modules):
    """
    Run reconnaissance mode
    
    Args:
        target (str): Target to scan
        options (dict): Additional options
        modules (dict): Available modules
        
    Returns:
        dict: Results of the scan
    """
    logger.info(f"Starting reconnaissance mode for target: {target}")
    print(f"{Fore.BLUE}[*] Starting reconnaissance mode for target: {target}")
    
    results = {
        "target": target,
        "mode": "recon",
        "timestamp": datetime.now().isoformat(),
        "modules": {}
    }
    
    # Run whois lookup
    if "whois" in modules:
        print(f"{Fore.BLUE}[*] Running WHOIS lookup...")
        whois_results = modules["whois"].run(target, options)
        results["modules"]["whois"] = whois_results
    
    # Run DNS enumeration
    if "dns" in modules:
        print(f"{Fore.BLUE}[*] Running DNS enumeration...")
        dns_results = modules["dns"].run(target, options)
        results["modules"]["dns"] = dns_results
    
    # Run subdomain enumeration
    if "subdomains" in modules:
        print(f"{Fore.BLUE}[*] Running subdomain enumeration...")
        subdomain_results = modules["subdomains"].run(target, options)
        results["modules"]["subdomains"] = subdomain_results
    
    # Run port scanning (basic)
    if "portscan" in modules:
        print(f"{Fore.BLUE}[*] Running basic port scan...")
        options["scan_type"] = "basic"
        portscan_results = modules["portscan"].run(target, options)
        results["modules"]["portscan"] = portscan_results
    
    logger.info("Reconnaissance completed.")
    print(f"{Fore.GREEN}[+] Reconnaissance completed.")
    
    return results

# Network mode
def network_mode(target, options, modules):
    """
    Run network scanning mode
    
    Args:
        target (str): Target to scan
        options (dict): Additional options
        modules (dict): Available modules
        
    Returns:
        dict: Results of the scan
    """
    logger.info(f"Starting network scanning mode for target: {target}")
    print(f"{Fore.BLUE}[*] Starting network scanning mode for target: {target}")
    
    results = {
        "target": target,
        "mode": "network",
        "timestamp": datetime.now().isoformat(),
        "modules": {}
    }
    
    # Run comprehensive port scanning
    if "portscan" in modules:
        print(f"{Fore.BLUE}[*] Running comprehensive port scan...")
        options["scan_type"] = "comprehensive"
        portscan_results = modules["portscan"].run(target, options)
        results["modules"]["portscan"] = portscan_results
    
    # Run service enumeration
    if "services" in modules:
        print(f"{Fore.BLUE}[*] Running service enumeration...")
        services_results = modules["services"].run(target, options)
        results["modules"]["services"] = services_results
    
    # Run OS detection
    if "os_detection" in modules:
        print(f"{Fore.BLUE}[*] Running OS detection...")
        os_results = modules["os_detection"].run(target, options)
        results["modules"]["os_detection"] = os_results
    
    # Run vulnerability scanning
    if "vuln_scan" in modules:
        print(f"{Fore.BLUE}[*] Running vulnerability scanning...")
        options["scan_type"] = "network"
        vuln_results = modules["vuln_scan"].run(target, options)
        results["modules"]["vuln_scan"] = vuln_results
    
    logger.info("Network scanning completed.")
    print(f"{Fore.GREEN}[+] Network scanning completed.")
    
    return results

# Web mode
def web_mode(target, options, modules):
    """
    Run web application scanning mode
    
    Args:
        target (str): Target to scan
        options (dict): Additional options
        modules (dict): Available modules
        
    Returns:
        dict: Results of the scan
    """
    logger.info(f"Starting web application scanning mode for target: {target}")
    print(f"{Fore.BLUE}[*] Starting web application scanning mode for target: {target}")
    
    results = {
        "target": target,
        "mode": "web",
        "timestamp": datetime.now().isoformat(),
        "modules": {}
    }
    
    # Run web fingerprinting
    if "webfinger" in modules:
        print(f"{Fore.BLUE}[*] Running web fingerprinting...")
        webfinger_results = modules["webfinger"].run(target, options)
        results["modules"]["webfinger"] = webfinger_results
    
    # Run directory brute forcing
    if "dirb" in modules:
        print(f"{Fore.BLUE}[*] Running directory brute forcing...")
        dirb_results = modules["dirb"].run(target, options)
        results["modules"]["dirb"] = dirb_results
    
    # Run CMS detection
    if "cms" in modules:
        print(f"{Fore.BLUE}[*] Running CMS detection...")
        cms_results = modules["cms"].run(target, options)
        results["modules"]["cms"] = cms_results
    
    # Run web vulnerability scanning
    if "vuln_scan" in modules:
        print(f"{Fore.BLUE}[*] Running web vulnerability scanning...")
        options["scan_type"] = "web"
        vuln_results = modules["vuln_scan"].run(target, options)
        results["modules"]["vuln_scan"] = vuln_results
    
    logger.info("Web application scanning completed.")
    print(f"{Fore.GREEN}[+] Web application scanning completed.")
    
    return results

# Full mode
def full_mode(target, options, modules):
    """
    Run full scanning mode (all modules)
    
    Args:
        target (str): Target to scan
        options (dict): Additional options
        modules (dict): Available modules
        
    Returns:
        dict: Results of the scan
    """
    logger.info(f"Starting full scanning mode for target: {target}")
    print(f"{Fore.BLUE}[*] Starting full scanning mode for target: {target}")
    
    results = {
        "target": target,
        "mode": "full",
        "timestamp": datetime.now().isoformat(),
        "modules": {}
    }
    
    # Run recon mode
    recon_results = recon_mode(target, options, modules)
    results["modules"]["recon"] = recon_results["modules"]
    
    # Run network mode
    network_results = network_mode(target, options, modules)
    results["modules"]["network"] = network_results["modules"]
    
    # Run web mode
    web_results = web_mode(target, options, modules)
    results["modules"]["web"] = web_results["modules"]
    
    logger.info("Full scanning completed.")
    print(f"{Fore.GREEN}[+] Full scanning completed.")
    
    return results

# Generate report
def generate_report(results, options):
    """
    Generate a report from the scan results
    
    Args:
        results (dict): Scan results
        options (dict): Additional options
        
    Returns:
        str: Path to the generated report
    """
    logger.info("Generating report...")
    print(f"{Fore.BLUE}[*] Generating report...")
    
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate report filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_name = results["target"].replace("http://", "").replace("https://", "").replace("/", "_")
    report_name = f"sayer_report_{target_name}_{timestamp}"
    
    # Save JSON report
    json_report_path = os.path.join(reports_dir, f"{report_name}.json")
    with open(json_report_path, 'w') as f:
        json.dump(results, f, indent=4)
    
    # Generate HTML report if requested
    if "format" not in options or options["format"] == "html" or "html" in options["format"]:
        try:
            from jinja2 import Environment, FileSystemLoader
            
            # Load template
            template_dir = os.path.join(BASE_DIR, "templates")
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template("report.html")
            
            # Render template
            html_content = template.render(results=results, version=__version__, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            # Save HTML report
            html_report_path = os.path.join(reports_dir, f"{report_name}.html")
            with open(html_report_path, 'w') as f:
                f.write(html_content)
                
            logger.info(f"HTML report generated: {html_report_path}")
            print(f"{Fore.GREEN}[+] HTML report generated: {html_report_path}")
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            print(f"{Fore.RED}[!] Error generating HTML report: {str(e)}")
    
    # Generate PDF report if requested
    if "format" in options and (options["format"] == "pdf" or "pdf" in options["format"]):
        try:
            import pdfkit
            
            # Check if HTML report exists
            html_report_path = os.path.join(reports_dir, f"{report_name}.html")
            if not os.path.exists(html_report_path):
                # Generate HTML report first
                from jinja2 import Environment, FileSystemLoader
                
                # Load template
                template_dir = os.path.join(BASE_DIR, "templates")
                env = Environment(loader=FileSystemLoader(template_dir))
                template = env.get_template("report.html")
                
                # Render template
                html_content = template.render(results=results, version=__version__, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
                # Save HTML report
                with open(html_report_path, 'w') as f:
                    f.write(html_content)
            
            # Generate PDF from HTML
            pdf_report_path = os.path.join(reports_dir, f"{report_name}.pdf")
            pdfkit.from_file(html_report_path, pdf_report_path)
            
            logger.info(f"PDF report generated: {pdf_report_path}")
            print(f"{Fore.GREEN}[+] PDF report generated: {pdf_report_path}")
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            print(f"{Fore.RED}[!] Error generating PDF report: {str(e)}")
    
    logger.info("Report generation completed.")
    print(f"{Fore.GREEN}[+] Report generation completed.")
    
    return json_report_path

# Main function
def main():
    """
    Main function
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Sayer - Advanced Penetration Testing Tool")
    parser.add_argument("-t", "--target", help="Target to scan (IP, CIDR, domain, URL)")
    parser.add_argument("-m", "--mode", choices=["recon", "network", "web", "full"], default="recon", help="Scanning mode")
    parser.add_argument("-o", "--output", help="Output file for the report")
    parser.add_argument("-f", "--format", choices=["json", "html", "pdf"], default="html", help="Report format")
    parser.add_argument("-c", "--config", help="Custom configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--version", action="version", version=f"Sayer v{__version__}")
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check if target is provided
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Validate target
    if not validate_target(args.target):
        print(f"{Fore.RED}[!] Invalid target format: {args.target}")
        sys.exit(1)
    
    # Set verbose logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Check dependencies
    check_dependencies()
    
    # Load configuration
    config = load_config()
    if not config:
        sys.exit(1)
    
    # Load custom configuration if provided
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                custom_config = yaml.safe_load(f)
                config.update(custom_config)
            logger.info(f"Custom configuration loaded: {args.config}")
        except Exception as e:
            logger.error(f"Error loading custom configuration: {str(e)}")
            print(f"{Fore.RED}[!] Error loading custom configuration: {str(e)}")
    
    # Load modules
    modules = load_modules()
    if not modules:
        print(f"{Fore.YELLOW}[!] No modules found. Creating example module...")
        modules = load_modules()  # Reload modules after creating example
    
    # Prepare options
    options = {
        "config": config,
        "verbose": args.verbose,
        "format": args.format,
        "output": args.output
    }
    
    # Run selected mode
    start_time = time.time()
    
    try:
        if args.mode == "recon":
            results = recon_mode(args.target, options, modules)
        elif args.mode == "network":
            results = network_mode(args.target, options, modules)
        elif args.mode == "web":
            results = web_mode(args.target, options, modules)
        elif args.mode == "full":
            results = full_mode(args.target, options, modules)
        else:
            print(f"{Fore.RED}[!] Invalid mode: {args.mode}")
            sys.exit(1)
        
        # Generate report
        report_path = generate_report(results, options)
        
        # Print summary
        end_time = time.time()
        duration = end_time - start_time
        print(f"{Fore.GREEN}[+] Scan completed in {duration:.2f} seconds.")
        print(f"{Fore.GREEN}[+] Report saved to: {report_path}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.")
        logger.warning("Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred: {str(e)}")
        logger.error(f"An error occurred: {str(e)}")
        sys.exit(1)

# Entry point
if __name__ == "__main__":
    main()