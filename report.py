#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Report Generation Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module generates reports in various formats (HTML, PDF, JSON) from scan results.
"""

import json
import logging
import os
from datetime import datetime
import jinja2
import base64
import webbrowser
from pathlib import Path

# Configure logging
logger = logging.getLogger("sayer.modules.report")

def generate_json_report(results, output_file=None):
    """
    Generate a JSON report from scan results
    
    Args:
        results (dict): Scan results
        output_file (str): Output file path
        
    Returns:
        str: Path to the generated report file
    """
    try:
        # Create output directory if it doesn't exist
        if output_file:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        else:
            # Generate default output file name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = results.get("target", "unknown")
            target = target.replace("http://", "").replace("https://", "").replace("/", "_")
            output_dir = "reports"
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"sayer_{target}_{timestamp}.json")
        
        # Write JSON report
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        logger.info(f"JSON report generated: {output_file}")
        return output_file
    
    except Exception as e:
        logger.error(f"Error generating JSON report: {str(e)}")
        return None

def generate_html_report(results, template_file=None, output_file=None):
    """
    Generate an HTML report from scan results
    
    Args:
        results (dict): Scan results
        template_file (str): Template file path
        output_file (str): Output file path
        
    Returns:
        str: Path to the generated report file
    """
    try:
        # Create output directory if it doesn't exist
        if output_file:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        else:
            # Generate default output file name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = results.get("target", "unknown")
            target = target.replace("http://", "").replace("https://", "").replace("/", "_")
            output_dir = "reports"
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"sayer_{target}_{timestamp}.html")
        
        # Use default template if none provided
        if not template_file:
            template_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates", "report.html")
        
        # Check if template file exists
        if not os.path.exists(template_file):
            logger.error(f"Template file not found: {template_file}")
            return None
        
        # Load template
        template_dir = os.path.dirname(template_file)
        template_name = os.path.basename(template_file)
        
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
        template = env.get_template(template_name)
        
        # Prepare data for template
        report_data = {
            "title": f"Sayer Security Scan Report - {results.get('target', 'Unknown Target')}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": results.get("target", "Unknown"),
            "scan_type": results.get("scan_type", "Unknown"),
            "modules": results.get("modules", []),
            "results": results,
            "summary": generate_summary(results)
        }
        
        # Add logo
        logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "logo.svg")
        if os.path.exists(logo_path):
            with open(logo_path, 'r') as f:
                report_data["logo_svg"] = f.read()
        
        # Render template
        html_content = template.render(**report_data)
        
        # Write HTML report
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_file}")
        return output_file
    
    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}")
        return None

def generate_pdf_report(results, template_file=None, output_file=None):
    """
    Generate a PDF report from scan results
    
    Args:
        results (dict): Scan results
        template_file (str): Template file path
        output_file (str): Output file path
        
    Returns:
        str: Path to the generated report file
    """
    try:
        # Try to import weasyprint
        try:
            from weasyprint import HTML
        except ImportError:
            logger.error("WeasyPrint not installed. Cannot generate PDF report.")
            return None
        
        # Create output directory if it doesn't exist
        if output_file:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        else:
            # Generate default output file name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = results.get("target", "unknown")
            target = target.replace("http://", "").replace("https://", "").replace("/", "_")
            output_dir = "reports"
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"sayer_{target}_{timestamp}.pdf")
        
        # First generate HTML report
        html_file = generate_html_report(results, template_file, None)
        if not html_file:
            logger.error("Failed to generate HTML report for PDF conversion")
            return None
        
        # Convert HTML to PDF
        HTML(html_file).write_pdf(output_file)
        
        logger.info(f"PDF report generated: {output_file}")
        return output_file
    
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        return None

def generate_summary(results):
    """
    Generate a summary of scan results
    
    Args:
        results (dict): Scan results
        
    Returns:
        dict: Summary of scan results
    """
    summary = {
        "target": results.get("target", "Unknown"),
        "scan_type": results.get("scan_type", "Unknown"),
        "timestamp": results.get("timestamp", datetime.now().isoformat()),
        "modules": results.get("modules", []),
        "findings": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "total_findings": 0
    }
    
    # Count findings by severity
    for module_name, module_results in results.items():
        if not isinstance(module_results, dict):
            continue
        
        # Skip non-module results
        if module_name in ["target", "scan_type", "timestamp", "modules"]:
            continue
        
        # Check for vulnerabilities
        if "vulnerabilities" in module_results:
            for vuln in module_results["vulnerabilities"]:
                severity = vuln.get("severity", "info").lower()
                if severity in summary["findings"]:
                    summary["findings"][severity] += 1
                    summary["total_findings"] += 1
        
        # Check for summary in module results
        if "summary" in module_results and isinstance(module_results["summary"], dict):
            module_summary = module_results["summary"]
            
            # Check for severity counts
            if "severity_counts" in module_summary and isinstance(module_summary["severity_counts"], dict):
                for severity, count in module_summary["severity_counts"].items():
                    if severity in summary["findings"]:
                        summary["findings"][severity] += count
                        summary["total_findings"] += count
    
    return summary

def open_report(report_file):
    """
    Open a report file in the default browser
    
    Args:
        report_file (str): Path to the report file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not os.path.exists(report_file):
            logger.error(f"Report file not found: {report_file}")
            return False
        
        # Open report in default browser
        webbrowser.open(f"file://{os.path.abspath(report_file)}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error opening report: {str(e)}")
        return False

def run(results, options):
    """
    Generate reports from scan results
    
    Args:
        results (dict): Scan results
        options (dict): Additional options
        
    Returns:
        dict: Paths to the generated report files
    """
    logger.info("Generating reports")
    
    report_files = {}
    
    try:
        # Get report formats from options
        formats = options.get("formats", ["json", "html"])
        if not formats:
            formats = ["json", "html"]
        
        # Get output directory from options
        output_dir = options.get("output_dir", "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        # Get template file from options
        template_file = options.get("template_file", None)
        
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Get target name
        target = results.get("target", "unknown")
        target = target.replace("http://", "").replace("https://", "").replace("/", "_")
        
        # Generate reports in requested formats
        for fmt in formats:
            if fmt.lower() == "json":
                output_file = os.path.join(output_dir, f"sayer_{target}_{timestamp}.json")
                json_file = generate_json_report(results, output_file)
                if json_file:
                    report_files["json"] = json_file
            
            elif fmt.lower() == "html":
                output_file = os.path.join(output_dir, f"sayer_{target}_{timestamp}.html")
                html_file = generate_html_report(results, template_file, output_file)
                if html_file:
                    report_files["html"] = html_file
            
            elif fmt.lower() == "pdf":
                output_file = os.path.join(output_dir, f"sayer_{target}_{timestamp}.pdf")
                pdf_file = generate_pdf_report(results, template_file, output_file)
                if pdf_file:
                    report_files["pdf"] = pdf_file
        
        # Open report if requested
        if options.get("open_report", False) and report_files:
            # Prefer HTML, then PDF, then JSON
            if "html" in report_files:
                open_report(report_files["html"])
            elif "pdf" in report_files:
                open_report(report_files["pdf"])
            elif "json" in report_files:
                open_report(report_files["json"])
        
    except Exception as e:
        logger.error(f"Error generating reports: {str(e)}")
        report_files["error"] = f"Error generating reports: {str(e)}"
    
    return report_files

# For testing
if __name__ == "__main__":
    import sys
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python report.py <results_file>")
        sys.exit(1)
    
    # Load results from file
    with open(sys.argv[1], 'r') as f:
        results = json.load(f)
    
    # Generate reports
    report_files = run(results, {"formats": ["json", "html"], "open_report": True})
    
    print("Generated reports:")
    for fmt, file_path in report_files.items():
        print(f"{fmt}: {file_path}")