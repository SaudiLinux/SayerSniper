#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Enumeration Module for Sayer
Developed by Saudi Linux (SaudiLinux7@gmail.com)

This module performs DNS enumeration for domains.
"""

import dns.resolver
import dns.reversename
import socket
import json
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger("sayer.modules.dns")

def run(target, options):
    """
    Run DNS enumeration on the target
    
    Args:
        target (str): Target domain or IP address
        options (dict): Additional options
        
    Returns:
        dict: Results of the DNS enumeration
    """
    logger.info(f"Running DNS enumeration for {target}")
    
    results = {
        "module": "dns",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "records": {},
        "summary": {}
    }
    
    try:
        # Check if target is an IP address
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False
        
        if is_ip:
            # Perform reverse DNS lookup
            try:
                reverse_name = dns.reversename.from_address(target)
                reverse_records = dns.resolver.resolve(reverse_name, "PTR")
                
                ptr_records = []
                for record in reverse_records:
                    ptr_records.append(str(record))
                
                results["records"]["ptr"] = ptr_records
            except Exception as e:
                logger.warning(f"Error performing reverse DNS lookup: {str(e)}")
                results["records"]["ptr"] = []
        else:
            # Perform DNS lookups for various record types
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    
                    records = []
                    for answer in answers:
                        if record_type == "SOA":
                            records.append({
                                "mname": str(answer.mname),
                                "rname": str(answer.rname),
                                "serial": answer.serial,
                                "refresh": answer.refresh,
                                "retry": answer.retry,
                                "expire": answer.expire,
                                "minimum": answer.minimum
                            })
                        elif record_type == "MX":
                            records.append({
                                "preference": answer.preference,
                                "exchange": str(answer.exchange)
                            })
                        else:
                            records.append(str(answer))
                    
                    results["records"][record_type.lower()] = records
                except Exception as e:
                    logger.debug(f"No {record_type} records found: {str(e)}")
                    results["records"][record_type.lower()] = []
            
            # Try to get SPF record (usually in TXT records)
            spf_records = []
            if "txt" in results["records"]:
                for txt in results["records"]["txt"]:
                    if txt.startswith('"v=spf1') or txt.startswith('v=spf1'):
                        spf_records.append(txt)
            
            results["records"]["spf"] = spf_records
            
            # Try to get DMARC record
            try:
                dmarc_target = f"_dmarc.{target}"
                dmarc_answers = dns.resolver.resolve(dmarc_target, "TXT")
                
                dmarc_records = []
                for answer in dmarc_answers:
                    dmarc_records.append(str(answer))
                
                results["records"]["dmarc"] = dmarc_records
            except Exception as e:
                logger.debug(f"No DMARC records found: {str(e)}")
                results["records"]["dmarc"] = []
        
        # Generate summary
        total_records = sum(len(records) for records in results["records"].values())
        record_counts = {record_type: len(records) for record_type, records in results["records"].items()}
        
        results["summary"] = {
            "total_records": total_records,
            "record_counts": record_counts
        }
        
    except Exception as e:
        logger.error(f"Error performing DNS enumeration: {str(e)}")
        results["error"] = f"Error performing DNS enumeration: {str(e)}"
    
    return results

# For testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python dns.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    results = run(target, {})
    
    print(json.dumps(results, indent=4))