#!/usr/bin/env python3
"""
Burp XML Header Analyzer

This script scans Burp XML export files for response headers that reveal server information,
such as service types, versions, and products used on web servers.
It outputs the findings as a JSON file.

Usage:
    python burp_header_analyzer.py --file burp_export.xml [--output results.json]
"""

import argparse
import base64
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Tuple
from collections import defaultdict

# Headers that typically reveal server information
INTERESTING_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-asp-version",
    "x-runtime",
    "x-version",
    "powered-by",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "via",
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "x-backend-server",
    "x-cache",
    "x-cache-hits",
    "x-served-by",
    "x-timer",
    "x-proxy",
    "x-request-id",
    "x-shopify-stage",
    "x-wix-request-id",
    "x-content-type-options",
    "x-xss-protection",
    "x-frame-options",
    "strict-transport-security",
    "cf-ray",
    "cloudfront-viewer-country",
    "nel",
    "report-to",
    "x-cloud-trace-context",
    "x-firebase-hostname",
    "x-vercel-cache",
    "x-vercel-id",
    "x-nextjs-page",
    "x-robots-tag",
    "x-jenkins",
    "x-environment",
    "x-github-request-id",
    "x-now",
    "x-fastly",
    "x-nginx-cache-status"
}

# Regex patterns for version detection in header values
VERSION_PATTERNS = [
    r'([a-zA-Z0-9_\.-]+)[\/\s](\d+(?:\.\d+)+)',  # matches product/1.2.3 or product 1.2.3
    r'v(\d+(?:\.\d+)+)',  # matches v1.2.3
    r'[vV]ersion[\/\s:\-]?(\d+(?:\.\d+)+)',  # matches Version: 1.2.3
]

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Extract server information from Burp XML files')
    parser.add_argument('--file', '-f', required=True, help='Path to Burp XML file')
    parser.add_argument('--output', '-o', default='server_info.json', help='Output JSON file path')
    return parser.parse_args()

def extract_headers_from_response(response_text: str) -> Dict[str, str]:
    """Extract headers from HTTP response text."""
    headers = {}
    
    # Find the end of headers (double newline)
    header_end = response_text.find('\r\n\r\n')
    if header_end == -1:
        header_end = response_text.find('\n\n')
    
    if header_end == -1:
        return headers
    
    header_text = response_text[:header_end]
    
    # Skip the first line (HTTP status line)
    header_lines = header_text.split('\n')[1:]
    
    for line in header_lines:
        line = line.strip()
        if not line:
            continue
        
        # Split by first colon
        parts = line.split(':', 1)
        if len(parts) == 2:
            header_name = parts[0].strip().lower()
            header_value = parts[1].strip()
            headers[header_name] = header_value
    
    return headers

def detect_versions(header_value: str) -> List[Tuple[str, str]]:
    """Detect versions in header values using regex patterns."""
    results = []
    
    for pattern in VERSION_PATTERNS:
        matches = re.findall(pattern, header_value)
        if matches:
            if isinstance(matches[0], tuple):
                # Pattern captured product and version
                for product, version in matches:
                    results.append((product, version))
            else:
                # Pattern only captured version
                results.append(("unknown", matches[0]))
    
    # Special case for server header without version pattern
    if not results and '/' in header_value:
        parts = header_value.split('/', 1)
        if len(parts) == 2 and parts[1].strip():
            # Simple product/version format
            product = parts[0].strip()
            version = parts[1].strip()
            results.append((product, version))
    
    return results

def analyze_burp_xml(xml_path: str) -> Dict:
    """Analyze Burp XML file for server information in response headers."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    results = {}
    
    for i, item in enumerate(root.findall('item'), 1):
        # Get URL
        url_elem = item.find('url')
        url = url_elem.text if url_elem is not None else "unknown"
        
        # Get response
        response_elem = item.find('response')
        if response_elem is None:
            continue
        
        response_text = response_elem.text
        is_base64 = response_elem.get('base64') == 'true'
        
        if is_base64 and response_text:
            try:
                response_text = base64.b64decode(response_text).decode('utf-8', errors='ignore')
            except Exception as e:
                print(f"Error decoding response for item {i}: {e}")
                continue
        
        if not response_text:
            continue
        
        # Extract headers
        headers = extract_headers_from_response(response_text)
        
        # Filter for interesting headers
        interesting_headers_found = {
            header: value for header, value in headers.items() 
            if header.lower() in INTERESTING_HEADERS
        }
        
        if not interesting_headers_found:
            continue
        
        # Extract version information
        detected_products = []
        
        for header, value in interesting_headers_found.items():
            versions = detect_versions(value)
            if versions:
                for product, version in versions:
                    detected_products.append({
                        "source_header": header,
                        "product": product,
                        "version": version,
                        "full_header_value": value
                    })
            else:
                # Include header even if no version detected
                detected_products.append({
                    "source_header": header,
                    "product": "unknown",
                    "version": "unknown",
                    "full_header_value": value
                })
        
        # Add to results
        if detected_products:
            results[i] = {
                "url": url,
                "headers": interesting_headers_found,
                "detected_products": detected_products
            }
    
    return results

def main():
    """Main function."""
    args = parse_args()
    
    print(f"Analyzing Burp XML file: {args.file}")
    results = analyze_burp_xml(args.file)
    
    print(f"Found server information in {len(results)} requests")
    
    # Save to JSON
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()
