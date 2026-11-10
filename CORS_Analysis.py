import xml.etree.ElementTree as ET
import json
import base64
import re
import argparse
import sys
from difflib import SequenceMatcher

def load_cors_indicators(file_path):
    """Load the CORS indicators JSON file and reformat it"""
    try:
        with open(file_path, 'r') as f:
            original_data = json.load(f)
        
        # Reformat the data for better matching
        reformatted_data = reformat_cors_indicators(original_data)
        
        return reformatted_data
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in CORS indicators file: {e}")
        print(f"Check line {e.lineno}, column {e.colno}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading CORS indicators: {e}")
        sys.exit(1)

def reformat_cors_indicators(original_data):
    """Reformats the CORS indicators data for better string matching"""
    reformatted = {
        "cors_vulnerability_indicators": {
            "response_headers": {}
        }
    }
    
    # Process response headers
    for header_key, header_data in original_data["cors_vulnerability_indicators"]["response_headers"].items():
        reformatted_patterns = []
        
        for pattern in header_data["patterns"]:
            # Handle patterns that are direct header values
            if ":" in pattern and "(" not in pattern:
                # Split the header name from value
                parts = pattern.split(":", 1)
                if len(parts) == 2:
                    header_name = parts[0].strip()
                    header_value = parts[1].strip()
                    
                    # For combined headers like "GET, POST, PUT", split into individual entries
                    if header_key == "access_control_allow_methods" and "," in header_value:
                        # Skip the combined entry that has explanation text
                        if "(" in header_value:
                            continue
                            
                        methods = [method.strip() for method in header_value.split(",")]
                        for method in methods:
                            reformatted_patterns.append({
                                "header_name": header_name,
                                "value": method,
                                "original_pattern": pattern
                            })
                    else:
                        reformatted_patterns.append({
                            "header_name": header_name,
                            "value": header_value,
                            "original_pattern": pattern
                        })
            # Handle complex patterns with explanations
            elif ":" in pattern and "(" in pattern:
                # Extract just the header part before any explanation
                header_part = pattern.split("(", 1)[0].strip()
                if ":" in header_part:
                    parts = header_part.split(":", 1)
                    if len(parts) == 2:
                        header_name = parts[0].strip()
                        header_value = parts[1].strip()
                        
                        reformatted_patterns.append({
                            "header_name": header_name,
                            "value": header_value,
                            "original_pattern": pattern,
                            "note": "Requires additional context check"
                        })
        
        # Add the reformatted patterns to the output
        if reformatted_patterns:
            reformatted["cors_vulnerability_indicators"]["response_headers"][header_key] = {
                "patterns": reformatted_patterns,
                "risk_level": header_data["risk_level"]
            }
    
    # Also include other categories that might be useful for reference
    reformatted["cors_vulnerability_indicators"]["request_patterns"] = original_data["cors_vulnerability_indicators"]["request_patterns"]
    reformatted["cors_vulnerability_indicators"]["response_patterns"] = original_data["cors_vulnerability_indicators"]["response_patterns"]
    reformatted["cors_vulnerability_indicators"]["implementation_patterns"] = original_data["cors_vulnerability_indicators"]["implementation_patterns"]
    reformatted["cors_vulnerability_indicators"]["internal_network"] = original_data["cors_vulnerability_indicators"]["internal_network"]
    reformatted["cors_vulnerability_indicators"]["security_misconfigs"] = original_data["cors_vulnerability_indicators"]["security_misconfigs"]
    
    return reformatted

def decode_burp_data(encoded_data):
    """Decode base64 encoded data from Burp Suite"""
    try:
        return base64.b64decode(encoded_data).decode('utf-8', errors='replace')
    except Exception:
        return ""

def extract_url_from_item(item):
    """Extract the URL from a Burp Suite item"""
    url_element = item.find('url')
    if url_element is not None and url_element.text:
        return url_element.text
    return "Unknown URL"

def extract_headers_from_response(response_data):
    """Extract headers from the response data"""
    headers = {}
    
    # Find the end of the headers section (double newline)
    header_end = re.search(r'\r\n\r\n|\n\n', response_data)
    
    if header_end:
        headers_section = response_data[:header_end.start()]
        header_lines = re.split(r'\r\n|\n', headers_section)
        
        # Skip the first line (HTTP status line)
        for line in header_lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip()] = value.strip()
    
    return headers

def calculate_similarity(a, b):
    """Calculate the similarity between two strings"""
    if not a or not b:
        return 0
    return SequenceMatcher(None, str(a).lower(), str(b).lower()).ratio()

def find_cors_vulnerabilities(headers, cors_indicators):
    """Find CORS vulnerabilities in the headers"""
    vulnerabilities = []
    
    for header_key, header_data in cors_indicators["cors_vulnerability_indicators"]["response_headers"].items():
        for pattern in header_data["patterns"]:
            header_name = pattern["header_name"]
            expected_value = pattern["value"]
            
            # Check if the header exists in the response
            for resp_header_name, resp_header_value in headers.items():
                # Normalize header names for comparison (case-insensitive)
                if header_name.lower() == resp_header_name.lower():
                    # Check for exact match
                    exact_match = expected_value.lower() == resp_header_value.lower()
                    
                    # Check for contains match
                    contains_match = expected_value.lower() in resp_header_value.lower() or resp_header_value.lower() in expected_value.lower()
                    
                    # Calculate similarity
                    similarity = calculate_similarity(expected_value, resp_header_value)
                    
                    if exact_match or contains_match or similarity > 0.7:
                        match_type = "exact" if exact_match else "contains" if contains_match else "similar"
                        
                        vulnerability = {
                            "header_name": resp_header_name,
                            "header_value": resp_header_value,
                            "pattern_matched": pattern["original_pattern"],
                            "vulnerability_type": header_key,
                            "risk_level": header_data["risk_level"],
                            "match_type": match_type,
                            "similarity": similarity
                        }
                        
                        # Add note if this pattern requires additional context
                        if "note" in pattern:
                            vulnerability["note"] = pattern["note"]
                        
                        vulnerabilities.append(vulnerability)
    
    return vulnerabilities

def parse_burp_file(burp_file_path, cors_indicators):
    """Parse the Burp Suite XML file and analyze responses for CORS vulnerabilities"""
    try:
        tree = ET.parse(burp_file_path)
        root = tree.getroot()
        
        analysis_results = []
        
        # Process each item in the Burp Suite file
        for i, item in enumerate(root.findall('.//item'), 1):
            url = extract_url_from_item(item)
            response = item.find('response')
            
            if response is not None and response.text:
                response_data = decode_burp_data(response.text)
                headers = extract_headers_from_response(response_data)
                
                # Find CORS vulnerabilities
                vulnerabilities = find_cors_vulnerabilities(headers, cors_indicators)
                
                if vulnerabilities:
                    # Extract endpoint from URL
                    from urllib.parse import urlparse
                    parsed_url = urlparse(url)
                    endpoint = f"{parsed_url.path}"
                    if parsed_url.query:
                        endpoint += f"?{parsed_url.query}"
                    
                    analysis_results.append({
                        "item_number": i,
                        "url": url,
                        "endpoint": endpoint,
                        "cors_vulnerabilities": vulnerabilities
                    })
        
        return analysis_results
    
    except Exception as e:
        print(f"Error parsing Burp file: {e}")
        sys.exit(1)

def save_reformatted_cors_indicators(cors_indicators, output_path="reformatted_cors_indicators.json"):
    """Save the reformatted CORS indicators to a file"""
    try:
        with open(output_path, 'w') as f:
            json.dump(cors_indicators, f, indent=2)
        print(f"Reformatted CORS indicators saved to {output_path}")
    except Exception as e:
        print(f"Error saving reformatted CORS indicators: {e}")

def main():
    """Main function to process arguments and execute the script"""
    parser = argparse.ArgumentParser(description='Analyze Burp Suite responses for CORS vulnerabilities')
    parser.add_argument('burp_file', help='Path to the Burp Suite XML file')
    parser.add_argument('cors_file', help='Path to the CORS indicators JSON file')
    parser.add_argument('--output', default='CORSVulnerabilityAnalysis.json', help='Output JSON file name (default: CORSVulnerabilityAnalysis.json)')
    parser.add_argument('--save_reformatted', action='store_true', help='Save the reformatted CORS indicators to a file')
    
    args = parser.parse_args()
    
    # Load and reformat CORS indicators
    cors_indicators = load_cors_indicators(args.cors_file)
    
    # Save reformatted CORS indicators if requested
    if args.save_reformatted:
        save_reformatted_cors_indicators(cors_indicators)
    
    # Parse Burp file and analyze for CORS vulnerabilities
    analysis_results = parse_burp_file(args.burp_file, cors_indicators)
    
    # Output results
    if not analysis_results:
        print("No CORS vulnerabilities found.")
    else:
        # Print summary to terminal
        print(f"Analysis complete. Found CORS vulnerabilities in {len(analysis_results)} items:")
        
        # Sort results by risk level
        def risk_level_key(item):
            risk_levels = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            # Find the highest risk level in this item
            highest_risk = "low"
            for vuln in item['cors_vulnerabilities']:
                if risk_levels.get(vuln['risk_level'], 4) < risk_levels.get(highest_risk, 4):
                    highest_risk = vuln['risk_level']
            return risk_levels.get(highest_risk, 4)
        
        sorted_results = sorted(analysis_results, key=risk_level_key)
        
        for item in sorted_results:
            print(f"\nItem #{item['item_number']}: {item['endpoint']}")
            print(f"URL: {item['url']}")
            
            vulnerabilities_by_risk = {}
            for vuln in item['cors_vulnerabilities']:
                risk_level = vuln['risk_level']
                if risk_level not in vulnerabilities_by_risk:
                    vulnerabilities_by_risk[risk_level] = []
                vulnerabilities_by_risk[risk_level].append(vuln)
            
            # Sort by risk level (critical, high, medium, low)
            risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for risk_level in sorted(vulnerabilities_by_risk.keys(), key=lambda x: risk_order.get(x, 999)):
                print(f"  {risk_level.upper()} Risk Vulnerabilities:")
                for vuln in vulnerabilities_by_risk[risk_level]:
                    print(f"    - {vuln['header_name']}: {vuln['header_value']}")
                    print(f"      Matched pattern: {vuln['pattern_matched']}")
                    print(f"      Vulnerability type: {vuln['vulnerability_type']}")
                    print(f"      Match type: {vuln['match_type']} (similarity: {vuln['similarity']:.2f})")
                    if "note" in vuln:
                        print(f"      Note: {vuln['note']}")
                    print()
        
        # Save detailed results to JSON file
        with open(args.output, 'w') as f:
            json.dump({
                "analysis_results": analysis_results
            }, f, indent=2)
        
        print(f"\nDetailed analysis saved to {args.output}")

if __name__ == "__main__":
    main()
