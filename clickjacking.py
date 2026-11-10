import xml.etree.ElementTree as ET
import base64
import re
import sys
import os
from collections import defaultdict

def extract_headers_from_content(content):
    """Extract headers from a response string."""
    headers = {}
    # Split on double newline to separate headers from body
    parts = content.split('\r\n\r\n', 1)
    if len(parts) > 0:
        # Get individual headers
        header_lines = parts[0].split('\r\n')
        for line in header_lines[1:]:  # Skip the first line (HTTP/1.1 200 OK)
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
    return headers

def analyze_proxy_data(xml_file):
    """Analyze XML proxy data for clickjacking protection headers."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError:
        print(f"Error: Could not parse {xml_file} as XML.")
        return
    except FileNotFoundError:
        print(f"Error: File {xml_file} not found.")
        return

    results = defaultdict(list)
    vulnerable_urls = []
    
    # Look for response elements, which may vary based on the XML structure
    # Adjust the XPath as needed for your specific XML format
    for item in root.findall('.//item'):
        url_elem = item.find('.//url')
        response_elem = item.find('.//response')
        
        if url_elem is not None and response_elem is not None and response_elem.text:
            url = url_elem.text
            
            try:
                # Decode base64 response
                response_content = base64.b64decode(response_elem.text).decode('utf-8', errors='ignore')
                
                # Extract headers
                headers = extract_headers_from_content(response_content)
                
                # Check for clickjacking protection headers
                is_protected = False
                
                # Check X-Frame-Options
                if 'x-frame-options' in headers:
                    xfo_value = headers['x-frame-options'].upper()
                    if 'DENY' in xfo_value or 'SAMEORIGIN' in xfo_value or 'ALLOW-FROM' in xfo_value:
                        results[url].append(f"X-Frame-Options: {headers['x-frame-options']}")
                        is_protected = True
                
                # Check Content-Security-Policy
                if 'content-security-policy' in headers:
                    csp_value = headers['content-security-policy']
                    frame_ancestors_match = re.search(r'frame-ancestors\s+([^;]+)', csp_value)
                    if frame_ancestors_match:
                        frame_ancestors = frame_ancestors_match.group(1)
                        if "'none'" in frame_ancestors or "'self'" in frame_ancestors:
                            results[url].append(f"Content-Security-Policy: frame-ancestors {frame_ancestors}")
                            is_protected = True
                
                if not is_protected:
                    vulnerable_urls.append(url)
                
            except Exception as e:
                print(f"Error processing {url}: {str(e)}")
    
    return results, vulnerable_urls

def create_test_files(vulnerable_urls):
    """Create HTML test files for each potentially vulnerable endpoint."""
    # Create a directory for test files if it doesn't exist
    test_dir = "clickjacking_tests"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    
    created_files = []
    for i, url in enumerate(vulnerable_urls):
        # Create a safe filename
        safe_name = f"test_{i+1}.html"
        file_path = os.path.join(test_dir, safe_name)
        
        # Create the HTML content
        html_content = f"""<!DOCTYPE html>
<html>
    <head>
        <title>Clickjack test page</title>
    </head>
    <body>
        <iframe src="{url}" width="500" height="500"></iframe>
    </body>
</html>"""
        
        # Write the file
        with open(file_path, "w") as f:
            f.write(html_content)
        
        created_files.append((url, file_path))
    
    return created_files

def print_report(results, vulnerable_urls):
    """Print a summary report of the analysis."""
    print("\n====== CLICKJACKING PROTECTION ANALYSIS REPORT ======\n")
    
    if results:
        print("PROTECTED ENDPOINTS:")
        print("-------------------")
        for url, protections in results.items():
            print(f"\nURL: {url}")
            for protection in protections:
                print(f"  ✓ {protection}")
        print("\n")
    
    # Create test files for vulnerable URLs
    test_files = []
    if vulnerable_urls:
        test_files = create_test_files(vulnerable_urls)
        
        print("POTENTIALLY VULNERABLE ENDPOINTS:")
        print("--------------------------------")
        for url, file_path in test_files:
            print(f"  ✗ {url} -> Test file: {file_path}")
        print("\nThese endpoints do not have explicit X-Frame-Options or CSP frame-ancestors protection.")
        print("Test files have been created for manual verification.")
    else:
        print("No potentially vulnerable endpoints found!")
    
    print("\n====== SUMMARY ======")
    print(f"Total URLs analyzed: {len(results) + len(vulnerable_urls)}")
    print(f"Protected URLs: {len(results)}")
    print(f"Potentially vulnerable URLs: {len(vulnerable_urls)}")
    
    if test_files:
        print(f"\nGenerated {len(test_files)} test files in the 'clickjacking_tests' directory.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python clickjacking_analyzer.py <path_to_xml_file>")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    print(f"Analyzing {xml_file} for clickjacking protection headers...")
    results, vulnerable_urls = analyze_proxy_data(xml_file)
    print_report(results, vulnerable_urls)
    
    if vulnerable_urls:
        print("\nNext steps:")
        print("1. Open the generated HTML files in your browser")
        print("2. If you can see the target website loaded in the iframe, it may be vulnerable to clickjacking")
        print("3. Document the findings with screenshots for your report")

if __name__ == "__main__":
    main()
