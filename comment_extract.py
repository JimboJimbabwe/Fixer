#!/usr/bin/env python3
"""
Burp Suite Response Comment Extractor

Extracts all types of comments from HTTP responses in Burp Suite XML files.
Supports HTML, JavaScript, CSS, XML, and other comment formats.
"""

import xml.etree.ElementTree as ET
import argparse
import base64
import re
from collections import defaultdict
import sys
from urllib.parse import urlparse
import hashlib

class CommentExtractor:
    def __init__(self):
        # Define regex patterns for different comment types
        self.comment_patterns = {
            'html': [
                (r'<!--(.*?)-->', 'HTML Comment'),
                (r'<!--(.*?)--!>', 'HTML Comment (variant)'),
            ],
            'javascript': [
                (r'//([^\n\r]*)', 'JS Single-line'),
                (r'/\*(.*?)\*/', 'JS Multi-line'),
            ],
            'css': [
                (r'/\*(.*?)\*/', 'CSS Comment'),
            ],
            'jsp': [
                (r'<%--.*?--%>', 'JSP Comment'),
            ],
            'asp': [
                (r'<%\'[^\n\r]*%>', 'ASP Comment (VB)'),
                (r'<%//[^\n\r]*%>', 'ASP Comment (C#)'),
                (r'<%/\*.*?\*/%>', 'ASP Multi-line'),
            ],
            'php': [
                (r'<\?php\s*//[^\n\r]*\?>', 'PHP Single-line'),
                (r'<\?php\s*/\*.*?\*/\s*\?>', 'PHP Multi-line'),
                (r'#[^\n\r]*', 'PHP/Shell Comment'),
            ],
            'xml': [
                (r'<!--(.*?)-->', 'XML Comment'),
            ],
            'sql': [
                (r'--[^\n\r]*', 'SQL Comment'),
                (r'/\*(.*?)\*/', 'SQL Multi-line'),
            ],
            'python': [
                (r'#[^\n\r]*', 'Python Comment'),
                (r'""".*?"""', 'Python Docstring'),
                (r"'''.*?'''", 'Python Docstring (single)'),
            ]
        }
        
        # Compile all patterns with appropriate flags
        self.compiled_patterns = {}
        for lang, patterns in self.comment_patterns.items():
            self.compiled_patterns[lang] = []
            for pattern, comment_type in patterns:
                # Use DOTALL to make . match newlines for multi-line comments
                compiled = re.compile(pattern, re.DOTALL | re.IGNORECASE)
                self.compiled_patterns[lang].append((compiled, comment_type))

    def extract_comments_from_text(self, text):
        """
        Extract all comments from a text string
        
        Returns:
            dict: Dictionary with comment types as keys and lists of comments as values
        """
        found_comments = defaultdict(list)
        
        for lang, patterns in self.compiled_patterns.items():
            for pattern, comment_type in patterns:
                matches = pattern.findall(text)
                for match in matches:
                    # Clean up the comment text
                    comment_text = match.strip() if isinstance(match, str) else str(match).strip()
                    if comment_text:
                        found_comments[comment_type].append(comment_text)
        
        return found_comments

    def categorize_comment(self, comment):
        """
        Categorize a comment based on its content
        
        Returns:
            str: Category of the comment
        """
        comment_lower = comment.lower()
        
        # Check for specific patterns
        if 'todo' in comment_lower or 'fixme' in comment_lower:
            return 'TODO/FIXME'
        elif 'debug' in comment_lower or 'test' in comment_lower:
            return 'Debug/Test'
        elif 'deprecated' in comment_lower or 'obsolete' in comment_lower:
            return 'Deprecated'
        elif 'warning' in comment_lower or 'caution' in comment_lower:
            return 'Warning'
        elif 'note' in comment_lower or 'nb:' in comment_lower:
            return 'Note'
        elif 'hack' in comment_lower or 'workaround' in comment_lower:
            return 'Hack/Workaround'
        elif 'copyright' in comment_lower or 'license' in comment_lower:
            return 'Copyright/License'
        elif 'author' in comment_lower or 'created' in comment_lower:
            return 'Metadata'
        elif re.search(r'v\d+\.\d+', comment_lower) or 'version' in comment_lower:
            return 'Version Info'
        elif re.search(r'\b(api|key|token|secret|password)\b', comment_lower):
            return 'Potential Sensitive'
        elif re.search(r'\b(url|http|endpoint|path)\b', comment_lower):
            return 'URL/Endpoint'
        else:
            return 'General'

def parse_burp_xml(file_path):
    """
    Parse a Burp Suite XML file and extract responses
    
    Args:
        file_path (str): Path to the XML file
        
    Returns:
        list: List of dictionaries with request/response data
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        items = []
        for idx, item in enumerate(root.findall('./item')):
            url_elem = item.find('url')
            response_elem = item.find('response')
            request_elem = item.find('request')
            
            if url_elem is None or response_elem is None:
                continue
            
            url = url_elem.text or ""
            
            # Get response data
            response_data = {
                "raw": response_elem.text or "",
                "base64": response_elem.get('base64', 'false') == 'true'
            }
            
            # Decode if base64
            if response_data["base64"]:
                try:
                    response_data["raw"] = base64.b64decode(response_data["raw"]).decode('utf-8', errors='ignore')
                except:
                    continue
            
            # Get request method if available
            method = "UNKNOWN"
            if request_elem is not None:
                request_text = request_elem.text or ""
                if request_elem.get('base64', 'false') == 'true':
                    try:
                        request_text = base64.b64decode(request_text).decode('utf-8', errors='ignore')
                    except:
                        pass
                
                # Extract method from first line
                if request_text:
                    first_line = request_text.split('\n')[0]
                    method = first_line.split(' ')[0] if ' ' in first_line else "UNKNOWN"
            
            items.append({
                "index": idx,
                "url": url,
                "method": method,
                "response": response_data["raw"],
                "domain": urlparse(url).netloc if url else ""
            })
        
        return items
    except Exception as e:
        print(f"Error parsing XML file: {str(e)}")
        return []

def analyze_comments(items, extractor):
    """
    Analyze all responses and extract comments
    
    Args:
        items (list): List of parsed request/response items
        extractor (CommentExtractor): Comment extractor instance
        
    Returns:
        dict: Analysis results
    """
    results = {
        "total_responses": len(items),
        "responses_with_comments": 0,
        "total_comments": 0,
        "comments_by_type": defaultdict(list),
        "comments_by_category": defaultdict(list),
        "comments_by_domain": defaultdict(lambda: defaultdict(list)),
        "unique_comments": set(),
        "interesting_findings": [],
        "detailed_comments": []
    }
    
    for item in items:
        comments = extractor.extract_comments_from_text(item["response"])
        
        if comments:
            results["responses_with_comments"] += 1
            
            for comment_type, comment_list in comments.items():
                for comment in comment_list:
                    # Clean and normalize comment
                    cleaned_comment = ' '.join(comment.split())[:500]  # Limit length
                    
                    # Skip empty or whitespace-only comments
                    if not cleaned_comment or cleaned_comment.isspace():
                        continue
                    
                    results["total_comments"] += 1
                    
                    # Add to various collections
                    results["comments_by_type"][comment_type].append(cleaned_comment)
                    
                    # Categorize the comment
                    category = extractor.categorize_comment(cleaned_comment)
                    results["comments_by_category"][category].append(cleaned_comment)
                    
                    # Track by domain
                    results["comments_by_domain"][item["domain"]][comment_type].append(cleaned_comment)
                    
                    # Track unique comments
                    results["unique_comments"].add(cleaned_comment)
                    
                    # Store detailed info
                    results["detailed_comments"].append({
                        "index": item["index"],
                        "url": item["url"],
                        "method": item["method"],
                        "domain": item["domain"],
                        "type": comment_type,
                        "category": category,
                        "comment": cleaned_comment
                    })
                    
                    # Check for interesting findings
                    if category in ['Potential Sensitive', 'TODO/FIXME', 'Debug/Test', 'Hack/Workaround']:
                        results["interesting_findings"].append({
                            "url": item["url"],
                            "category": category,
                            "comment": cleaned_comment,
                            "type": comment_type
                        })
    
    return results

def save_comments_to_file(results, output_file):
    """
    Save all extracted comments to a organized text file
    
    Args:
        results (dict): Analysis results
        output_file (str): Output filename
    """
    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write("="*80 + "\n")
        f.write("BURP SUITE RESPONSE COMMENT EXTRACTION REPORT\n")
        f.write("="*80 + "\n\n")
        
        # Summary statistics
        f.write("SUMMARY STATISTICS\n")
        f.write("-"*80 + "\n")
        f.write(f"Total Responses Analyzed: {results['total_responses']}\n")
        f.write(f"Responses with Comments: {results['responses_with_comments']}\n")
        f.write(f"Total Comments Found: {results['total_comments']}\n")  # Fixed line
        f.write(f"Unique Comments: {len(results['unique_comments'])}\n\n")
        
        # Interesting findings section
        if results['interesting_findings']:
            f.write("\n" + "="*80 + "\n")
            f.write("INTERESTING FINDINGS (Potential Security Issues)\n")
            f.write("="*80 + "\n\n")
            
            for finding in results['interesting_findings']:
                f.write(f"Category: {finding['category']}\n")
                f.write(f"Type: {finding['type']}\n")
                f.write(f"URL: {finding['url']}\n")
                f.write(f"Comment: {finding['comment']}\n")
                f.write("-"*40 + "\n")
        
        # Comments by category
        f.write("\n" + "="*80 + "\n")
        f.write("COMMENTS BY CATEGORY\n")
        f.write("="*80 + "\n")
        
        for category in sorted(results['comments_by_category'].keys()):
            comments = results['comments_by_category'][category]
            f.write(f"\n{category} ({len(comments)} comments)\n")
            f.write("-"*40 + "\n")
            
            # Show unique comments in this category
            unique_in_category = list(set(comments))[:10]  # Limit to 10 examples
            for i, comment in enumerate(unique_in_category, 1):
                f.write(f"{i}. {comment}\n")
            
            if len(set(comments)) > 10:
                f.write(f"... and {len(set(comments)) - 10} more unique comments\n")
        
        # Comments by type
        f.write("\n" + "="*80 + "\n")
        f.write("COMMENTS BY TYPE\n")
        f.write("="*80 + "\n")
        
        for comment_type in sorted(results['comments_by_type'].keys()):
            comments = results['comments_by_type'][comment_type]
            f.write(f"\n{comment_type} ({len(comments)} total, {len(set(comments))} unique)\n")
            f.write("-"*40 + "\n")
            
            # Show first few unique examples
            unique_comments = list(set(comments))[:5]
            for i, comment in enumerate(unique_comments, 1):
                # Truncate long comments for display
                display_comment = comment[:200] + "..." if len(comment) > 200 else comment
                f.write(f"{i}. {display_comment}\n")
            
            if len(set(comments)) > 5:
                f.write(f"... and {len(set(comments)) - 5} more unique comments\n")
        
        # Comments by domain
        f.write("\n" + "="*80 + "\n")
        f.write("COMMENTS BY DOMAIN\n")
        f.write("="*80 + "\n")
        
        for domain in sorted(results['comments_by_domain'].keys()):
            domain_comments = results['comments_by_domain'][domain]
            total_domain_comments = sum(len(comments) for comments in domain_comments.values())
            
            f.write(f"\n{domain or 'No Domain'} ({total_domain_comments} comments)\n")
            f.write("-"*40 + "\n")
            
            for comment_type, comments in domain_comments.items():
                f.write(f"  {comment_type}: {len(comments)} comments\n")
        
        # All unique comments (deduplicated)
        f.write("\n" + "="*80 + "\n")
        f.write("ALL UNIQUE COMMENTS\n")
        f.write("="*80 + "\n\n")
        
        for i, comment in enumerate(sorted(results['unique_comments']), 1):
            f.write(f"{i}. {comment}\n")
        
        # Detailed comment list (optional - can be very long)
        f.write("\n" + "="*80 + "\n")
        f.write("DETAILED COMMENT LIST (First 100)\n")
        f.write("="*80 + "\n\n")
        
        for i, detail in enumerate(results['detailed_comments'][:100], 1):
            f.write(f"Comment #{i}\n")
            f.write(f"  URL: {detail['url']}\n")
            f.write(f"  Method: {detail['method']}\n")
            f.write(f"  Type: {detail['type']}\n")
            f.write(f"  Category: {detail['category']}\n")
            f.write(f"  Comment: {detail['comment']}\n")
            f.write("-"*40 + "\n")
        
        if len(results['detailed_comments']) > 100:
            f.write(f"\n... and {len(results['detailed_comments']) - 100} more comments\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write("END OF REPORT\n")
        f.write("="*80 + "\n")

def save_json_output(results, output_file):
    """
    Save results in JSON format
    """
    import json
    
    # Convert sets to lists for JSON serialization
    json_results = {
        "summary": {
            "total_responses": results["total_responses"],
            "responses_with_comments": results["responses_with_comments"],
            "total_comments": results["total_comments"],
            "unique_comments_count": len(results["unique_comments"])
        },
        "comments_by_type": {k: list(set(v)) for k, v in results["comments_by_type"].items()},
        "comments_by_category": {k: list(set(v)) for k, v in results["comments_by_category"].items()},
        "interesting_findings": results["interesting_findings"],
        "detailed_comments": results["detailed_comments"][:500]  # Limit for file size
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(json_results, f, indent=2, ensure_ascii=False)

def print_summary(results):
    """
    Print a summary to console
    """
    print("\n" + "="*60)
    print("COMMENT EXTRACTION SUMMARY")
    print("="*60)
    
    print(f"\nTotal Responses Analyzed: {results['total_responses']}")
    print(f"Responses with Comments: {results['responses_with_comments']}")
    print(f"Total Comments Found: {results['total_comments']}")
    print(f"Unique Comments: {len(results['unique_comments'])}")
    
    # Show comment type distribution
    print("\nComment Types Found:")
    for comment_type, comments in results['comments_by_type'].items():
        print(f"  {comment_type}: {len(comments)} ({len(set(comments))} unique)")
    
    # Show category distribution
    print("\nComment Categories:")
    for category, comments in results['comments_by_category'].items():
        print(f"  {category}: {len(comments)} comments")
    
    # Show interesting findings
    if results['interesting_findings']:
        print(f"\nInteresting Findings: {len(results['interesting_findings'])}")
        print("  Categories: " + ", ".join(set(f['category'] for f in results['interesting_findings'])))
    
    print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(
        description="Extract all comments from HTTP responses in Burp Suite XML files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s burp_output.xml
  %(prog)s burp_output.xml -o comments.txt
  %(prog)s burp_output.xml -o comments.json --json
  %(prog)s burp_output.xml --no-summary
        """
    )
    
    parser.add_argument("xml_file", help="Path to Burp Suite XML file")
    parser.add_argument("-o", "--output", default="extracted_comments.txt",
                       help="Output file for results (default: extracted_comments.txt)")
    parser.add_argument("--json", action="store_true",
                       help="Save output in JSON format instead of text")
    parser.add_argument("-s", "--summary", action="store_true", default=True,
                       help="Print summary to console (default: True)")
    parser.add_argument("--no-summary", dest="summary", action="store_false",
                       help="Don't print summary to console")
    
    args = parser.parse_args()
    
    # Initialize the comment extractor
    print(f"Initializing comment extractor...")
    extractor = CommentExtractor()
    
    # Parse the XML file
    print(f"Parsing Burp Suite XML file: {args.xml_file}")
    items = parse_burp_xml(args.xml_file)
    
    if not items:
        print("Error: No valid responses found in the XML file")
        sys.exit(1)
    
    print(f"Found {len(items)} responses to analyze...")
    
    # Analyze responses for comments
    print("Extracting comments from responses...")
    results = analyze_comments(items, extractor)
    
    # Print summary if requested
    if args.summary:
        print_summary(results)
    
    # Save results
    if args.json:
        output_file = args.output if args.output.endswith('.json') else args.output + '.json'
        save_json_output(results, output_file)
        print(f"\nResults saved to: {output_file} (JSON format)")
    else:
        output_file = args.output if args.output.endswith('.txt') else args.output
        save_comments_to_file(results, output_file)
        print(f"\nResults saved to: {output_file}")
    
    # Print quick stats
    if results['interesting_findings']:
        print(f"\n⚠️  Found {len(results['interesting_findings'])} potentially interesting comments!")
        print("Check the output file for details on potential security issues.")

if __name__ == "__main__":
    main()
