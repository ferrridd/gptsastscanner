#!/usr/bin/env python3
import os
import argparse
import json
import logging
from datetime import datetime
from gpt_sast.scanner import GPTSASTScanner

def setup_logging(verbose=False):
    """Configure logging settings"""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('gpt_sast.log')
        ]
    )

def main():
    parser = argparse.ArgumentParser(description='GPT-powered SAST Scanner with Data Flow Analysis')
    parser.add_argument('project_path', help='Path to the project to scan')
    parser.add_argument('--api-key', help='OpenAI API key')
    parser.add_argument('--model', default='gpt-4', help='GPT model to use')
    parser.add_argument('--output', help='Output file for results (JSON)')
    parser.add_argument('--html-report', help='Generate HTML report (specify path)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--max-file-size', type=int, default=100000, help='Maximum file size in bytes to scan')
    parser.add_argument('--max-files', type=int, help='Maximum number of files to scan')
    parser.add_argument('--scan-all', action='store_true', help='Scan all source files instead of just critical ones')
    parser.add_argument('--concurrent-scans', type=int, default=3, help='Number of concurrent scans')
    parser.add_argument('--no-cache', action='store_true', help='Disable caching')
    parser.add_argument('--confidence-threshold', type=float, default=0.7, 
                        help='Confidence threshold for vulnerabilities (0.0-1.0)')
    
    args = parser.parse_args()
    
    # Set up logging
    setup_logging(args.verbose)
    logger = logging.getLogger('gpt_sast')
    
    # Get API key from arguments or environment
    api_key = args.api_key or os.environ.get('OPENAI_API_KEY')
    if not api_key:
        logger.error("OpenAI API key is required. Provide it with --api-key or set OPENAI_API_KEY environment variable.")
        return
    
    db_path = None if args.no_cache else ".scan_cache.db"
    
    start_time = datetime.now()
    logger.info(f"Scan started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Create scanner instance
    scanner = GPTSASTScanner(
        api_key, 
        args.model, 
        db_path=db_path,
        concurrent_scans=args.concurrent_scans,
        confidence_threshold=args.confidence_threshold
    )
    
    # Run the scan
    results = scanner.scan_project(
        args.project_path,
        max_file_size=args.max_file_size,
        max_files=args.max_files,
        scan_all=args.scan_all
    )
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    results["scan_duration_seconds"] = duration
    
    logger.info(f"Scan completed in {duration:.2f} seconds")
    logger.info(f"Found {results['vulnerabilities_found']} vulnerabilities")
    
    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
    
    # Generate HTML report if requested
    if args.html_report:
        from gpt_sast.reporting import generate_html_report
        generate_html_report(results, args.html_report)
        logger.info(f"HTML report generated: {args.html_report}")

if __name__ == "__main__":
    main()