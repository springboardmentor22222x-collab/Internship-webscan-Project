# week4_xss.py - Week 4: XSS Testing Main Script
from modules.crawler import IntelligentCrawler
from modules.xss_tester import XSSTester
from colorama import init, Fore
import json
import os

init(autoreset=True)

def run_week4():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}       WEEK 4: CROSS-SITE SCRIPTING (XSS) TESTING")
    print(f"{Fore.CYAN}{'='*60}")
    
    # Initialize and login
    print(f"{Fore.YELLOW}[*] Initializing scanner and logging into DVWA...")
    crawler = IntelligentCrawler("http://localhost:8088")
    
    if crawler.login_to_dvwa():
        print(f"{Fore.GREEN}[+] Authentication successful!")
        
        # Initialize XSS tester
        xss_tester = XSSTester(crawler.session, "http://localhost:8088")
        
        # Load previously crawled data
        try:
            with open('output/crawl_results.json', 'r', encoding='utf-8') as f:
                crawl_data = json.load(f)
            print(f"{Fore.GREEN}[+] Loaded previous crawl data: {len(crawl_data['pages'])} pages, {len(crawl_data['forms'])} forms")
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[*] No previous crawl data found, performing quick crawl...")
            crawler.crawl()
            crawler.get_dvwa_vulnerability_pages()
            crawl_data = crawler.save_results()
        
        # Extract URLs and forms for testing
        urls = crawl_data['pages']
        forms = crawl_data['forms']
        
        print(f"{Fore.YELLOW}[*] Testing {len(urls)} URLs for Reflected XSS...")
        
        # Test all URLs for reflected XSS
        total_vulns = []
        for i, url in enumerate(urls, 1):
            print(f"{Fore.WHITE}[{i}/{len(urls)}] Testing URL: {url[:50]}...")
            
            # Skip non-HTML pages
            if any(url.endswith(ext) for ext in ['.jpg', '.png', '.css', '.js', '.ico']):
                continue
            
            vulns = xss_tester.test_url_reflected_xss(url)
            total_vulns.extend(vulns)
            
            # Show progress
            if vulns:
                print(f"{Fore.RED}[!] Found {len(vulns)} XSS vulnerabilities on this page")
        
        print(f"{Fore.YELLOW}[*] Testing {len(forms)} forms for XSS...")
        
        # Test all forms for XSS
        form_vulns = []
        for i, form in enumerate(forms, 1):
            print(f"{Fore.WHITE}[{i}/{len(forms)}] Testing form on: {form['page_url'][:50]}...")
            vulns = xss_tester.test_form_reflected_xss(form)
            form_vulns.extend(vulns)
            
            if vulns:
                print(f"{Fore.RED}[!] Found {len(vulns)} XSS vulnerabilities in this form")
        
        total_vulns.extend(form_vulns)
        
        # Specifically test DVWA XSS pages
        print(f"{Fore.YELLOW}[*] Running targeted DVWA XSS tests...")
        dvwa_vulns = xss_tester.test_dvwa_xss_pages()
        total_vulns.extend(dvwa_vulns)
        
        # Save results
        xss_tester.vulnerabilities = total_vulns
        results = xss_tester.save_results()
        
        # Display comprehensive summary
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}           XSS TESTING COMPLETE!")
        print(f"{Fore.GREEN}{'='*60}")
        
        if results['total_vulnerabilities'] > 0:
            print(f"{Fore.RED}[!] FOUND {results['total_vulnerabilities']} XSS VULNERABILITIES!")
            print(f"{Fore.YELLOW}📊 Vulnerability Breakdown:")
            
            # Count by type
            type_count = {}
            for vuln in results['vulnerabilities']:
                xss_type = vuln['type']
                type_count[xss_type] = type_count.get(xss_type, 0) + 1
            
            for xss_type, count in type_count.items():
                print(f"{Fore.WHITE}   • {xss_type}: {count}")
            
            # Count by severity
            high_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])
            print(f"\n{Fore.RED}⚠️  {high_count} HIGH severity vulnerabilities require immediate attention!")
            
            # Show top 3 vulnerable pages
            print(f"\n{Fore.YELLOW}🔍 Top Vulnerable Pages:")
            page_vulns = {}
            for vuln in results['vulnerabilities']:
                page = vuln['url']
                page_vulns[page] = page_vulns.get(page, 0) + 1
            
            sorted_pages = sorted(page_vulns.items(), key=lambda x: x[1], reverse=True)[:3]
            for page, count in sorted_pages:
                print(f"{Fore.WHITE}   • {page[:50]}... ({count} vulnerabilities)")
        
        else:
            print(f"{Fore.GREEN}[+] No XSS vulnerabilities detected.")
            print(f"{Fore.GREEN}✅ The application appears to be secure against XSS attacks.")
            print(f"{Fore.YELLOW}[*] Note: This test focuses on reflected XSS. Consider additional testing for stored and DOM-based XSS.")
        
        print(f"\n{Fore.CYAN}📁 Generated Reports:")
        print(f"{Fore.WHITE}   1. output/xss_report.html - Complete HTML report with remediation guidance")
        print(f"{Fore.WHITE}   2. output/xss_results.json - Detailed JSON results")
        print(f"{Fore.WHITE}   3. All previous reports are preserved in output/ directory")
        
        print(f"\n{Fore.YELLOW}🔧 Testing Methodology:")
        print(f"{Fore.WHITE}   • Tested {len(urls)} URLs for reflected XSS")
        print(f"{Fore.WHITE}   • Tested {len(forms)} forms for XSS")
        print(f"{Fore.WHITE}   • Used {results['payloads_tested']} different XSS payloads")
        print(f"{Fore.WHITE}   • Targeted DVWA XSS-specific pages")
        
       
        
        # Save week completion marker
        with open('output/week4_completed.txt', 'w') as f:
            f.write(f"Week 4 completed at: {results['timestamp']}\n")
            f.write(f"Total XSS vulnerabilities found: {results['total_vulnerabilities']}\n")
        
    else:
        print(f"{Fore.RED}[-] Failed to authenticate to DVWA!")
        print(f"{Fore.YELLOW}[*] Troubleshooting steps:")
        print(f"{Fore.WHITE}   1. Ensure DVWA is running: http://localhost:8088")
        print(f"{Fore.WHITE}   2. Access http://localhost:8088/setup.php and click 'Create/Reset Database'")
        print(f"{Fore.WHITE}   3. Login with admin/password")
        print(f"{Fore.WHITE}   4. Set security level to LOW")

if __name__ == "__main__":
    run_week4()