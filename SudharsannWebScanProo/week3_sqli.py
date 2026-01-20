from modules.crawler import IntelligentCrawler
from modules.sqli_tester import SQLInjectionTester
from colorama import init, Fore
import json

init(autoreset=True)

def run_week3():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}           WEEK 3: SQL INJECTION TESTING")
    print(f"{Fore.CYAN}{'='*60}")
    
    # Initialize and login
    print(f"{Fore.YELLOW}[*] Initializing scanner and logging into DVWA...")
    crawler = IntelligentCrawler("http://localhost:8088")
    
    if crawler.login_to_dvwa():
        print(f"{Fore.GREEN}[+] Authentication successful!")
        
        # Initialize SQLi tester
        tester = SQLInjectionTester(crawler.session, "http://localhost:8088")
        
        # Load previously crawled data or crawl fresh
        try:
            with open('output/crawl_results.json', 'r', encoding='utf-8') as f:
                crawl_data = json.load(f)
            print(f"{Fore.GREEN}[+] Loaded previous crawl data")
        except:
            print(f"{Fore.YELLOW}[*] No previous crawl data found, performing quick crawl...")
            crawler.crawl()
            crawler.get_dvwa_vulnerability_pages()
            crawl_data = crawler.save_results()
        
        # Extract URLs and forms for testing
        urls = crawl_data['pages']
        forms = crawl_data['forms']
        
        print(f"{Fore.YELLOW}[*] Testing {len(urls)} URLs for SQL Injection...")
        
        # Test all URLs
        total_vulns = []
        for i, url in enumerate(urls, 1):
            print(f"{Fore.WHITE}[{i}/{len(urls)}] Testing: {url}")
            vulns = tester.test_get_parameters(url)
            total_vulns.extend(vulns)
        
        # Test all forms
        print(f"{Fore.YELLOW}[*] Testing {len(forms)} forms for SQL Injection...")
        form_vulns = tester.test_post_forms(forms)
        total_vulns.extend(form_vulns)
        
        # Specifically test DVWA SQLi page
        print(f"{Fore.YELLOW}[*] Running targeted DVWA SQL Injection test...")
        dvwa_vulns = tester.test_dvwa_sqli()
        total_vulns.extend(dvwa_vulns)
        
        # Save results
        tester.vulnerabilities = total_vulns
        results = tester.save_results()
        
        # Display summary
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}           SQL INJECTION TEST COMPLETE!")
        print(f"{Fore.GREEN}{'='*60}")
        
        if results['total_vulnerabilities'] > 0:
            print(f"{Fore.RED}[!] FOUND {results['total_vulnerabilities']} SQL INJECTION VULNERABILITIES!")
            high_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])
            medium_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Medium'])
            
            print(f"{Fore.YELLOW}📊 Vulnerability Breakdown:")
            print(f"{Fore.RED}   • High Severity: {high_count}")
            print(f"{Fore.YELLOW}   • Medium Severity: {medium_count}")
            
            print(f"\n{Fore.RED}⚠️  Immediate action required!")
        else:
            print(f"{Fore.GREEN}[+] No SQL Injection vulnerabilities detected.")
            print(f"{Fore.GREEN}✅ The application appears to be secure against SQLi attacks.")
        
        print(f"\n{Fore.CYAN}📁 Generated Reports:")
        print(f"{Fore.WHITE}   1. output/sqli_report.html - Complete HTML report")
        print(f"{Fore.WHITE}   2. output/sqli_results.json - Detailed JSON results")
        
        print(f"\n{Fore.YELLOW}🔍 Sample Vulnerabilities Found:")
        if results['vulnerabilities']:
            for vuln in results['vulnerabilities'][:3]:  # Show first 3
                print(f"{Fore.WHITE}   • {vuln['type']} on {vuln['parameter']} ({vuln['severity']})")
        else:
            print(f"{Fore.WHITE}   • None detected")
        
        
    else:
        print(f"{Fore.RED}[-] Failed to authenticate to DVWA!")
        print(f"{Fore.YELLOW}[*] Make sure DVWA is running at http://localhost:8088")
        print(f"{Fore.YELLOW}[*] Access http://localhost:8088/setup.php and click 'Create/Reset Database'")

if __name__ == "__main__":
    run_week3()