from modules.crawler import IntelligentCrawler
from modules.scanner import WebScanner
from colorama import init, Fore
import os

init(autoreset=True)

def main():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}           WEK 2: TARGET SCANNING MODULE")
    print(f"{Fore.CYAN}{'='*60}")
    
    # Initialize crawler
    print(f"{Fore.YELLOW}[*] Initializing Intelligent Crawler...")
    crawler = IntelligentCrawler("http://localhost:8088")
    
    # Login to DVWA
    if crawler.login_to_dvwa():
        print(f"{Fore.GREEN}[+] Authentication successful!")
        
        # Start crawling
        print(f"{Fore.YELLOW}[*] Starting web application crawl...")
        crawler.crawl()
        
        # Add DVWA vulnerability pages
        print(f"{Fore.YELLOW}[*] Adding DVWA vulnerability pages...")
        crawler.get_dvwa_vulnerability_pages()
        
        # Save results
        print(f"{Fore.YELLOW}[*] Saving crawl results...")
        crawl_data = crawler.save_results()
        
        # Analyze results
        print(f"{Fore.YELLOW}[*] Analyzing discovered targets...")
        scanner = WebScanner(crawl_data)
        analysis = scanner.analyze()
        
        # Display summary
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}                 SCAN COMPLETE!")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.CYAN}📊 Summary:")
        print(f"{Fore.WHITE}   • Target URL: {analysis['summary']['target_url']}")
        print(f"{Fore.WHITE}   • Pages Crawled: {analysis['summary']['pages_crawled']}")
        print(f"{Fore.WHITE}   • Forms Discovered: {analysis['summary']['forms_found']}")
        print(f"{Fore.WHITE}   • Input Fields: {analysis['summary']['inputs_found']}")
        print(f"{Fore.WHITE}   • Injection Points: {analysis['summary']['injection_points']}")
        
        print(f"\n{Fore.YELLOW}📁 Output Files:")
        print(f"{Fore.WHITE}   1. output/target_report.html - Complete HTML report")
        print(f"{Fore.WHITE}   2. output/crawl_results.json - Raw crawl data")
        print(f"{Fore.WHITE}   3. output/target_analysis.json - Analysis data")
        print(f"{Fore.WHITE}   4. output/urls.txt - List of discovered URLs")
        
       
        
    else:
        print(f"{Fore.RED}[-] Failed to authenticate to DVWA!")
        print(f"{Fore.YELLOW}[*] Make sure DVWA is running at http://localhost:8088")
        print(f"{Fore.YELLOW}[*] Check if you need to create/reset database")

if __name__ == "__main__":
    main()