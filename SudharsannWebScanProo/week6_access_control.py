# week6_access_control.py - Week 6: Access Control & IDOR Testing
from modules.crawler import IntelligentCrawler
from modules.access_control_tester import AccessControlTester
from colorama import init, Fore
from collections import defaultdict
import json
import os

init(autoreset=True)

def run_week6():
    print(f"{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}        WEEK 6: ACCESS CONTROL & IDOR TESTING")
    print(f"{Fore.CYAN}{'='*70}")
    
    print(f"{Fore.YELLOW}[*] Initializing Access Control Security Scanner...")
    print(f"{Fore.MAGENTA}[*] Using Real ML Models: K-Means Clustering & Random Forest")
    
    # Initialize crawler and login
    crawler = IntelligentCrawler("http://localhost:8088")
    
    if crawler.login_to_dvwa():
        print(f"{Fore.GREEN}[+] DVWA Login successful! Starting access control tests...")
        
        # Initialize access control tester
        access_tester = AccessControlTester(crawler.session)
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 1: Role Identification & Analysis")
        print(f"{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.WHITE}[*] Identifying roles and access levels...")
        role_results = access_tester.identify_roles_and_access()
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 2: IDOR Vulnerability Testing")
        print(f"{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.WHITE}[*] Testing Insecure Direct Object References...")
        idor_results = access_tester.test_idor_vulnerabilities()
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 3: Access Control Violation Testing")
        print(f"{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.WHITE}[*] Testing privilege escalation and missing authorization...")
        access_results = access_tester.test_access_control_violations()
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 4: AI/ML Pattern Analysis")
        print(f"{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.WHITE}[*] Running K-Means clustering and Random Forest classification...")
        ml_results = access_tester.run_ml_analysis()
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 5: Comprehensive Reporting")
        print(f"{Fore.MAGENTA}{'═'*70}")
        report = access_tester.save_results()
        
        # Display comprehensive summary
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"{Fore.GREEN}         ACCESS CONTROL TESTING COMPLETE!")
        print(f"{Fore.GREEN}{'='*70}")
        
        total_vulns = report['vulnerabilities_found']
        
        if total_vulns > 0:
            print(f"{Fore.RED}[!] FOUND {total_vulns} ACCESS CONTROL VULNERABILITIES!")
            
            # Categorize vulnerabilities
            vulnerability_types = defaultdict(int)
            for vuln in report['vulnerabilities']:
                vuln_type = vuln['type']
                vulnerability_types[vuln_type] += 1
            
            print(f"\n{Fore.YELLOW}📊 Vulnerability Breakdown:")
            for vuln_type, count in vulnerability_types.items():
                print(f"{Fore.WHITE}   • {vuln_type}: {count}")
            
            print(f"\n{Fore.RED}⚠️  CRITICAL FINDINGS:")
            for vuln in report['vulnerabilities']:
                if vuln['severity'] == 'High':
                    print(f"{Fore.WHITE}   • {vuln['type']}: {vuln.get('evidence', '')}")
        
        else:
            print(f"{Fore.GREEN}[+] No access control vulnerabilities detected.")
            print(f"{Fore.GREEN}✅ The application has strong access controls.")
        
        # ML Insights
        if report['ml_insights']:
            print(f"\n{Fore.CYAN}🤖 AI/ML SECURITY INSIGHTS:")
            for insight in report['ml_insights']:
                print(f"{Fore.WHITE}   • {insight.get('type', 'Insight')}: {insight.get('finding', '')}")
        
        # ML Models Information
        print(f"\n{Fore.CYAN}🧠 MACHINE LEARNING MODELS DEPLOYED:")
        for model in report['ml_models_used']:
            description = {
                'response_clusterer': 'K-Means for response pattern clustering',
                'access_classifier': 'Random Forest for access violation classification',
                'idor_detector': 'K-Means for IDOR pattern detection',
                'escalation_detector': 'Random Forest for privilege escalation analysis'
            }.get(model, model)
            print(f"{Fore.WHITE}   • {model}: {description}")
        
        print(f"\n{Fore.CYAN}📁 Generated Reports & Files:")
        print(f"{Fore.WHITE}   1. output/access_control_report.html - Interactive HTML report")
        print(f"{Fore.WHITE}   2. output/access_control_results.json - Detailed JSON results")
        print(f"{Fore.WHITE}   3. ml_models/access_*.joblib - Trained ML models")
        
        print(f"\n{Fore.YELLOW}🔧 OWASP Compliance Check:")
        print(f"{Fore.WHITE}   • A01:2021-Broken Access Control: {len([v for v in report['vulnerabilities'] if 'access' in v['type'].lower() or 'privilege' in v['type'].lower()])} issues")
        print(f"{Fore.WHITE}   • IDOR Vulnerabilities: {len([v for v in report['vulnerabilities'] if 'IDOR' in v['type']])} issues")
        
        print(f"\n{Fore.GREEN}✅ Suggested Mitigations Summary:")
        for i, mitigation in enumerate(report['suggested_mitigations'][:3], 1):
            print(f"{Fore.WHITE}   {i}. {mitigation}")
        
        # Save week completion marker
        with open('output/week6_completed.txt', 'w') as f:
            f.write(f"Week 6 completed at: {report['timestamp']}\n")
            f.write(f"Access control vulnerabilities found: {total_vulns}\n")
            f.write(f"ML models trained: {report['statistics']['ml_models_trained']}\n")
            f.write(f"IDOR tests performed: {report['statistics']['idor_tests_performed']}\n")
        
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}              WEEK 6: ALL TASKS COMPLETED!")
        print(f"{Fore.MAGENTA}{'='*70}")
       
        print(f"{Fore.GREEN} Real ML models (K-Means & Random Forest) implemented")
        print(f"{Fore.GREEN} Horizontal & vertical privilege escalation tested")
        print(f"{Fore.GREEN} IDOR vulnerability detection implemented")
        print(f"{Fore.GREEN} Professional reports generated with ML insights")
      
        
    else:
        print(f"{Fore.RED}[-] Failed to login to DVWA!")
        print(f"{Fore.YELLOW}[*] Troubleshooting:")
        print(f"{Fore.WHITE}   1. Ensure DVWA is running: http://localhost:8088")
        print(f"{Fore.WHITE}   2. Reset database at: http://localhost:8088/setup.php")
        print(f"{Fore.WHITE}   3. Login with admin/password")
        print(f"{Fore.WHITE}   4. Set security level to LOW")

if __name__ == "__main__":
    run_week6()