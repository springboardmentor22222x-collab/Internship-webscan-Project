# week5_comprehensive.py - Comprehensive Authentication Testing
from modules.crawler import IntelligentCrawler
from modules.auth_tester import ComprehensiveAuthenticationTester
from colorama import init, Fore
import json
import os

init(autoreset=True)

def run_comprehensive_auth_tests(use_ml=True):
    """Run comprehensive authentication tests with optional ML enhancement"""
    
    if use_ml:
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}   WEEK 5: COMPREHENSIVE AUTHENTICATION TESTING WITH AI/ML")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.MAGENTA}🤖 Machine Learning Models Enabled")
    else:
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}        WEEK 5: AUTHENTICATION & SESSION TESTING")
        print(f"{Fore.CYAN}{'='*70}")
    
    print(f"{Fore.YELLOW}[*] Initializing Authentication Security Scanner...")
    
    # Initialize crawler and login
    crawler = IntelligentCrawler("http://localhost:8088")
    
    if crawler.login_to_dvwa():
        print(f"{Fore.GREEN}[+] DVWA Login successful! Starting authentication tests...")
        
        # Initialize comprehensive authentication tester
        auth_tester = ComprehensiveAuthenticationTester(crawler.session)
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 1: Testing Weak/Default Credentials")
        print(f"{Fore.MAGENTA}{'═'*70}")
        weak_cred_results = auth_tester.test_weak_credentials(use_ml=use_ml)
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 2: Brute-Force Attack Simulation")
        print(f"{Fore.MAGENTA}{'═'*70}")
        brute_force_results = auth_tester.simulate_brute_force(username="admin", max_attempts=15, use_ml=use_ml)
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 3: Session Cookie Analysis")
        print(f"{Fore.MAGENTA}{'═'*70}")
        cookie_results = auth_tester.analyze_session_cookies(use_ml=use_ml)
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 4: Session Hijacking Testing")
        print(f"{Fore.MAGENTA}{'═'*70}")
        hijacking_results = auth_tester.test_session_hijacking(use_ml=use_ml)
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 5: Session Fixation Testing")
        print(f"{Fore.MAGENTA}{'═'*70}")
        fixation_results = auth_tester.test_session_fixation(use_ml=use_ml)
        
        print(f"\n{Fore.MAGENTA}{'═'*70}")
        print(f"{Fore.MAGENTA}    TASK 6: AI/ML Analysis & Report Generation")
        print(f"{Fore.MAGENTA}{'═'*70}")
        report = auth_tester.save_results(use_ml=use_ml)
        
        # Display comprehensive summary
        print(f"\n{Fore.GREEN}{'='*70}")
        if use_ml:
            print(f"{Fore.GREEN}         AI/ML ENHANCED TESTING COMPLETE!")
        else:
            print(f"{Fore.GREEN}           AUTHENTICATION TESTING COMPLETE!")
        print(f"{Fore.GREEN}{'='*70}")
        
        total_vulns = report['vulnerabilities_found']
        
        if total_vulns > 0:
            print(f"{Fore.RED}[!] FOUND {total_vulns} AUTHENTICATION VULNERABILITIES!")
            
            # Breakdown by severity
            high_count = len([v for v in report['vulnerabilities'] if v['severity'] == 'High'])
            medium_count = len([v for v in report['vulnerabilities'] if v['severity'] == 'Medium'])
            low_count = len([v for v in report['vulnerabilities'] if v['severity'] == 'Low'])
            
            print(f"\n{Fore.YELLOW}📊 Severity Breakdown:")
            print(f"{Fore.RED}   • High Severity: {high_count}")
            print(f"{Fore.YELLOW}   • Medium Severity: {medium_count}")
            print(f"{Fore.GREEN}   • Low Severity: {low_count}")
            
            print(f"\n{Fore.YELLOW}🔍 Top Vulnerability Types:")
            vuln_types = {}
            for vuln in report['vulnerabilities']:
                vuln_type = vuln['type']
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            for vuln_type, count in list(vuln_types.items())[:5]:
                print(f"{Fore.WHITE}   • {vuln_type}: {count}")
            
            print(f"\n{Fore.RED}⚠️  CRITICAL FINDINGS:")
            for vuln in report['vulnerabilities']:
                if vuln['severity'] == 'High':
                    print(f"{Fore.WHITE}   • {vuln['type']}: {vuln.get('evidence', '')}")
        
        else:
            print(f"{Fore.GREEN}[+] No authentication vulnerabilities detected.")
            print(f"{Fore.GREEN}✅ The application has strong authentication controls.")
        
        # AI/ML Insights
        if report['ai_ml_insights']:
            print(f"\n{Fore.CYAN}🤖 AI/ML SECURITY INSIGHTS:")
            for insight in report['ai_ml_insights']:
                print(f"{Fore.WHITE}   • {insight.get('type', 'Insight')}: {insight.get('finding', '')}")
        
        # Display ML-specific information if enabled
        if use_ml:
            print(f"\n{Fore.CYAN}🧠 MACHINE LEARNING STATISTICS:")
            print(f"{Fore.WHITE}   • Models Trained: {report.get('ml_statistics', {}).get('models_trained', 0)}")
            print(f"{Fore.WHITE}   • ML Insights Generated: {report.get('ml_statistics', {}).get('insights_generated', 0)}")
            print(f"{Fore.WHITE}   • Data Points Collected: {sum(report.get('data_collected', {}).values())}")
            
            print(f"\n{Fore.CYAN}📁 ML-GENERATED FILES:")
            ml_files = []
            if os.path.exists("ml_models"):
                ml_files.extend([f"ml_models/{f}" for f in os.listdir("ml_models")])
            if os.path.exists("ml_logs"):
                ml_files.extend([f"ml_logs/{f}" for f in os.listdir("ml_logs")])
            
            for file in ml_files[:3]:
                print(f"{Fore.WHITE}   • {file}")
        
        print(f"\n{Fore.CYAN}📁 Generated Reports & Evidence:")
        if use_ml:
            print(f"{Fore.WHITE}   1. output/auth_ml_report.html - ML-enhanced HTML report")
            print(f"{Fore.WHITE}   2. output/auth_ml_results.json - Detailed JSON results")
        else:
            print(f"{Fore.WHITE}   1. output/auth_report.html - Complete HTML report")
            print(f"{Fore.WHITE}   2. output/auth_results.json - Detailed JSON results")
        print(f"{Fore.WHITE}   3. output/bruteforce_logs.json - Brute-force attempt logs")
        print(f"{Fore.WHITE}   4. All screenshots should be captured manually")
        
        print(f"\n{Fore.YELLOW}🔧 OWASP Compliance Check:")
        print(f"{Fore.WHITE}   • A2:2017-Broken Authentication: {len([v for v in report['vulnerabilities'] if 'credential' in v['type'].lower() or 'brute' in v['type'].lower()])} issues")
        print(f"{Fore.WHITE}   • A3:2017-Sensitive Data Exposure: {len([v for v in report['vulnerabilities'] if 'cookie' in v['type'].lower() or 'session' in v['type'].lower()])} issues")
        
        print(f"\n{Fore.GREEN}✅ Mitigation Recommendations Summary:")
        recommendations = set()
        for vuln in report['vulnerabilities']:
            if 'recommendation' in vuln:
                recommendations.add(vuln['recommendation'])
        
        for i, rec in enumerate(list(recommendations)[:5], 1):
            print(f"{Fore.WHITE}   {i}. {rec}")
        
        # Save week completion marker
        filename = 'week5_ml_completed.txt' if use_ml else 'week5_completed.txt'
        with open(f'output/{filename}', 'w') as f:
            f.write(f"Week 5 completed at: {report['timestamp']}\n")
            f.write(f"Total vulnerabilities found: {total_vulns}\n")
            f.write(f"Tests performed: {len(report['tests_performed'])}\n")
            if use_ml:
                f.write(f"ML Models Used: {len(report.get('ml_models_used', []))}\n")
                f.write(f"ML Insights: {report.get('ml_statistics', {}).get('insights_generated', 0)}\n")
        
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}              WEEK 5: ALL TASKS COMPLETED!")
        print(f"{Fore.MAGENTA}{'='*70}")
       
        
        if use_ml:
            print(f"{Fore.GREEN}✅ Real ML models from scikit-learn implemented")
            print(f"{Fore.GREEN}✅ Model training and prediction demonstrated")
            print(f"{Fore.GREEN}✅ Advanced analytics with clustering and classification")
            print(f"{Fore.GREEN}✅ Models saved for future use and retraining")
        
        
        
    else:
        print(f"{Fore.RED}[-] Failed to login to DVWA!")
        print(f"{Fore.YELLOW}[*] Troubleshooting:")
        print(f"{Fore.WHITE}   1. Ensure DVWA is running: http://localhost:8088")
        print(f"{Fore.WHITE}   2. Reset database at: http://localhost:8088/setup.php")
        print(f"{Fore.WHITE}   3. Login with admin/password")
        print(f"{Fore.WHITE}   4. Set security level to LOW")

def run_basic_auth_tests():
    """Run basic authentication tests without ML"""
    run_comprehensive_auth_tests(use_ml=False)

def run_ml_enhanced_auth_tests():
    """Run ML-enhanced authentication tests"""
    run_comprehensive_auth_tests(use_ml=True)

if __name__ == "__main__":
    # You can choose which version to run
    print(f"{Fore.YELLOW}[*] Select testing mode:")
    print(f"{Fore.WHITE}   1. Basic Authentication Testing (No ML)")
    print(f"{Fore.WHITE}   2. ML-Enhanced Authentication Testing")
    
    choice = input(f"{Fore.CYAN}Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        run_basic_auth_tests()
    elif choice == "2":
        run_ml_enhanced_auth_tests()
    else:
        print(f"{Fore.YELLOW}[*] Defaulting to ML-enhanced testing...")
        run_ml_enhanced_auth_tests()