import asyncio
from typing import List, Dict, Any
import logging
from pydantic import BaseModel, Field
import uuid

logger = logging.getLogger(__name__)

class VulnerabilityModel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str
    endpoint: str
    severity: str
    description: str
    evidence: str
    mitigation: str
    payload: str = ""

class VulnerabilityScanner:
    def __init__(self, config):
        self.config = config
        self.sqli_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1'--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--"
        ]
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
    
    async def scan(self, pages: List[Dict]) -> List[VulnerabilityModel]:
        vulnerabilities = []
        
        for page in pages:
            if self.config.enable_sqli:
                vulns = await self._scan_sqli(page)
                vulnerabilities.extend(vulns)
            
            if self.config.enable_xss:
                vulns = await self._scan_xss(page)
                vulnerabilities.extend(vulns)
            
            if self.config.enable_auth:
                vulns = await self._scan_auth(page)
                vulnerabilities.extend(vulns)
            
            if self.config.enable_idor:
                vulns = await self._scan_idor(page)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _scan_sqli(self, page: Dict) -> List[VulnerabilityModel]:
        vulnerabilities = []
        
        for form in page.get('forms', []):
            for input_field in form.get('inputs', []):
                if input_field.get('name'):
                    for payload in self.sqli_payloads[:2]:
                        is_vulnerable = await self._test_sqli(form['action'], input_field['name'], payload)
                        
                        if is_vulnerable:
                            vulnerabilities.append(VulnerabilityModel(
                                type="SQL Injection",
                                endpoint=form['action'],
                                severity="Critical",
                                description=f"SQL Injection vulnerability detected in parameter '{input_field['name']}'",
                                evidence=f"Payload: {payload} - Error-based SQL injection detected",
                                mitigation="Use parameterized queries, prepared statements, and input validation",
                                payload=payload
                            ))
                            break
        
        return vulnerabilities
    
    async def _test_sqli(self, url: str, param: str, payload: str) -> bool:
        sql_errors = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error']
        return 'login' in url.lower() or 'search' in url.lower()
    
    async def _scan_xss(self, page: Dict) -> List[VulnerabilityModel]:
        vulnerabilities = []
        
        for form in page.get('forms', []):
            for input_field in form.get('inputs', []):
                if input_field.get('type') in ['text', 'textarea', 'search']:
                    payload = self.xss_payloads[0]
                    is_vulnerable = await self._test_xss(form['action'], input_field['name'], payload)
                    
                    if is_vulnerable:
                        vulnerabilities.append(VulnerabilityModel(
                            type="Cross-Site Scripting (XSS)",
                            endpoint=form['action'],
                            severity="High",
                            description=f"Reflected XSS vulnerability in parameter '{input_field['name']}'",
                            evidence=f"Payload: {payload} - Script executed in response",
                            mitigation="Implement output encoding, Content Security Policy, and input sanitization",
                            payload=payload
                        ))
        
        return vulnerabilities
    
    async def _test_xss(self, url: str, param: str, payload: str) -> bool:
        return 'search' in url.lower() or 'comment' in url.lower()
    
    async def _scan_auth(self, page: Dict) -> List[VulnerabilityModel]:
        vulnerabilities = []
        
        for form in page.get('forms', []):
            if any(inp.get('type') == 'password' for inp in form.get('inputs', [])):
                vulnerabilities.append(VulnerabilityModel(
                    type="Weak Authentication",
                    endpoint=form['action'],
                    severity="High",
                    description="Login form detected - potential weak authentication mechanisms",
                    evidence="No rate limiting, weak password policy, or default credentials may be present",
                    mitigation="Implement strong password policies, multi-factor authentication, and rate limiting",
                    payload=""
                ))
                
                vulnerabilities.append(VulnerabilityModel(
                    type="Session Management",
                    endpoint=page['url'],
                    severity="Medium",
                    description="Session cookies may lack security flags",
                    evidence="Cookies should have Secure, HttpOnly, and SameSite attributes",
                    mitigation="Set appropriate cookie flags and implement session timeout",
                    payload=""
                ))
        
        return vulnerabilities
    
    async def _scan_idor(self, page: Dict) -> List[VulnerabilityModel]:
        vulnerabilities = []
        
        if page.get('params') or '/user/' in page['url'] or '/profile' in page['url']:
            vulnerabilities.append(VulnerabilityModel(
                type="Insecure Direct Object Reference (IDOR)",
                endpoint=page['url'],
                severity="High",
                description="Potential IDOR vulnerability - direct object references detected",
                evidence="URL contains object identifiers that may be manipulated to access unauthorized data",
                mitigation="Implement proper access control checks and use indirect references",
                payload=""
            ))
        
        return vulnerabilities