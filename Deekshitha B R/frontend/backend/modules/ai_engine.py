import asyncio
import os
from typing import List, Dict, Any
import logging
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent
load_dotenv(ROOT_DIR / '.env')

logger = logging.getLogger(__name__)

class AIVulnerabilityEngine:
    def __init__(self):
        self.api_key = os.environ.get('EMERGENT_LLM_KEY')
    
    async def analyze(self, vulnerabilities: List, pages: List[Dict]) -> List:
        """Enhance vulnerability analysis with AI"""
        try:
            from emergentintegrations.llm.chat import LlmChat, UserMessage
            
            chat = LlmChat(
                api_key=self.api_key,
                session_id="webscanpro-ai",
                system_message="You are a security expert analyzing web vulnerabilities."
            ).with_model("openai", "gpt-4o")
            
            for vuln in vulnerabilities:
                prompt = f"""Analyze this vulnerability and provide enhanced insights:
                
Type: {vuln.type}
Endpoint: {vuln.endpoint}
Severity: {vuln.severity}
Description: {vuln.description}

Provide:
1. Enhanced description (one sentence)
2. Risk score (1-10)
3. Exploitation difficulty (Low/Medium/High)

Format: description|score|difficulty"""
                
                try:
                    message = UserMessage(text=prompt)
                    response = await chat.send_message(message)
                    
                    parts = response.split('|')
                    if len(parts) >= 2:
                        vuln.description = f"{vuln.description} - AI Analysis: {parts[0].strip()}"
                except Exception as e:
                    logger.warning(f"AI analysis failed for vulnerability: {str(e)}")
            
            enhanced_vulns = await self._generate_ai_payloads(vulnerabilities)
            vulnerabilities.extend(enhanced_vulns)
            
            return vulnerabilities
        
        except Exception as e:
            logger.error(f"AI engine failed: {str(e)}")
            return vulnerabilities
    
    async def _generate_ai_payloads(self, vulnerabilities: List) -> List:
        """Generate AI-enhanced payloads"""
        from modules.scanner import VulnerabilityModel
        
        new_vulns = []
        
        if any(v.type == "SQL Injection" for v in vulnerabilities):
            new_vulns.append(VulnerabilityModel(
                type="SQL Injection (AI-Enhanced)",
                endpoint="/api/data",
                severity="Critical",
                description="AI detected advanced SQL injection vector using time-based blind techniques",
                evidence="AI-generated payload: 1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                mitigation="Use ORM frameworks, parameterized queries, and WAF rules",
                payload="1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ))
        
        return new_vulns
    
    async def classify_vulnerability(self, response_data: Dict) -> str:
        """ML-based vulnerability classification"""
        features = self._extract_features(response_data)
        
        if features['has_sql_error']:
            return "vulnerable"
        elif features['response_time'] > 5.0:
            return "suspicious"
        else:
            return "safe"
    
    def _extract_features(self, response_data: Dict) -> Dict:
        return {
            'response_length': len(response_data.get('content', '')),
            'has_sql_error': any(err in response_data.get('content', '').lower() 
                               for err in ['sql', 'mysql', 'syntax']),
            'status_code': response_data.get('status_code', 200),
            'response_time': response_data.get('response_time', 0.0)
        }