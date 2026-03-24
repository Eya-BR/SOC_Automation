"""
Fixed Clean SOC Analyzer - No Duplicates, Uses Model LLM for Recommendations
"""

import logging
import json
import re
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

from .api_tokens import APITokens
from .mitre_loader import MITRELoader
from .rag_system import AdvancedRAGSystem

logger = logging.getLogger(__name__)

class Analyzer:
    """Clean analyzer - uses model LLM for contextual recommendations"""
    
    def __init__(self):
        """Initialize analyzer"""
        self.tokens = APITokens()
        self.rag_system = AdvancedRAGSystem()
        self.mitre_loader = MITRELoader()
        self.virustotal_available = self.tokens.is_configured('virustotal')
        logger.info(f"Analyzer initialized - VT: {self.virustotal_available}")
    
    def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alert with model LLM recommendations - FIXED no contradictory severity"""
        try:
            alert_id = alert_data.get("sid", "unknown")
            observables = self._extract_observables(alert_data)
            rag_context = self.rag_system.retrieve_relevant_context(alert_data)
            vt_analysis = self._analyze_virustotal(observables) if self.virustotal_available and (observables.get('ips') or observables.get('domains') or observables.get('hashes')) else {"status": "skipped", "reason": "No relevant observables"}
            
            # Model LLM analysis with contextual recommendations
            llama_analysis = self._analyze_with_model_llm(alert_data)
            
            # Get MITRE techniques
            rag_mitre = self.mitre_loader.search_techniques(alert_data)
            
            # REMOVED: contradictory threat_score and overall_severity
            # Let LLM decide severity completely
            
            # Get recommendations from model LLM
            recommendations = llama_analysis.get("recommendations", self._get_fallback_recommendations(alert_data))
            
            # GUARANTEED CLEAN OUTPUT - NO DUPLICATES, NO CONTRADICTORY SEVERITY
            return {
                "alert_id": alert_id,
                "analysis_timestamp": datetime.now().isoformat(),
                "source": {
                    "system": "Splunk",
                    "rule": alert_data.get("search_name", "Unknown"),
                    "source_severity": "high",
                    "confidence": 0.9
                },
                # REMOVED: threat_score and overall_severity to avoid contradiction
                "observables": observables,
                "virustotal_analysis": vt_analysis,
                "llm_enrichment": {
                    "hypothesis": llama_analysis.get("hypothesis", "Activity detected"),
                    "confidence": llama_analysis.get("confidence", 0.0),
                    "severity": llama_analysis.get("severity", "medium"),  # LLM decides severity
                    "mitre_techniques": rag_mitre,
                    "recommendations": recommendations
                },
                "summary": f"Splunk: {alert_data.get('search_name', 'Unknown')} | LLM: {llama_analysis.get('hypothesis', 'Unknown')} | Severity: {llama_analysis.get('severity', 'medium')}"
            }
            
        except Exception as e:
            logger.error(f"Error in fixed analysis: {e}")
            return {
                "error": str(e),
                "alert_id": alert_data.get("sid", "unknown"),
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    def _analyze_with_model_llm(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze using model LLM for contextual recommendations - FIXED with count consideration"""
        try:
            # Prepare context for the model
            user = alert_data.get("result", {}).get("user", "")
            host = alert_data.get("result", {}).get("host", "")
            src_ip = alert_data.get("result", {}).get("src_ip", "")
            count = alert_data.get("result", {}).get("count", "1")
            privilege = alert_data.get("result", {}).get("Privileges", "")
            alert_name = alert_data.get("search_name", "Unknown")
            
            # Build context prompt for model - FIXED with better SOC logic
            context_prompt = f"""
You are a senior SOC analyst analyzing a security alert.

Alert Context:
- User: {user}
- Host: {host}
- Source IP: {src_ip}
- Attempt Count: {count}
- Privilege: {privilege}
- Alert Type: {alert_name}

Account Analysis:
- Machine Account: {user.endswith("$")}
- Domain Controller: {"DC" in host.upper() or "AD01" in host}
- Administrator Account: {"admin" in user.lower() or "administrator" in user.lower()}
- Internal IP: {self._is_private_ip(src_ip)}

Critical Assessment:
- Count of attempts: {count} ({"CRITICAL: Multiple logons - potential brute force or lateral movement" if int(count) > 1 else "Single logon - normal activity"})
- IP Type: {"Internal network traffic" if self._is_private_ip(src_ip) else "External IP - higher suspicion"}
- Account Type: {"High-privilege administrator account" if "admin" in user.lower() else "Standard user account"}
- Host Type: {"Domain Controller - high-value target" if "DC" in host.upper() or "AD01" in host else "Standard server"}

SOC Analysis Guidelines:
1. Be factual and specific - use actual values, not "unknown"
2. Consider context: internal IPs are less suspicious than external
3. Account for count: multiple logons = higher severity
4. Recommendations should be proportional to threat level
5. For medium alerts: verify and investigate, don't isolate immediately

Provide analysis in JSON format:
{{
    "hypothesis": "Specific factual description of what happened",
    "confidence": 0.0-1.0,
    "severity": "low|medium|high|critical",
    "recommendations": {{
        "immediate_actions": ["action1", "action2"],
        "investigation_steps": ["step1", "step2"],
        "containment_strategies": ["strategy1"],
        "prevention_measures": ["measure1", "measure2"]
    }}
}}
"""
            
            # Call the model LLM API - Local Ollama with Llama 3
            url = "http://localhost:11434/api/generate"
            payload = {
                "model": "llama3.2",
                "prompt": context_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "max_tokens": 500
                }
            }
            
            response = requests.post(url, json=payload, timeout=60)
            if response.status_code == 200:
                result = response.json()
                response_text = result.get("response", "")
                return self._parse_llm_response(response_text)
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return self._get_fallback_analysis(alert_data)
                
        except Exception as e:
            logger.error(f"Error calling Ollama: {e}")
            return self._get_fallback_analysis(alert_data)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            # Fallback to basic string check if ipaddress module fails
            if not ip or not isinstance(ip, str):
                return False
            
            # Check private IP ranges manually
            if ip.startswith("10."):
                return True
            elif ip.startswith("172."):
                # Check 172.16.0.0 to 172.31.255.255
                parts = ip.split(".")
                if len(parts) == 4 and parts[1].isdigit():
                    second_octet = int(parts[1])
                    return 16 <= second_octet <= 31
            elif ip.startswith("192.168."):
                return True
            return False
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """Parse LLM response text into structured format"""
        try:
            # Try to extract JSON from response
            import re
            
            # Look for JSON pattern in response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                parsed = json.loads(json_str)
                
                # Ensure required fields
                return {
                    "hypothesis": parsed.get("hypothesis", "Activity detected"),
                    "confidence": float(parsed.get("confidence", 0.5)),
                    "severity": parsed.get("severity", "medium"),
                    "recommendations": parsed.get("recommendations", self._get_fallback_recommendations({}))
                }
            else:
                # Fallback: extract from text
                return {
                    "hypothesis": response_text[:200] + "..." if len(response_text) > 200 else response_text,
                    "confidence": 0.5,
                    "severity": "medium",
                    "recommendations": self._get_fallback_recommendations({})
                }
                
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            return {
                "hypothesis": "Analysis completed",
                "confidence": 0.3,
                "severity": "medium",
                "recommendations": self._get_fallback_recommendations({})
            }
    
    def _get_fallback_analysis(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback analysis when LLM fails"""
        user = alert_data.get("result", {}).get("user", "")
        host = alert_data.get("result", {}).get("host", "")
        
        return {
            "hypothesis": f"Security activity detected on host {host}",
            "confidence": 0.3,
            "severity": "medium",
            "recommendations": self._get_fallback_recommendations(alert_data)
        }
    
    def _get_fallback_recommendations(self, alert_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Get fallback recommendations when model LLM is unavailable"""
        user = alert_data.get("result", {}).get("user", "")
        host = alert_data.get("result", {}).get("host", "")
        
        recommendations = {
            'immediate_actions': [],
            'investigation_steps': [],
            'containment_strategies': [],
            'prevention_measures': []
        }
        
        # Machine account recommendations
        if user.endswith("$"):
            recommendations['immediate_actions'].append("Verify machine account activity is expected")
            recommendations['investigation_steps'].append("Review service configuration")
        else:
            recommendations['immediate_actions'].append("Verify user authorization for privilege usage")
            recommendations['investigation_steps'].append("Review user account activity history")
        
        # Domain Controller recommendations
        if host and any(dc in host.upper() for dc in ["DC", "AD01"]):
            recommendations['containment_strategies'].append("Monitor for additional DC anomalies")
        
        # General prevention
        recommendations['prevention_measures'].append("Implement principle of least privilege")
        
        return recommendations
    
    def _generate_context_note(self, alert_data: Dict[str, Any]) -> str:
        """Generate context-aware note"""
        user = alert_data.get("result", {}).get("user", "")
        host = alert_data.get("result", {}).get("host", "")
        
        if user.endswith("$"):
            return f"Machine account ({user}) detected, activity may be legitimate"
        elif "AD" in host or "DC" in host:
            return f"Domain Controller ({host}) detected, elevated privileges expected"
        else:
            return "Human account detected - requires investigation"
    
    def _calculate_severity(self, alert_data: Dict[str, Any], llama_analysis: Dict) -> str:
        """Calculate severity - consistent logic"""
        user = alert_data.get("result", {}).get("user", "")
        
        # Machine accounts get lower severity
        if user.endswith("$"):
            return "low"
        
        # Base on alert name
        alert_name = alert_data.get("search_name", "").lower()
        if "privilege escalation" in alert_name:
            return "medium"
        else:
            return "low"
    
    def _calculate_threat_score(self, severity: str, confidence: float) -> float:
        """Calculate threat score"""
        severity_scores = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
        base_score = severity_scores.get(severity, 0.5)
        
        if confidence >= 0.7:
            return min(base_score + 0.2, 1.0)
        elif confidence >= 0.4:
            return base_score
        else:
            return max(base_score - 0.2, 0.1)
    
    def _extract_observables(self, alert_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract observables from alert - FIXED with user and host"""
        alert_text = str(alert_data).lower()
        
        observables = {
            'ips': self._extract_ips(alert_text),
            'domains': self._extract_domains(alert_text),
            'hashes': self._extract_hashes(alert_text),
            'urls': self._extract_urls(alert_text),
            'file_paths': self._extract_file_paths(alert_text),
            'commands': self._extract_commands(alert_text),
            'users': self._extract_users(alert_data),  # FIXED: Pass alert_data directly
            'processes': self._extract_processes(alert_text),
            'hosts': self._extract_hosts(alert_data)  # NEW: Extract hosts
        }
        
        return observables
    
    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, text)
        valid_ips = []
        
        for ip in matches:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        
        return list(set(valid_ips))
    
    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names"""
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        matches = re.findall(domain_pattern, text)
        return list(set(matches))
    
    def _extract_hashes(self, text: str) -> List[str]:
        """Extract file hashes"""
        text_upper = text.upper()
        
        hash_patterns = [
            r'\b[A-F0-9]{32}\b',  # MD5
            r'\b[A-F0-9]{40}\b',  # SHA1
            r'\b[A-F0-9]{64}\b',  # SHA256
        ]
        
        hashes = []
        for pattern in hash_patterns:
            matches = re.findall(pattern, text_upper)
            hashes.extend(matches)
        
        return list(set(hashes))
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        matches = re.findall(url_pattern, text, re.IGNORECASE)
        return list(set(matches))
    
    def _extract_file_paths(self, text: str) -> List[str]:
        """Extract file paths"""
        windows_pattern = r'[A-Za-z]:\\[^<>"{}|\\^`\[\]]*'
        unix_pattern = r'/[^<>"{}|\\^`\[\]]*'
        matches = re.findall(windows_pattern, text) + re.findall(unix_pattern, text)
        return list(set(matches))
    
    def _extract_commands(self, text: str) -> List[str]:
        """Extract command lines"""
        command_patterns = [
            r'powershell\s+-[a-zA-Z]+\s+[^\s\]]+',
            r'cmd\.exe\s+[^\s\]]+',
            r'wscript\.exe\s+[^\s\]]+',
            r'cscript\.exe\s+[^\s\]]+'
        ]
        
        commands = []
        for pattern in command_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            commands.extend(matches)
        
        return list(set(commands))
    
    def _extract_users(self, alert_data: Dict[str, Any]) -> List[str]:
        """Extract user accounts - FIXED to get from alert data directly"""
        users = []
        
        # Get user from result field
        result = alert_data.get("result", {})
        user = result.get("user", "")
        if user:
            users.append(user)
        
        # Also try extraction from text as fallback
        alert_text = str(alert_data).lower()
        user_patterns = [
            r'user[:\s]+["\']?([a-zA-Z0-9_\.]+)["\']?',
            r'account[:\s]+["\']?([a-zA-Z0-9_\.]+)["\']?',
            r'([a-zA-Z0-9_\.]+)\\[a-zA-Z0-9_\.]+'
        ]
        
        for pattern in user_patterns:
            matches = re.findall(pattern, alert_text, re.IGNORECASE)
            users.extend(matches)
        
        return list(set(users))
    
    def _extract_hosts(self, alert_data: Dict[str, Any]) -> List[str]:
        """Extract host names - NEW function"""
        hosts = []
        
        # Get host from result field
        result = alert_data.get("result", {})
        host = result.get("host", "")
        if host:
            hosts.append(host)
        
        # Also try extraction from text as fallback
        alert_text = str(alert_data).lower()
        host_patterns = [
            r'host[:\s]+["\']?([a-zA-Z0-9\-\.]+)["\']?',
            r'server[:\s]+["\']?([a-zA-Z0-9\-\.]+)["\']?',
            r'computer[:\s]+["\']?([a-zA-Z0-9\-\.]+)["\']?'
        ]
        
        for pattern in host_patterns:
            matches = re.findall(pattern, alert_text, re.IGNORECASE)
            hosts.extend(matches)
        
        return list(set(hosts))
    
    def _extract_processes(self, text: str) -> List[str]:
        """Extract process names"""
        process_patterns = [
            r'([a-zA-Z0-9_\-]+\.exe)',
            r'process[:\s]+["\']?([a-zA-Z0-9_\-]+)["\']?'
        ]
        
        processes = []
        for pattern in process_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            processes.extend(matches)
        
        return list(set(processes))
    
    def _analyze_virustotal(self, observables: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze observables with VirusTotal"""
        if not self.virustotal_available:
            return {'status': 'unavailable', 'reason': 'API key not configured'}
        
        vt_results = []
        
        # Check IPs
        for ip in observables.get('ips', [])[:5]:
            result = self._check_virustotal_ip(ip)
            if result:
                vt_results.append(result)
        
        # Check domains
        for domain in observables.get('domains', [])[:5]:
            result = self._check_virustotal_domain(domain)
            if result:
                vt_results.append(result)
        
        # Check hashes
        for hash_val in observables.get('hashes', [])[:5]:
            result = self._check_virustotal_hash(hash_val)
            if result:
                vt_results.append(result)
        
        return {
            'status': 'completed',
            'total_checks': len(vt_results),
            'malicious_findings': [r for r in vt_results if r.get('positives', 0) > 0],
            'malicious_count': len([r for r in vt_results if r.get('positives', 0) > 0])
        }
    
    def _check_virustotal_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP with VirusTotal"""
        try:
            url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': self.tokens.get_all_tokens()['virustotal'],
                'ip': ip
            }
            
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {
                    'type': 'ip',
                    'value': ip,
                    'positives': data.get('positives', 0),
                    'total': data.get('total', 0),
                    'ratio': data.get('positives', 0) / max(data.get('total', 1), 1),
                    'permalink': data.get('permalink', '')
                }
        except Exception as e:
            logger.error(f"VirusTotal IP check error: {e}")
        
        return None
    
    def _check_virustotal_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain with VirusTotal"""
        try:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': self.tokens.get_all_tokens()['virustotal'],
                'domain': domain
            }
            
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {
                    'type': 'domain',
                    'value': domain,
                    'positives': data.get('positives', 0),
                    'total': data.get('total', 0),
                    'ratio': data.get('positives', 0) / max(data.get('total', 1), 1),
                    'permalink': data.get('permalink', '')
                }
        except Exception as e:
            logger.error(f"VirusTotal domain check error: {e}")
        
        return None
    
    def _check_virustotal_hash(self, hash_val: str) -> Optional[Dict[str, Any]]:
        """Check hash with VirusTotal"""
        try:
            url = "https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.tokens.get_all_tokens()['virustotal'],
                'resource': hash_val
            }
            
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {
                    'type': 'hash',
                    'value': hash_val,
                    'positives': data.get('positives', 0),
                    'total': data.get('total', 0),
                    'ratio': data.get('positives', 0) / max(data.get('total', 1), 1),
                    'permalink': data.get('permalink', ''),
                    'scan_date': data.get('scan_date', ''),
                    'file_type': data.get('filetype', 'unknown')
                }
        except Exception as e:
            logger.error(f"VirusTotal hash check error: {e}")
        
        return None
