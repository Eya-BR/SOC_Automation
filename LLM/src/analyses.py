"""
Advanced Real-Time Alert Analysis System

Combines professional RAG (ChromaDB) + VirusTotal + MITRE ATT&CK + Llama 3
"""

import logging
import json
import re
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

from .api_tokens import APITokens
from src.mitre_rag_loader import MiterRAGLoader
from .rag_system import AdvancedRAGSystem

logger = logging.getLogger(__name__)

class AdvancedAnalyzer:
    """Professional-grade alert analyzer with ChromaDB RAG + Llama 3"""
    
    def __init__(self):
        """Initialize advanced analyzer"""
        self.tokens = APITokens()
        self.rag_system = AdvancedRAGSystem()
        self.mitre_loader = MiterRAGLoader(self.rag_system)
        
        # Check available APIs
        self.virustotal_available = self.tokens.is_configured('virustotal')
        logger.info(f"Advanced Analyzer initialized - VT: {self.virustotal_available}, RAG: ChromaDB")
    
    def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security alert with enhanced context awareness"""
        try:
            # Extract alert ID from Splunk SID
            alert_id = alert_data.get("sid", "unknown")
            
            # Extract observables
            observables = self._extract_observables(alert_data)
            
            # Get RAG context
            rag_context = self.rag_system.retrieve_relevant_context(alert_data)
            
            # Get VirusTotal analysis (only if observables exist)
            vt_analysis = self._analyze_virustotal(observables) if self.virustotal_available and (observables.get('ips') or observables.get('domains') or observables.get('hashes')) else {"status": "skipped", "reason": "No relevant observables"}
            
            # Get Llama 3 analysis with context validation
            llama_analysis = self._analyze_with_llama_context_aware(alert_data, rag_context)
            
            # Calculate unified severity (trust Splunk source)
            final_severity = self._calculate_unified_severity(alert_data, llama_analysis, rag_context)
            
            # ENFORCE consistency - unified severity across all fields
            if llama_analysis.get("confidence", 0.0) < 0.3:
                # Low confidence LLM cannot override Splunk severity
                final_severity = "high"  # Trust Splunk detection
                llama_analysis["severity"] = final_severity
                llama_analysis["urgency"] = final_severity
                llama_analysis["business_impact"] = final_severity
                llama_analysis["technical_impact"] = final_severity
            else:
                # High confidence LLM - use unified severity
                unified_severity = self._calculate_unified_severity(alert_data, llama_analysis, rag_context)
                # Apply unified severity to ALL fields
                llama_analysis["severity"] = unified_severity
                llama_analysis["urgency"] = unified_severity
                llama_analysis["business_impact"] = unified_severity
                llama_analysis["technical_impact"] = unified_severity
                final_severity = unified_severity
            
            # Calculate coherent threat score based on final severity
            threat_score = self._calculate_coherent_threat_score(final_severity, llama_analysis.get("confidence", 0.0))
            
            # Generate context-aware recommendations (no duplication)
            recommendations = self._generate_contextual_recommendations(alert_data, llama_analysis, observables)
            
            # Add recommendations to llama_analysis for consistency
            llama_analysis["recommendations"] = recommendations
            
            # Build final analysis (trust Splunk, LLM enriches) - CLEAN STRUCTURE
            analysis = {
                "alert_id": alert_id,
                "analysis_timestamp": datetime.now().isoformat(),
                "source": {
                    "system": "Splunk",
                    "rule": alert_data.get("search_name", "Unknown"),
                    "source_severity": "high",  # Trust Splunk detection
                    "confidence": 0.9
                },
                "threat_score": threat_score,
                "overall_severity": final_severity,
                "observables": observables,
                "virustotal_analysis": vt_analysis,
                "llm_enrichment": {
                    "hypothesis": llama_analysis.get("hypothesis", "Unknown activity"),
                    "confidence": llama_analysis.get("confidence", 0.0),
                    "note": self._generate_context_note(alert_data),
                    "recommendations": llama_analysis.get("recommendations", {
                        "immediate_actions": [],
                        "investigation_steps": [],
                        "containment_strategies": [],
                        "prevention_measures": []
                    })
                },
                "summary": f"Splunk: {alert_data.get('search_name', 'Unknown')} | LLM: {llama_analysis.get('hypothesis', 'Unknown')} | Severity: {final_severity}"
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing alert: {e}")
            return {
                "error": str(e),
                "alert_id": alert_data.get("sid", "unknown"),
                "analysis_timestamp": datetime.now().isoformat(),
                "threat_score": 0.0,
                "overall_severity": "medium"
            }
    
    def _generate_context_note(self, alert_data: Dict[str, Any]) -> str:
        """Generate context-aware note for analysis"""
        user = alert_data.get("result", {}).get("user", "")
        host = alert_data.get("result", {}).get("host", "")
        
        if user.endswith("$"):
            return f"Machine account ({user}) detected, activity may be legitimate"
        elif "AD" in host or "DC" in host:
            return f"Domain Controller ({host}) detected, elevated privileges expected"
        else:
            return "Human account detected - requires investigation"
    
    def _calculate_coherent_threat_score(self, severity: str, confidence: float) -> float:
        """Calculate coherent threat score based on severity and confidence"""
        severity_scores = {
            "low": 0.2,
            "medium": 0.5, 
            "high": 0.8,
            "critical": 1.0
        }
        
        base_score = severity_scores.get(severity.lower(), 0.5)
        
        # Adjust based on confidence
        if confidence >= 0.7:
            return min(base_score + 0.2, 1.0)
        elif confidence >= 0.4:
            return base_score
        else:
            return max(base_score - 0.2, 0.1)
    
    def _detect_account_type(self, alert_data: Dict[str, Any]) -> str:
        """Detect if account is machine, human, or service"""
        try:
            user = alert_data.get("result", {}).get("user", "")
            if user.endswith("$"):
                return "machine_account"
            elif user.lower().startswith(("svc_", "service_", "mssql_", "iis_")):
                return "service_account"
            else:
                return "human_account"
        except:
            return "unknown"
    
    def _analyze_privilege_usage(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze privilege usage context"""
        try:
            privilege = alert_data.get("result", {}).get("Privileges", "")
            host = alert_data.get("result", {}).get("host", "")
            
            privilege_context = {
                "privilege": privilege,
                "risk_level": "medium",
                "legitimate_uses": [],
                "suspicious_indicators": []
            }
            
            # SeSecurityPrivilege analysis
            if "SeSecurityPrivilege" in privilege:
                privilege_context["legitimate_uses"] = [
                    "Domain Controller operations",
                    "Backup and restore operations", 
                    "Security audit log access",
                    "System monitoring tools"
                ]
                privilege_context["suspicious_indicators"] = [
                    "Usage by non-system accounts",
                    "Unexpected host usage",
                    "Outside maintenance windows"
                ]
                privilege_context["risk_level"] = "medium"
            
            # Check if host is likely Domain Controller
            if host and any(dc_indicator in host.upper() for dc_indicator in ["DC", "AD", "PDC", "BDC"]):
                privilege_context["legitimate_uses"].append("Domain Controller normal operations")
                privilege_context["risk_level"] = "low"
            
            return privilege_context
        except:
            return {"privilege": "unknown", "risk_level": "medium"}
    
    def _generate_validation_notes(self, alert_data: Dict[str, Any], observables: Dict) -> List[str]:
        """Generate context-aware validation notes"""
        notes = []
        
        try:
            account_type = self._detect_account_type(alert_data)
            user = alert_data.get("result", {}).get("user", "")
            host = alert_data.get("result", {}).get("host", "")
            privilege = alert_data.get("result", {}).get("Privileges", "")
            
            # Machine account validation
            if account_type == "machine_account":
                notes.append(f"Machine account detected ({user}) - activity may be legitimate")
                notes.append("Verify if this is expected service/system behavior")
            
            # Domain Controller validation
            if host and any(dc in host.upper() for dc in ["DC", "AD01"]):
                notes.append(f"Host {host} appears to be Domain Controller")
                notes.append("Elevated privileges may be normal for DC operations")
            
            # Privilege validation
            if "SeSecurityPrivilege" in privilege:
                notes.append("SeSecurityPrivilege allows access to security logs and audit data")
                notes.append("Commonly used by backup tools, monitoring agents, and system services")
            
            # General validation
            notes.append("Validate against change management and maintenance windows")
            notes.append("Check for concurrent legitimate activities")
            
        except Exception as e:
            notes.append(f"Validation error: {e}")
        
        return notes
    
    def _calculate_unified_severity(self, alert_data: Dict[str, Any], llama_analysis: Dict, rag_context: List[Dict]) -> str:
        """Calculate unified severity trusting Splunk source"""
        try:
            # Base severity from Splunk rule (trust the detection)
            alert_name = alert_data.get("search_name", "").lower()
            base_severity = "high" if "privilege escalation" in alert_name else "medium"
            
            # Account type modifier
            account_type = self._detect_account_type(alert_data)
            if account_type == "machine_account":
                base_severity = "medium"  # Lower risk for machine accounts
            elif account_type == "service_account":
                base_severity = "medium"  # Moderate risk for service accounts
            
            # Context modifiers
            host = alert_data.get("result", {}).get("host", "")
            if host and any(dc in host.upper() for dc in ["DC", "AD01"]):
                base_severity = "low"  # Lower risk for Domain Controllers
            
            # RAG confidence modifier
            rag_confidence = max([m.get("similarity", 0) for m in rag_context]) if rag_context else 0
            if rag_confidence > 0.8:
                # Keep current severity if high RAG confidence
                pass
            elif rag_confidence < 0.3:
                # Lower severity if low RAG confidence
                if base_severity == "critical":
                    base_severity = "high"
                elif base_severity == "high":
                    base_severity = "medium"
            
            return base_severity
            
        except Exception as e:
            logger.error(f"Error calculating unified severity: {e}")
            return "medium"
    
    def _extract_observables(self, alert_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract all observables from alert"""
        alert_text = str(alert_data).lower()
        
        observables = {
            'ips': self._extract_ips(alert_text),
            'domains': self._extract_domains(alert_text),
            'hashes': self._extract_hashes(alert_text),
            'urls': self._extract_urls(alert_text),
            'file_paths': self._extract_file_paths(alert_text),
            'commands': self._extract_commands(alert_text),
            'users': self._extract_users(alert_text),
            'processes': self._extract_processes(alert_text)
        }
        
        logger.info(f"Extracted observables: {observables}")
        return observables
    
    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, text)
        
        # Validate IPs
        valid_ips = []
        for ip in matches:
            parts = ip.split('.')
            if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        
        return list(set(valid_ips))
    
    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names"""
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        matches = re.findall(domain_pattern, text)
        
        # Filter out IPs
        domains = []
        for domain in matches:
            if not self._is_valid_ip(domain):
                domains.append(domain)
        
        return list(set(domains))
    
    def _extract_hashes(self, text: str) -> List[str]:
        """Extract file hashes"""
        text_upper = text.upper()
        
        patterns = [
            r'\b[A-F0-9]{32}\b',  # MD5
            r'\b[A-F0-9]{40}\b',  # SHA1
            r'\b[A-F0-9]{64}\b'   # SHA256
        ]
        
        hashes = []
        for pattern in patterns:
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
        # Windows paths
        windows_pattern = r'[A-Za-z]:\\[^<>:"|?*\s]*'
        # Unix paths
        unix_pattern = r'/[^<>:"|?*\s]*(?:\.[a-zA-Z0-9]+)?'
        
        matches = re.findall(windows_pattern, text) + re.findall(unix_pattern, text)
        return list(set(matches))
    
    def _extract_commands(self, text: str) -> List[str]:
        """Extract command lines"""
        command_patterns = [
            r'powershell\s+-[a-zA-Z]+\s+[^\s\]]+',
            r'cmd\.exe\s+/c\s+[^\s\]]+',
            r'ssh\s+[^\s\]]+',
            r'curl\s+[^\s\]]+',
            r'wget\s+[^\s\]]+',
            r'certutil\s+[^\s\]]+'
        ]
        
        commands = []
        for pattern in command_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            commands.extend(matches)
        
        return list(set(commands))
    
    def _extract_users(self, text: str) -> List[str]:
        """Extract user accounts"""
        user_patterns = [
            r'user[:\s]+["\']?([a-zA-Z0-9_\.]+)["\']?',
            r'account[:\s]+["\']?([a-zA-Z0-9_\.]+)["\']?',
            r'login[:\s]+as\s+([a-zA-Z0-9_\.]+)'
        ]
        
        users = []
        for pattern in user_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            users.extend(matches)
        
        return list(set(users))
    
    def _extract_processes(self, text: str) -> List[str]:
        """Extract process names"""
        process_patterns = [
            r'([a-zA-Z0-9_\-]+\.exe)',
            r'([a-zA-Z0-9_\-]+\.ps1)',
            r'([a-zA-Z0-9_\-]+\.bat)',
            r'([a-zA-Z0-9_\-]+\.cmd)',
            r'([a-zA-Z0-9_\-]+\.scr)'
        ]
        
        processes = []
        for pattern in process_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            processes.extend(matches)
        
        return list(set(processes))
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IP"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _analyze_virustotal(self, observables: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze observables with VirusTotal"""
        if not self.virustotal_available:
            return {'status': 'unavailable', 'reason': 'API key not configured'}
        
        vt_results = []
        
        # Check IPs
        for ip in observables.get('ips', []):
            result = self._check_virustotal_ip(ip)
            if result:
                vt_results.append(result)
        
        # Check domains
        for domain in observables.get('domains', []):
            result = self._check_virustotal_domain(domain)
            if result:
                vt_results.append(result)
        
        # Check hashes
        for hash_val in observables.get('hashes', []):
            result = self._check_virustotal_hash(hash_val)
            if result:
                vt_results.append(result)
        
        return {
            'status': 'completed',
            'total_checks': len(observables.get('ips', [])) + len(observables.get('domains', [])) + len(observables.get('hashes', [])),
            'malicious_findings': vt_results,
            'malicious_count': len(vt_results)
        }
    
    def _check_virustotal_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP with VirusTotal"""
        try:
            url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': self.tokens.VIRUSTOTAL_API_KEY,
                'ip': ip
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('positives', 0) > 0:
                    return {
                        'type': 'ip',
                        'value': ip,
                        'positives': data['positives'],
                        'total': data['total'],
                        'ratio': data['positives'] / data['total'],
                        'permalink': data.get('permalink', ''),
                        'scan_date': data.get('scan_date', '')
                    }
        except Exception as e:
            logger.error(f"VirusTotal IP check error: {e}")
        
        return None
    
    def _check_virustotal_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain with VirusTotal"""
        try:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': self.tokens.VIRUSTOTAL_API_KEY,
                'domain': domain
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('positives', 0) > 0:
                    return {
                        'type': 'domain',
                        'value': domain,
                        'positives': data['positives'],
                        'total': data['total'],
                        'ratio': data['positives'] / data['total'],
                        'permalink': data.get('permalink', ''),
                        'scan_date': data.get('scan_date', '')
                    }
        except Exception as e:
            logger.error(f"VirusTotal domain check error: {e}")
        
        return None
    
    def _check_virustotal_hash(self, hash_val: str) -> Optional[Dict[str, Any]]:
        """Check hash with VirusTotal"""
        try:
            url = "https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.tokens.VIRUSTOTAL_API_KEY,
                'resource': hash_val
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('positives', 0) > 0:
                    return {
                        'type': 'hash',
                        'value': hash_val[:8] + '...',
                        'positives': data['positives'],
                        'total': data['total'],
                        'ratio': data['positives'] / data['total'],
                        'permalink': data.get('permalink', ''),
                        'scan_date': data.get('scan_date', ''),
                        'file_type': data.get('filetype', 'unknown')
                    }
        except Exception as e:
            logger.error(f"VirusTotal hash check error: {e}")
        
        def _detect_account_type(self, alert_data: Dict[str, Any]) -> str:
        """Detect if account is machine, human, or service"""
        try:
            user = alert_data.get("result", {}).get("user", "")
            if user.endswith("$"):
                return "machine_account"
            elif user.lower().startswith(("svc_", "service_", "mssql_", "iis_")):
                return "service_account"
            else:
                return "human_account"
        except Exception as e:
            logger.error(f"Error detecting account type: {e}")
            return "unknown"
    
    def _determine_threat_type(self, rag_context: List[Dict], vt_analysis: Dict, llama_analysis: Dict) -> str:
        """Determine threat type"""
        # Check Llama 3 classification
        if llama_analysis.get('classification', {}).get('threat_type'):
            return llama_analysis['classification']['threat_type']
        
        # Check RAG context
        if rag_context:
            mitre_matches = [item for item in rag_context if item.get('type') == 'mitre_technique']
            if mitre_matches:
                top_match = mitre_matches[0]
                return f"MITRE ATT&CK: {top_match['metadata'].get('tactic', 'Unknown')} - {top_match['metadata'].get('name', 'Unknown')}"
        
        # Check VirusTotal
        if vt_analysis.get('malicious_count', 0) > 0:
            return "Malicious indicators detected"
        
        return "Suspicious activity detected"
    
    def _calculate_confidence(self, threat_score: float, rag_context: List[Dict], vt_analysis: Dict) -> float:
        """Calculate confidence in analysis"""
        confidence = threat_score
        
        # Boost confidence if multiple sources agree
        sources_confident = 0
        if rag_context:
            sources_confident += 0.3
        if vt_analysis.get('malicious_count', 0) > 0:
            sources_confident += 0.4
        
        return min(confidence + sources_confident * 0.1, 1.0)
    
    def _determine_urgency(self, severity: str, threat_score: float) -> str:
        """Determine urgency level"""
        if severity == 'critical':
            return 'immediate'
        elif severity == 'high':
            return 'high'
        elif severity == 'medium':
            return 'medium'
        else:
            return 'low'
    
    def _determine_business_impact(self, severity: str, vt_analysis: Dict) -> str:
        """Determine business impact"""
        if severity == 'critical' or vt_analysis.get('malicious_count', 0) > 2:
            return 'critical'
        elif severity == 'high' or vt_analysis.get('malicious_count', 0) > 0:
            return 'high'
        elif severity == 'medium':
            return 'medium'
        else:
            return 'low'
    
    def _analyze_attack_surface(self, alert_data: Dict[str, Any]) -> str:
        """Analyze attack surface"""
        observables = self._extract_observables(alert_data)
        
        surface_elements = []
        if observables['ips']:
            surface_elements.append(f"External IPs: {len(observables['ips'])}")
        if observables['domains']:
            surface_elements.append(f"External domains: {len(observables['domains'])}")
        if observables['processes']:
            surface_elements.append(f"Processes: {', '.join(observables['processes'][:3])}")
        if observables['urls']:
            surface_elements.append(f"URLs: {len(observables['urls'])}")
        if observables['hosts']:
            surface_elements.append(f"Hosts: {', '.join(observables['hosts'][:3])}")
        if observables['privileges']:
            surface_elements.append(f"Privileges: {', '.join(observables['privileges'][:3])}")
        
        return "; ".join(surface_elements) if surface_elements else "Local activity"
    
    def _normalize_severity(self, llama_severity: str, threat_score: float, vt_severity: str = "low") -> str:
        """Normalize severity from different sources"""
        severity_map = {
            "low": 1, "medium": 2, "high": 3, "critical": 4
        }
        
        # Map threat score to severity
        if threat_score <= 0.3:
            score_severity = 1
        elif threat_score <= 0.6:
            score_severity = 2
        elif threat_score <= 0.8:
            score_severity = 3
        else:
            score_severity = 4
        
        # Get maximum severity
        llama_val = severity_map.get(llama_severity.lower(), 1)
        vt_val = severity_map.get(vt_severity.lower(), 1)
        
        max_severity_val = max(llama_val, score_severity, vt_val)
        
        # Convert back to string
        reverse_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        return reverse_map[max_severity_val]
    
    def _generate_recommendations(self, alert_data: Dict[str, Any], rag_context: List[Dict], 
                              vt_analysis: Dict, llama_analysis: Dict) -> Dict[str, List[str]]:
        """Generate specific recommendations"""
        recommendations = {
            'immediate_actions': [],
            'investigation_steps': [],
            'containment_strategies': [],
            'prevention_measures': []
        }
        
        # RAG-based recommendations
        if rag_context:
            mitre_matches = [item for item in rag_context if item.get('type') == 'mitre_technique']
            if mitre_matches:
                top_match = mitre_matches[0]
                tactic = top_match['metadata'].get('tactic', '').lower()
                
                if 'initial access' in tactic:
                    recommendations['immediate_actions'].extend([
                        "Block source IPs/domains immediately",
                        "Review authentication logs",
                        "Enable multi-factor authentication"
                    ])
                    recommendations['prevention_measures'].extend([
                        "Implement email security filters",
                        "Conduct security awareness training",
                        "Deploy endpoint protection"
                    ])
                
                elif 'execution' in tactic:
                    recommendations['immediate_actions'].extend([
                        "Isolate affected systems",
                        "Review process execution logs",
                        "Check for persistence mechanisms"
                    ])
                    recommendations['containment_strategies'].extend([
                        "Disable suspicious scheduled tasks",
                        "Block command execution for non-admins"
                    ])
                
                elif 'credential access' in tactic:
                    recommendations['immediate_actions'].extend([
                        "Force password resets",
                        "Review account access logs",
                        "Enable account lockouts"
                    ])
                    recommendations['investigation_steps'].extend([
                        "Check for credential dumping tools",
                        "Review LSASS access patterns"
                    ])
        
        # VirusTotal-based recommendations
        if vt_analysis.get('malicious_count', 0) > 0:
            recommendations['immediate_actions'].extend([
                "Quarantine malicious files",
                "Block malicious IPs/domains",
                "Scan affected systems"
            ])
            recommendations['containment_strategies'].extend([
                "Implement network segmentation",
                "Deploy IDS/IPS rules"
            ])
        
        # Llama 3 recommendations
        if llama_analysis.get('recommendations'):
            llama_recs = llama_analysis['recommendations']
            for key in recommendations:
                if key in llama_recs:
                    recommendations[key].extend(llama_recs[key])
        
        # Remove duplicates
        for key in recommendations:
            recommendations[key] = list(set(recommendations[key]))
        
        return recommendations
    
    def _generate_summary(self, rag_context: List[Dict], vt_analysis: Dict, 
                        llama_analysis: Dict, threat_score: float) -> str:
        """Generate analysis summary"""
        summary_parts = []
        
        if rag_context:
            summary_parts.append(
                f"Semantic RAG: {len(rag_context)} matches (highest similarity: {max([item.get('similarity', 0) for item in rag_context]):.3f})"
            )
        
        if vt_analysis.get('malicious_count', 0) > 0:
            summary_parts.append(
                f"VirusTotal: {vt_analysis['malicious_count']} malicious indicators"
            )
        
        if llama_analysis.get('classification', {}).get('threat_type'):
            summary_parts.append(
                f"Llama 3: {llama_analysis['classification']['threat_type']}"
            )
        
        summary_parts.append(f"Overall threat score: {threat_score:.3f}")
        
        return " | ".join(summary_parts)
    
    def _get_smart_fallback_analysis(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Smart fallback analysis when Llama 3 is unavailable"""
        try:
            # Extract basic information
            search_name = alert_data.get('search_name', 'Unknown Alert')
            result = alert_data.get('result', {})
            
            # Extract observables
            observables = self._extract_observables(alert_data)
            
            # Get RAG context (includes SOC reasoning)
            try:
                rag_context = self.rag_system.retrieve_relevant_context(alert_data, max_results=5)
                mitre_techniques = [ctx for ctx in rag_context if ctx.get('type') == 'mitre_techniques']
                soc_reasoning = [ctx for ctx in rag_context if ctx.get('type') == 'security_knowledge' and 'account' in ctx.get('document', '').lower()]
            except:
                rag_context = []
                mitre_techniques = []
                soc_reasoning = []
            
            # Basic classification based on alert content
            alert_text = str(alert_data).lower()
            
            # Determine category
            if any(keyword in alert_text for keyword in ['authentication', 'login', 'ntlm', 'credential']):
                category = 'authentication'
            elif any(keyword in alert_text for keyword in ['privilege', 'escalation', 'admin', 'sudo']):
                category = 'privilege_escalation'
            elif any(keyword in alert_text for keyword in ['malware', 'virus', 'trojan']):
                category = 'malware'
            else:
                category = 'unknown'
            
            # Generate basic recommendations
            recommendations = {
                'immediate_actions': ['Investigate alert manually'],
                'investigation_steps': ['Review alert details'],
                'containment_strategies': ['Monitor for suspicious activity'],
                'prevention_measures': ['Update security policies']
            }
            
            if category == 'authentication':
                recommendations['immediate_actions'].extend([
                    'Verify user identity and authentication context',
                    'Check for concurrent sessions from different locations'
                ])
                recommendations['investigation_steps'].extend([
                    'Review authentication logs for the affected user',
                    'Check account activity patterns',
                    'Verify if this is expected behavior for the user'
                ])
            elif category == 'privilege_escalation':
                recommendations['immediate_actions'].extend([
                    'Verify if privilege escalation is authorized',
                    'Check user permissions and recent changes'
                ])
                recommendations['investigation_steps'].extend([
                    'Review privilege assignment logs',
                    'Check for unauthorized privilege changes',
                    'Analyze what actions were taken with elevated privileges'
                ])
            
            return {
                "classification": {
                    "category": category,
                    "severity": "medium",
                    "confidence": 0.6,
                    "threat_type": f"{category.replace('_', ' ').title()} detected",
                    "attack_patterns": [category],
                    "mitre_techniques": []
                },
                "recommendations": recommendations,
                "risk_assessment": {
                    "business_impact": "medium",
                    "technical_impact": "medium",
                    "urgency": "medium",
                    "attack_surface": self._calculate_attack_surface(observables)
                },
                "semantic_analysis": {
                    "rag_matches": [ctx.get('document', '') for ctx in rag_context[:3]],
                    "similarity_scores": {"RAG similarity": max([ctx.get('similarity', 0) for ctx in rag_context]) if rag_context else 0},
                    "context_understanding": "Smart fallback analysis with RAG context"
                }
            }
        except Exception as e:
            logger.error(f"Error in smart fallback: {e}")
            return self._get_basic_fallback_analysis()
    
    def _get_basic_fallback_analysis(self) -> Dict[str, Any]:
        """Basic fallback analysis when Llama 3 fails"""
        return {
            "classification": {
                "category": "unknown",
                "severity": "medium",
                "confidence": 0.5,
                "threat_type": "Unable to classify - Llama 3 unavailable",
                "attack_patterns": [],
                "mitre_techniques": []
            },
            "recommendations": {
                "immediate_actions": ["Investigate alert manually", "Check system logs"],
                "investigation_steps": ["Review alert details", "Analyze affected systems"],
                "containment_strategies": ["Monitor for suspicious activity"],
                "prevention_measures": ["Update security policies", "Enhance monitoring"]
            },
            "risk_assessment": {
                "business_impact": "medium",
                "technical_impact": "medium",
                "urgency": "medium",
                "attack_surface": "Unknown"
            },
            "semantic_analysis": {
                "rag_matches": [],
                "similarity_scores": {
                    "Similarity with ChromaDB knowledge base": 0.0,
                    "Similarity with VirusTotal threat intelligence": 0.0
                },
                "context_understanding": "Basic context analysis completed"
            }
        }
    
    def _generate_specific_recommendations(self, category: str, severity: str, 
                                        observables: Dict, mitre_techniques: List) -> Dict[str, List[str]]:
        """Generate specific recommendations based on alert type"""
        
        recommendations = {
            'immediate_actions': [],
            'investigation_steps': [],
            'containment_strategies': [],
            'prevention_measures': []
        }
        
        if category == 'authentication':
            recommendations['immediate_actions'].extend([
                'Verify user identity and authentication context',
                'Check for concurrent sessions from different locations'
            ])
            recommendations['investigation_steps'].extend([
                'Review authentication logs for the affected user',
                'Check account activity patterns',
                'Verify if this is expected behavior for the user'
            ])
            recommendations['containment_strategies'].extend([
                'Require multi-factor authentication if not already enabled',
                'Monitor for additional suspicious authentication attempts'
            ])
            
        elif category == 'privilege_escalation':
            recommendations['immediate_actions'].extend([
                'Verify if privilege escalation is authorized',
                'Check user permissions and recent changes'
            ])
            recommendations['investigation_steps'].extend([
                'Review privilege assignment logs',
                'Check for unauthorized privilege changes',
                'Analyze what actions were taken with elevated privileges'
            ])
            recommendations['containment_strategies'].extend([
                'Temporarily restrict user privileges if suspicious',
                'Enable enhanced monitoring on privileged accounts'
            ])
            
        elif category == 'network_anomaly':
            recommendations['immediate_actions'].extend([
                'Verify network device status and configuration',
                'Check for legitimate causes of traffic increase'
            ])
            recommendations['investigation_steps'].extend([
                'Analyze traffic patterns and sources',
                'Check for DDoS or scanning activities',
                'Review firewall logs for the time period'
            ])
            recommendations['containment_strategies'].extend([
                'Implement rate limiting if attack confirmed',
                'Block suspicious IP addresses if identified'
            ])
        
        # Add MITRE-specific recommendations
        if mitre_techniques:
            technique_names = [tech.get('metadata', {}).get('name', 'Unknown') for tech in mitre_techniques]
            recommendations['investigation_steps'].append(
                f'Investigate MITRE techniques: {", ".join(technique_names)}'
            )
        
        # Add severity-based measures
        if severity in ['high', 'critical']:
            recommendations['immediate_actions'].insert(0, 'Escalate to security team immediately')
            recommendations['containment_strategies'].insert(0, 'Consider temporary isolation if threat confirmed')
        
        # Default recommendations
        if not recommendations['immediate_actions']:
            recommendations['immediate_actions'].append('Review alert details and context')
        
        if not recommendations['investigation_steps']:
            recommendations['investigation_steps'].extend([
                'Review system logs',
                'Check for related alerts'
            ])
        
        if not recommendations['containment_strategies']:
            recommendations['containment_strategies'].append('Monitor for additional suspicious activity')
        
        if not recommendations['prevention_measures']:
            recommendations['prevention_measures'].append('Review and update security policies')
        
        return recommendations

    def _get_fallback_analysis(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback analysis when system fails"""
        return {
            'alert_id': alert_data.get('_id', 'unknown'),
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'threat_score': 0.5,
            'overall_severity': 'medium',
            'status': 'fallback',
            'error': 'Advanced analysis system unavailable',
            'recommendations': {
                'immediate_actions': ['Investigate alert manually'],
                'investigation_steps': ['Review alert details'],
                'containment_strategies': ['Monitor for suspicious activity'],
                'prevention_measures': ['Update security policies']
            }
        }
    
    def _analyze_with_llama_context_aware(self, alert_data: Dict[str, Any], rag_context: List[Dict]) -> Dict[str, Any]:
        """Context-aware Llama 3 analysis that avoids hallucinations"""
        try:
            # Extract key context
            user = alert_data.get("result", {}).get("user", "")
            host = alert_data.get("result", {}).get("host", "")
            privilege = alert_data.get("result", {}).get("Privileges", "")
            account_type = self._detect_account_type(alert_data)
            
            # Build context-aware prompt
            prompt = f"""Analyze this security alert with STRICT evidence requirements:

Alert Details:
- User: {user} ({account_type})
- Host: {host}
- Privilege: {privilege}
- Alert: {alert_data.get('search_name', 'Unknown')}

CRITICAL EVIDENCE RULES:
1. ONLY use facts from alert - NO assumptions beyond provided data
2. NEVER assume "attacker", "vulnerability", or "exploit" unless explicitly stated
3. Machine accounts (ending with $) are legitimate system accounts
4. SeSecurityPrivilege is used for legitimate system operations
5. If evidence is insufficient, state uncertainty and possible benign explanations
6. MITRE techniques: Do NOT generate - use "unknown" only

Account Type Rules:
- Machine accounts (ending with $) = legitimate system behavior
- Domain Controllers (AD01) = expected elevated privileges
- SeSecurityPrivilege = used for auditing and log management

Required JSON format:
{{
    "hypothesis": "Statement based ONLY on provided evidence",
    "confidence": 0.0-1.0,
    "evidence_available": true/false,
    "context_factors": ["observable factors only"],
    "legitimate_explanations": ["possible benign reasons"],
    "suspicious_indicators": ["indicators based on evidence"],
    "requires_investigation": true/false,
    "mitre_techniques": ["unknown"]
}}

RESPOND ONLY WITH VALID JSON. NO EXPLANATIONS."""
            
            response = self._call_llama3(prompt)
            if response:
                return self._parse_contextual_response(response, alert_data)
            else:
                return self._get_contextual_fallback_with_mitre(alert_data)
                
        except Exception as e:
            logger.error(f"Error in context-aware analysis: {e}")
            return self._get_contextual_fallback_with_mitre(alert_data)
    
    def _parse_contextual_response(self, response: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse contextual Llama 3 response"""
        try:
            # Extract JSON from response
            import json
            import re
            
            # Find JSON in response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                parsed = json.loads(json_str)
                
                # BLOCK LLM MITRE suggestions completely
                # Only use RAG-based MITRE mapping
                rag_mitre = self.mitre_loader.search_mitre_techniques(alert_data)
                
                # FORCE UNCERTAINTY for machine accounts - NO HALLUCINATIONS
                user = alert_data.get("result", {}).get("user", "")
                if user.endswith("$"):
                    # Machine account = legitimate behavior
                    parsed["hypothesis"] = f"SeSecurityPrivilege usage detected on host {alert_data.get('result', {}).get('host', 'Unknown')}"
                    parsed["confidence"] = 0.2  # Force low confidence
                    parsed["legitimate_explanations"] = ["Machine account performing legitimate operations", "System maintenance or service activity"]
                    parsed["suspicious_indicators"] = []
                    parsed["requires_investigation"] = False
                    # NO ATTACKER LANGUAGE
                    if "attacker" in parsed.get("hypothesis", "").lower():
                        parsed["hypothesis"] = "SeSecurityPrivilege usage detected on host"
                    if "exploit" in parsed.get("hypothesis", "").lower():
                        parsed["hypothesis"] = "SeSecurityPrivilege usage detected on host"
                    if "vulnerability" in parsed.get("hypothesis", "").lower():
                        parsed["hypothesis"] = "SeSecurityPrivilege usage detected on host"
                else:
                    # Human account - can be suspicious but still require evidence
                    if "attacker" in parsed.get("hypothesis", "").lower():
                        parsed["hypothesis"] = "Privilege usage detected - requires investigation"
                    parsed["confidence"] = min(parsed.get("confidence", 0.3), 0.5)  # Cap confidence
                
                # Ensure required fields with validated MITRE
                return {
                    "hypothesis": parsed.get("hypothesis", "Privilege usage detected"),
                    "confidence": float(parsed.get("confidence", 0.3)),  # Default to low confidence
                    "context_factors": parsed.get("context_factors", []),
                    "legitimate_explanations": parsed.get("legitimate_explanations", []),
                    "suspicious_indicators": parsed.get("suspicious_indicators", []),
                    "requires_investigation": parsed.get("requires_investigation", True),
                    "mitre_techniques": rag_mitre  # ONLY RAG techniques, no LLM suggestions
                }
            else:
                return self._get_contextual_fallback_with_rag(alert_data)
        except Exception as e:
            logger.error(f"Error parsing contextual response: {e}")
            return self._get_contextual_fallback_with_rag(alert_data)
    
    def _get_contextual_fallback(self) -> Dict[str, Any]:
        """Fallback contextual analysis"""
        return {
            "hypothesis": "Privilege usage detected - requires validation",
            "confidence": 0.4,
            "context_factors": ["Privilege escalation alert", "System activity"],
            "legitimate_explanations": ["System maintenance", "Service operations"],
            "suspicious_indicators": ["Unauthorized privilege usage"],
            "requires_investigation": True,
            "mitre_techniques": []  # Will be populated by RAG if needed
        }
    
    def _get_contextual_fallback_with_rag(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback contextual analysis with RAG-based MITRE mapping"""
        # Use RAG for MITRE techniques (always up-to-date)
        rag_mitre = self.mitre_loader.search_mitre_techniques(alert_data)
        
        return {
            "hypothesis": "Privilege usage detected - requires validation",
            "confidence": 0.4,
            "context_factors": ["Privilege escalation alert", "System activity"],
            "legitimate_explanations": ["System maintenance", "Service operations"],
            "suspicious_indicators": ["Unauthorized privilege usage"],
            "requires_investigation": True,
            "mitre_techniques": rag_mitre
        }
    
    def _validate_llm_suggestions(self, llm_suggestions: List, rag_results: List) -> List:
        """Validate LLM suggestions against RAG results"""
        validated = []
        rag_ids = {r.get('id', '') for r in rag_results}
        
        for suggestion in llm_suggestions:
            if isinstance(suggestion, str) and suggestion.startswith("T"):
                # Check if LLM suggestion exists in RAG results
                if suggestion in rag_ids:
                    validated.append({
                        "id": suggestion,
                        "name": next((r.get('name', '') for r in rag_results if r.get('id') == suggestion), ''),
                        "confidence": "medium",
                        "reason": "LLM suggestion validated by RAG"
                    })
                else:
                    # LLM hallucination - mark as low confidence
                    validated.append({
                        "id": suggestion,
                        "name": "Unknown technique",
                        "confidence": "low",
                        "reason": "LLM suggestion - not found in ATT&CK database"
                    })
        
        return validated
    
    def _get_contextual_fallback_with_mitre(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback contextual analysis with MITRE mapping"""
        # Generate context-based MITRE mapping (always provide techniques)
        mitre_mapping = self.mitre_loader.search_mitre_techniques(alert_data)
        
        return {
            "hypothesis": "Privilege usage detected - requires validation",
            "confidence": 0.4,
            "context_factors": ["Privilege escalation alert", "System activity"],
            "legitimate_explanations": ["System maintenance", "Service operations"],
            "suspicious_indicators": ["Unauthorized privilege usage"],
            "requires_investigation": True,
            "mitre_techniques": mitre_mapping  # Always provide relevant techniques from RAG
        }
    
    def _generate_contextual_recommendations(self, alert_data: Dict[str, Any], llama_analysis: Dict, observables: Dict) -> Dict[str, List[str]]:
        """Generate context-aware recommendations without duplication"""
        recommendations = {
            'immediate_actions': [],
            'investigation_steps': [],
            'containment_strategies': [],
            'prevention_measures': []
        }
        
        try:
            account_type = self._detect_account_type(alert_data)
            user = alert_data.get("result", {}).get("user", "")
            host = alert_data.get("result", {}).get("host", "")
            privilege = alert_data.get("result", {}).get("Privileges", "")
            requires_investigation = llama_analysis.get("requires_investigation", True)
            
            # Account type specific recommendations
            if account_type == "machine_account":
                recommendations['immediate_actions'].extend([
                    "Verify machine account activity is expected",
                    "Check service schedules and maintenance windows"
                ])
                recommendations['investigation_steps'].extend([
                    "Review service configuration",
                    "Validate against change management records"
                ])
            else:
                recommendations['immediate_actions'].extend([
                    "Verify user authorization for privilege usage",
                    "Check for concurrent legitimate activities"
                ])
                recommendations['investigation_steps'].extend([
                    "Review user account activity history",
                    "Validate privilege assignment justification"
                ])
            
            # Host-specific recommendations
            if host and any(dc in host.upper() for dc in ["DC", "AD01"]):
                recommendations['immediate_actions'].append("Verify Domain Controller normal operations")
                recommendations['containment_strategies'].append("Monitor for additional DC anomalies")
            
            # Privilege-specific recommendations
            if "SeSecurityPrivilege" in privilege:
                recommendations['investigation_steps'].extend([
                    "Review security log access patterns",
                    "Check backup and monitoring tool activity"
                ])
            
            # General recommendations
            if requires_investigation:
                recommendations['containment_strategies'].append("Enhanced monitoring of affected system")
                recommendations['prevention_measures'].extend([
                    "Implement principle of least privilege",
                    "Regular access reviews and audits"
                ])
            
            # Ensure at least one recommendation in each category
            if not recommendations['immediate_actions']:
                recommendations['immediate_actions'].append("Review alert context and validate activity")
            if not recommendations['investigation_steps']:
                recommendations['investigation_steps'].append("Analyze system logs for related activity")
            if not recommendations['containment_strategies']:
                recommendations['containment_strategies'].append("Monitor for additional suspicious activity")
            if not recommendations['prevention_measures']:
                recommendations['prevention_measures'].append("Review and update security policies")
                
        except Exception as e:
            logger.error(f"Error generating contextual recommendations: {e}")
            # Fallback recommendations
            recommendations = {
                'immediate_actions': ['Investigate alert manually'],
                'investigation_steps': ['Review alert details'],
                'containment_strategies': ['Monitor for suspicious activity'],
                'prevention_measures': ['Update security policies']
            }
        
        return recommendations
