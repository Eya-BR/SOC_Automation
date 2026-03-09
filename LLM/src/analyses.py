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
from .rag_system import AdvancedRAGSystem

logger = logging.getLogger(__name__)

class AdvancedAnalyzer:
    """Professional-grade alert analyzer with ChromaDB RAG + Llama 3"""
    
    def __init__(self):
        """Initialize advanced analyzer"""
        self.tokens = APITokens()
        self.rag_system = AdvancedRAGSystem()
        
        # Check available APIs
        self.virustotal_available = self.tokens.is_configured('virustotal')
        logger.info(f"Advanced Analyzer initialized - VT: {self.virustotal_available}, RAG: ChromaDB")
    
    def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive alert analysis with professional RAG + Llama 3
        
        Args:
            alert_data: Security alert to analyze
            
        Returns:
            Comprehensive analysis with semantic understanding
        """
        try:
            alert_id = alert_data.get('_id', 'unknown')
            logger.info(f"Starting advanced analysis for alert: {alert_id}")
            
            # Step 1: Extract observables
            observables = self._extract_observables(alert_data)
            
            # Step 2: Get semantic RAG context
            rag_context = self.rag_system.retrieve_relevant_context(alert_data)
            
            # Step 3: VirusTotal analysis
            virustotal_analysis = self._analyze_virustotal(observables)
            
            # Step 4: Analyze with Llama 3 using enhanced context
            llama_analysis = self._analyze_with_llama3(alert_data, rag_context, virustotal_analysis)
            
            # Step 5: Generate comprehensive analysis
            final_analysis = self._generate_comprehensive_analysis(
                alert_data, observables, rag_context, virustotal_analysis, llama_analysis
            )
            
            logger.info(f"Advanced analysis completed for alert: {alert_id}")
            return final_analysis
            
        except Exception as e:
            logger.error(f"Advanced analysis error: {e}")
            return self._get_smart_fallback_analysis(alert_data)
    
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
        
        return None
    
    def _analyze_with_llama3(self, alert_data: Dict[str, Any], rag_context: List[Dict], vt_analysis: Dict) -> Dict[str, Any]:
        """Analyze alert with Llama 3 using enhanced semantic context"""
        try:
            # Build enhanced prompt with semantic context
            prompt = self._build_enhanced_prompt(alert_data, rag_context, vt_analysis)
            
            # Call Llama 3
            response = self._call_llama3(prompt)
            
            # Parse response
            return self._parse_llama3_response(response)
            
        except Exception as e:
            logger.error(f"Llama 3 analysis error: {e}")
            return self._get_fallback_llama3_analysis()
    
    def _build_enhanced_prompt(self, alert_data: Dict[str, Any], rag_context: List[Dict], vt_analysis: Dict) -> str:
        """Build enhanced prompt with semantic RAG context"""
        
        # Format RAG context
        rag_text = ""
        if rag_context:
            for item in rag_context:
                rag_text += f"\n[{item['type'].upper()}] {item['document']}"
                rag_text += f" (Similarity: {item['similarity']:.3f})"
                if item['metadata'].get('tags'):
                    rag_text += f" Tags: {', '.join(item['metadata']['tags'])}"
        
        # Format VirusTotal results
        vt_text = ""
        if vt_analysis.get('malicious_count', 0) > 0:
            vt_text = f"\n[VIRUSTOTAL] {vt_analysis['malicious_count']} malicious indicators detected"
            for finding in vt_analysis['malicious_findings']:
                vt_text += f"\n- {finding['type']}: {finding['value']} ({finding['positives']}/{finding['total']} engines)"
        
        prompt = f"""You are an expert cybersecurity analyst using Llama 3 with advanced Retrieval-Augmented Generation (RAG). Analyze this security alert:

ALERT DATA:
{json.dumps(alert_data, indent=2)}

SEMANTIC KNOWLEDGE (ChromaDB RAG):
{rag_text}

THREAT INTELLIGENCE (VirusTotal):
{vt_text}

Use the semantic knowledge and threat intelligence to provide comprehensive analysis in this exact JSON format:
{{
    "classification": {{
        "category": "malware|phishing|brute_force|reconnaissance|lateral_movement|data_exfiltration|persistence|privilege_escalation|legitimate",
        "severity": "critical|high|medium|low",
        "confidence": 0.0-1.0,
        "threat_type": "Brief description of the threat",
        "attack_patterns": ["Specific attack patterns detected"],
        "mitre_techniques": ["MITRE ATT&CK techniques matched"]
    }},
    "recommendations": {{
        "immediate_actions": ["Specific immediate actions to take"],
        "investigation_steps": ["Step-by-step investigation process"],
        "containment_strategies": ["How to contain the threat"],
        "prevention_measures": ["How to prevent similar incidents"]
    }},
    "risk_assessment": {{
        "business_impact": "low|medium|high|critical",
        "technical_impact": "low|medium|high|critical",
        "urgency": "low|medium|high|critical",
        "attack_surface": "Attack surface analysis"
    }},
    "semantic_analysis": {{
        "rag_matches": ["Semantic matches from ChromaDB"],
        "similarity_scores": ["Similarity scores for matches"],
        "context_understanding": "How well the system understood the context"
    }}
}}

IMPORTANT: Use the semantic RAG knowledge to provide deeper analysis than keyword matching. Focus on attack patterns, relationships, and contextual meaning. Respond ONLY with valid JSON. No explanations, no markdown, just JSON."""
        return prompt
    
    def _call_llama3(self, prompt: str) -> str:
        """Call Llama 3 via Ollama"""
        try:
            url = "http://localhost:11434/api/generate"
            payload = {
                "model": "llama3.2",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "max_tokens": 2000,
                    "repeat_penalty": 1.1
                }
            }
            
            response = requests.post(url, json=payload, timeout=60)
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                logger.error(f"Llama 3 API error: {response.status_code}")
                return ""
                
        except Exception as e:
            logger.error(f"Error calling Llama 3: {e}")
            return ""
    
    def _parse_llama3_response(self, response: str) -> Dict[str, Any]:
        """Parse Llama 3 response with improved JSON handling"""
        try:
            # Clean response
            response = response.strip()
            
            # Try to extract JSON from response
            if response.startswith('{') and response.endswith('}'):
                json_str = response
            else:
                # Look for JSON in the response
                start_idx = response.find('{')
                end_idx = response.rfind('}')
                
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    json_str = response[start_idx:end_idx + 1]
                else:
                    logger.error("No JSON found in Llama 3 response")
                    return self._get_fallback_llama3_analysis()
            
            # Parse JSON with error handling
            try:
                parsed = json.loads(json_str)
                return parsed
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error: {e}")
                logger.error(f"Response was: {json_str[:200]}...")
                
                # Try to fix common JSON issues
                try:
                    # Remove trailing commas
                    json_str = json_str.replace(',\n}', '\n}').replace(',}', '}')
                    json_str = json_str.replace(',\n]', '\n]').replace(',]', ']')
                    
                    parsed = json.loads(json_str)
                    logger.info("JSON parsing succeeded after cleanup")
                    return parsed
                except:
                    logger.error("JSON parsing failed even after cleanup")
                    return self._get_fallback_llama3_analysis()
            
        except Exception as e:
            logger.error(f"Error parsing Llama 3 response: {e}")
            return self._get_fallback_llama3_analysis()
    
    def _get_fallback_llama3_analysis(self) -> Dict[str, Any]:
        """Fallback analysis when Llama 3 fails"""
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
    
    def _calculate_threat_score(self, rag_context: List[Dict], vt_analysis: Dict, llama_analysis: Dict) -> float:
        """Calculate overall threat score"""
        score = 0.0
        
        # RAG contribution (30% weight)
        if rag_context:
            highest_similarity = max([item.get('similarity', 0) for item in rag_context])
            score += highest_similarity * 0.3
        
        # VirusTotal contribution (40% weight)
        if vt_analysis.get('status') == 'completed' and vt_analysis['malicious_count'] > 0:
            vt_score = min(vt_analysis['malicious_count'] * 0.2, 1.0)
            score += vt_score * 0.4
        
        # Llama 3 contribution (30% weight)
        if llama_analysis.get('classification', {}).get('confidence', 0) > 0:
            llama_score = llama_analysis['classification']['confidence']
            score += llama_score * 0.3
        
        return min(score, 1.0)
    
    def _determine_overall_severity(self, threat_score: float, llama_analysis: Dict, vt_analysis: Dict) -> str:
        """Determine overall severity"""
        if threat_score >= 0.8:
            return 'critical'
        elif threat_score >= 0.6:
            return 'high'
        elif threat_score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
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
                    'Review authentication logs for affected user',
                    'Check account activity patterns',
                    'Verify if this is expected behavior for user'
                ])
            elif category == 'privilege_escalation':
                recommendations['immediate_actions'].extend([
                    'Review privilege assignment and justification',
                    'Verify change management approval'
                ])
                recommendations['investigation_steps'].extend([
                    'Analyze privilege escalation timeline',
                    'Check for unauthorized privilege changes',
                    'Review account permissions and roles'
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
                'investigation_steps': ['Review alert details', 'Check system logs'],
                'containment_strategies': ['Monitor for suspicious activity'],
                'prevention_measures': ['Update security policies']
            }
        }
