"""
Professional MITRE ATT&CK Loader - Local Dataset + Periodic Updates
Best Practice: Version-controlled and periodically refreshed
"""

import json
import logging
import os
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class MITRELoader:
    """Professional MITRE ATT&CK loader using local dataset"""
    
    def __init__(self, data_path: str = "./data/knowledge"):
        self.data_path = data_path
        self.techniques_file = os.path.join(data_path, "mitre_techniques.json")
        self.last_updated_file = os.path.join(data_path, "mitre_last_updated.txt")
        self.techniques = []
        self.last_updated = "Unknown"
        
        # Load techniques on initialization
        self._load_techniques()
    
    def _load_techniques(self) -> bool:
        """Load MITRE techniques from local dataset"""
        try:
            if not os.path.exists(self.techniques_file):
                logger.warning(f"MITRE techniques file not found: {self.techniques_file}")
                return False
            
            with open(self.techniques_file, 'r', encoding='utf-8') as f:
                self.techniques = json.load(f)
            
            # Load last updated info
            if os.path.exists(self.last_updated_file):
                with open(self.last_updated_file, 'r') as f:
                    self.last_updated = f.read().strip()
            
            logger.info(f"Loaded {len(self.techniques)} MITRE techniques from local dataset")
            logger.info(f"Dataset last updated: {self.last_updated}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading MITRE techniques: {e}")
            return False
    
    def search_techniques(self, alert_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search for relevant MITRE techniques based on alert context"""
        try:
            # Build search query from alert data
            query = self._build_search_query(alert_data)
            
            # Search techniques using keyword matching
            relevant_techniques = []
            
            for technique in self.techniques:
                relevance_score = self._calculate_relevance(query, technique)
                if relevance_score > 0.3:  # Threshold for relevance
                    technique_copy = technique.copy()
                    technique_copy['relevance_score'] = relevance_score
                    technique_copy['match_reason'] = self._get_match_reason(query, technique)
                    relevant_techniques.append(technique_copy)
            
            # Sort by relevance score
            relevant_techniques.sort(key=lambda x: x['relevance_score'], reverse=True)
            
            # Return top 5 most relevant techniques
            result = relevant_techniques[:5]
            
            logger.info(f"Found {len(result)} relevant MITRE techniques for query: {query}")
            return result
            
        except Exception as e:
            logger.error(f"Error searching MITRE techniques: {e}")
            return []
    
    def _build_search_query(self, alert_data: Dict[str, Any]) -> str:
        """Build search query from alert data"""
        query_parts = []
        
        # Extract key information
        result = alert_data.get("result", {})
        user = result.get("user", "")
        host = result.get("host", "")
        privilege = result.get("Privileges", "")
        src_ip = result.get("src_ip", "")
        alert_name = alert_data.get("search_name", "")
        
        # Build query parts
        if user:
            query_parts.append(user)
        if host:
            query_parts.append(host)
        if privilege:
            query_parts.append(privilege)
        if alert_name:
            query_parts.append(alert_name)
        
        # Add context keywords
        if "privilege" in alert_name.lower():
            query_parts.extend(["privilege escalation", "elevation of privilege"])
        if "logon" in alert_name.lower():
            query_parts.extend(["logon", "authentication", "valid accounts"])
        if "admin" in user.lower():
            query_parts.extend(["administrator", "privileged account"])
        if user.endswith("$"):
            query_parts.extend(["machine account", "service account"])
        
        # Add IP-based keywords
        if src_ip:
            query_parts.extend(["network", "access", "connection"])
        
        # Add host-based keywords
        if host:
            if "dc" in host.lower() or "ad" in host.lower():
                query_parts.extend(["domain controller", "active directory"])
        
        query = " ".join(query_parts)
        
        # Debug logging
        logger.info(f"MITRE search query: '{query}' from user='{user}', host='{host}', alert='{alert_name}'")
        
        return query
    
    def _calculate_relevance(self, query: str, technique: Dict[str, Any]) -> float:
        """Calculate relevance score between query and technique"""
        score = 0.0
        query_lower = query.lower()
        
        # Debug logging for this technique
        technique_name = technique.get('name', '').lower()
        technique_tactics = [tactic.lower() for tactic in technique.get('tactics', [])]
        
        # Check name match
        name = technique.get('name', '').lower()
        name_match = any(word in name for word in query_lower.split() if len(word) > 2)
        if name_match:
            score += 0.5
            logger.debug(f"  Name match: '{technique_name}' contains words from query")
        
        # Check description match
        description = technique.get('description', '').lower()
        desc_words = description.split()
        matches = sum(1 for word in query_lower.split() if word in desc_words)
        if matches > 0:
            score += matches * 0.1
            logger.debug(f"  Description match: {matches} words in description")
        
        # Check tactics match
        if any(tactic in query_lower for tactic in technique_tactics):
            score += 0.3
            logger.debug(f"  Tactics match: {technique_tactics} contains query tactics")
        
        # Check detection methods match
        detection_methods = [dm.lower() for dm in technique.get('detection_methods', [])]
        if any(dm in query_lower for dm in detection_methods):
            score += 0.2
            logger.debug(f"  Detection methods match: found relevant method")
        
        logger.debug(f"  Final score for '{technique_name}': {score}")
        
        return min(score, 1.0)
    
    def _get_match_reason(self, query: str, technique: Dict[str, Any]) -> str:
        """Get reason for technique match"""
        reasons = []
        query_lower = query.lower()
        
        # Check name match
        name = technique.get('name', '').lower()
        if any(word in name for word in query_lower.split() if len(word) > 2):
            reasons.append("Name match")
        
        # Check tactics match
        tactics = [tactic.lower() for tactic in technique.get('tactics', [])]
        for tactic in tactics:
            if tactic in query_lower:
                reasons.append(f"Tactic: {tactic}")
        
        # Check description match
        description = technique.get('description', '').lower()
        if any(word in description for word in query_lower.split() if len(word) > 3):
            reasons.append("Description match")
        
        return "; ".join(reasons) if reasons else "General relevance"
    
    def get_technique_by_id(self, technique_id: str) -> Dict[str, Any]:
        """Get specific technique by ID"""
        for technique in self.techniques:
            if technique.get('id') == technique_id:
                return technique
        return {}
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Dict[str, Any]]:
        """Get all techniques for a specific tactic"""
        return [t for t in self.techniques if tactic.lower() in [tac.lower() for tac in t.get('tactics', [])]]
    
    def get_dataset_info(self) -> Dict[str, Any]:
        """Get dataset information"""
        return {
            "total_techniques": len(self.techniques),
            "last_updated": self.last_updated,
            "source": "MITRE ATT&CK Enterprise",
            "version": "1.0",
            "data_path": self.techniques_file,
            "tactics_count": len(set(tactic for technique in self.techniques for tactic in technique.get('tactics', [])))
        }
    
    def refresh_dataset(self) -> bool:
        """Refresh dataset from parsed file"""
        return self._load_techniques()

# Example usage
if __name__ == "__main__":
    loader = MITRELoader()
    
    # Test search
    test_alert = {
        "search_name": "AD - High Privilege Account Logon",
        "result": {
            "user": "Administrator",
            "host": "AD01",
            "Privileges": "SeSecurityPrivilege"
        }
    }
    
    techniques = loader.search_techniques(test_alert)
    print(f"Found {len(techniques)} relevant techniques")
    
    for technique in techniques:
        print(f"- {technique['id']}: {technique['name']} (Score: {technique['relevance_score']:.2f})")
        print(f"  Tactics: {', '.join(technique['tactics'])}")
        print(f"  Match: {technique['match_reason']}")
    
    # Show dataset info
    info = loader.get_dataset_info()
    print(f"\nDataset Info: {info}")
