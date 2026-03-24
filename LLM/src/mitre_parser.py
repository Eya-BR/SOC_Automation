"""
MITRE ATT&CK Parser - Professional Local Dataset Management
Best Practice: Local JSON + Periodic Updates
"""

import json
import logging
from typing import List, Dict, Any
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class MITREParser:
    """Professional MITRE ATT&CK dataset manager"""
    
    def __init__(self, data_path: str = "./data/knowledge"):
        self.data_path = data_path
        self.mitre_file = os.path.join(data_path, "mitre_attack.json")
        self.parsed_file = os.path.join(data_path, "mitre_techniques.json")
        self.last_updated_file = os.path.join(data_path, "mitre_last_updated.txt")
        
    def parse_mitre_dataset(self) -> bool:
        """Parse MITRE dataset into clean techniques format"""
        try:
            if not os.path.exists(self.mitre_file):
                logger.error(f"MITRE dataset not found: {self.mitre_file}")
                return False
            
            logger.info("Loading MITRE ATT&CK dataset...")
            with open(self.mitre_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            techniques = []
            
            # Handle bundle format
            if isinstance(data, dict) and data.get('type') == 'bundle':
                objects = data.get('objects', [])
                logger.info(f"Found bundle with {len(objects)} objects")
            else:
                objects = data if isinstance(data, list) else []
                logger.info(f"Found {len(objects)} objects")
            
            # Process techniques from MITRE data
            for obj in objects:
                if isinstance(obj, dict) and obj.get('type') == 'attack-pattern' and obj.get('id', '').startswith('attack-pattern--'):
                    technique = self._process_technique(obj)
                    if technique:
                        techniques.append(technique)
            
            logger.info(f"Parsed {len(techniques)} MITRE techniques")
            
            # Save parsed techniques
            with open(self.parsed_file, 'w', encoding='utf-8') as f:
                json.dump(techniques, f, indent=2, ensure_ascii=False)
            
            # Update last_updated timestamp
            with open(self.last_updated_file, 'w') as f:
                f.write(f"2026-03-24\n")
                f.write(f"Total techniques: {len(techniques)}\n")
                f.write(f"Source: MITRE ATT&CK Enterprise\n")
            
            logger.info(f"MITRE techniques saved to: {self.parsed_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error parsing MITRE dataset: {e}")
            return False
    
    def _process_technique(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Process individual MITRE technique"""
        try:
            # Get technique ID (Txxxx format)
            technique_id = "Unknown"
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id', 'Unknown')
                    break
            
            # Get tactics
            tactics = []
            if 'kill_chain_phases' in obj:
                for phase in obj['kill_chain_phases']:
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactics.append(phase.get('phase_name', 'Unknown'))
            
            # Get description
            description = obj.get('description', '')
            
            # Get detection methods (if available)
            detection_methods = []
            if 'x_mitre_detection' in obj:
                detection_methods = obj['x_mitre_detection']
            
            # Get mitigation methods
            mitigation_methods = []
            if 'x_mitre_mitigation' in obj:
                mitigation_methods = obj['x_mitre_mitigation']
            
            # Build technique object
            technique = {
                'id': technique_id,
                'name': obj.get('name', 'Unknown'),
                'description': description,
                'tactics': tactics,
                'platforms': obj.get('x_mitre_platforms', []),
                'detection_methods': detection_methods,
                'mitigation_methods': mitigation_methods,
                'data_sources': obj.get('x_mitre_data_sources', []),
                'permissions_required': obj.get('x_mitre_permissions_required', []),
                'effective_permissions': obj.get('x_mitre_effective_permissions', []),
                'system_requirements': obj.get('x_mitre_system_requirements', []),
                'is_subtechnique': obj.get('x_mitre_is_subtechnique', False),
                'subtechnique_of': obj.get('x_mitre_subtechnique_of', []),
                'capec_id': obj.get('x_mitre_capec_id', ''),
                'created': obj.get('created', ''),
                'modified': obj.get('modified', ''),
                'version': '1.0'
            }
            
            return technique
            
        except Exception as e:
            logger.error(f"Error processing technique: {e}")
            return None
    
    def load_parsed_techniques(self) -> List[Dict[str, Any]]:
        """Load parsed MITRE techniques"""
        try:
            if not os.path.exists(self.parsed_file):
                logger.warning(f"Parsed MITRE file not found: {self.parsed_file}")
                return []
            
            with open(self.parsed_file, 'r', encoding='utf-8') as f:
                techniques = json.load(f)
            
            logger.info(f"Loaded {len(techniques)} parsed MITRE techniques")
            return techniques
            
        except Exception as e:
            logger.error(f"Error loading parsed techniques: {e}")
            return []
    
    def get_last_updated(self) -> str:
        """Get last updated timestamp"""
        try:
            if os.path.exists(self.last_updated_file):
                with open(self.last_updated_file, 'r') as f:
                    return f.read().strip()
            return "Unknown"
        except:
            return "Unknown"
    
    def update_dataset(self) -> bool:
        """Update MITRE dataset from GitHub"""
        try:
            import requests
            
            logger.info("Updating MITRE dataset from GitHub...")
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            
            # Save updated dataset
            with open(self.mitre_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            logger.info("MITRE dataset updated successfully")
            
            # Parse the updated dataset
            return self.parse_mitre_dataset()
            
        except Exception as e:
            logger.error(f"Error updating MITRE dataset: {e}")
            return False

def main():
    """Main function for testing"""
    parser = MITREParser()
    
    # Parse existing dataset
    if parser.parse_mitre_dataset():
        print("✅ MITRE dataset parsed successfully")
        
        # Load and display sample
        techniques = parser.load_parsed_techniques()
        print(f"📊 Total techniques: {len(techniques)}")
        
        # Show sample technique
        if techniques:
            sample = techniques[0]
            print(f"🔍 Sample technique: {sample['id']} - {sample['name']}")
            print(f"📝 Tactics: {', '.join(sample['tactics'])}")
        
        # Show last updated
        print(f"📅 Last updated: {parser.get_last_updated()}")
    else:
        print("❌ Failed to parse MITRE dataset")

if __name__ == "__main__":
    main()
