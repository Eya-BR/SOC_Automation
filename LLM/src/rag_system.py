"""
Advanced RAG System - Professional Grade

Uses ChromaDB + SentenceTransformers for superior semantic understanding
"""

import logging
import json
import os
import requests
from typing import Dict, List, Any, Optional
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import torch
import numpy as np
from datetime import datetime

logger = logging.getLogger(__name__)

class AdvancedRAGSystem:
    """Professional-grade RAG system with vector embeddings"""
    
    def __init__(self, persist_directory: str = "./data/chroma_db"):
        """Initialize advanced RAG system"""
        self.persist_directory = persist_directory
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Initialize ChromaDB
        self.chroma_client = chromadb.PersistentClient(path=persist_directory)
        
        # Create collections
        self.collections = {}
        self._create_collections()
        
        # Load data
        self._load_knowledge_base()
        
        logger.info("Advanced RAG system initialized with direct MITRE ATT&CK")
        
    def _create_collections(self):
        """Create collections in ChromaDB"""
        try:
            # Create collections
            self.collections = {
                "security_knowledge": self.chroma_client.get_or_create_collection(
                    name="security_knowledge",
                    metadata={"hnsw:space": "cosine"}
                ),
                "mitre_techniques": self.chroma_client.get_or_create_collection(
                    name="mitre_techniques", 
                    metadata={"hnsw:space": "cosine"}
                )
            }
            
            logger.info("ChromaDB collections created successfully")
            
            
        except Exception as e:
            logger.error(f"Error initializing RAG system: {e}")
            raise
    
    def _load_knowledge_base(self):
        """Load knowledge base into ChromaDB"""
        try:
            knowledge_path = "./data/knowledge.json"
            if os.path.exists(knowledge_path):
                with open(knowledge_path, 'r', encoding='utf-8') as f:
                    knowledge_items = json.load(f)
                
                # Add to security_knowledge collection
                for item in knowledge_items:
                    # Create embedding
                    text = f"{item['text']} {' '.join(item['tags'])} {item['category']}"
                    embedding = self.model.encode(text)
                    
                    # Add to ChromaDB
                    self.collections["security_knowledge"].add(
                        ids=[item['id']],
                        documents=[item['text']],
                        embeddings=[embedding.tolist()],
                        metadatas=[{
                            'tags': item['tags'],
                            'category': item['category'],
                            'text': item['text']
                        }]
                    )
                
                logger.info(f"Loaded {len(knowledge_items)} knowledge items into ChromaDB")
                
                # Load MITRE techniques
                self._load_mitre_techniques()
                
        except Exception as e:
            logger.error(f"Error loading knowledge base: {e}")
    
    def _load_mitre_techniques(self):
        """Load MITRE ATT&CK techniques directly from GitHub"""
        try:
            # Fetch directly from MITRE ATT&CK GitHub repository
            techniques_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = requests.get(techniques_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            techniques = []
            
            # Process techniques
            for obj in data:
                if obj.get('type') == 'attack-pattern' and obj.get('id', '').startswith('attack-pattern--'):
                    technique = self._process_technique(obj)
                    if technique:
                        techniques.append(technique)
            
            logger.info(f"Loaded {len(techniques)} techniques from MITRE ATT&CK GitHub")
            
            # Add MITRE techniques to ChromaDB
            for technique in techniques:
                text = f"{technique['name']} {technique['tactic']} {' '.join(technique['indicators'])}"
                embedding = self.model.encode(text)
                
                self.collections["mitre_techniques"].add(
                    ids=[technique['id']],
                    documents=[technique['description']],
                    embeddings=[embedding.tolist()],
                    metadatas=[{
                        'id': technique['id'],
                        'name': technique['name'],
                        'tactic': technique['tactic'],
                        'techniques': technique['techniques'],
                        'indicators': technique['indicators'],
                        'detection_methods': technique['detection_methods'],
                        'mitigation': technique['mitigation'],
                        'severity': technique['severity'],
                        'confidence': technique['confidence'],
                        'last_updated': technique['last_updated']
                    }]
                )
            
            logger.info(f"Successfully loaded {len(techniques)} MITRE techniques into ChromaDB")
            
        except requests.RequestException as e:
            logger.error(f"Network error fetching MITRE data: {e}")
        except Exception as e:
            logger.error(f"Error loading MITRE techniques: {e}")
    
    def reload_mitre_techniques(self):
        """Reload MITRE techniques from GitHub (hot reload)"""
        try:
            # Clear existing MITRE collection
            self.collections["mitre_techniques"].delete()
            
            # Recreate collection
            self.collections["mitre_techniques"] = self.chroma_client.get_or_create_collection(
                name="mitre_techniques", 
                metadata={"hnsw:space": "cosine"}
            )
            
            # Reload from GitHub
            self._load_mitre_techniques()
            
            logger.info("MITRE techniques reloaded successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error reloading MITRE techniques: {e}")
            return False
    
    def _process_technique(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process individual technique object"""
        try:
            # Extract technique ID from STIX ID
            technique_id = obj.get('x_mitre_attack_spec_version', '').split('-')[-1]
            if not technique_id:
                # Try to extract from external_references
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        url_parts = ref.get('url', '').split('/')
                        for part in url_parts:
                            if part.startswith('T') and part[1:].isdigit():
                                technique_id = part
                                break
                        if technique_id:
                            break
            
            if not technique_id:
                return None
            
            # Get tactics
            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(phase.get('phase_name', ''))
            
            # Get techniques/sub-techniques
            techniques = [obj.get('name', '')]
            
            # Get indicators from description
            description = obj.get('description', '')
            indicators = self._extract_indicators(description)
            
            # Get detection methods
            detection_methods = self._extract_detection_methods(obj)
            
            # Get mitigation
            mitigation = self._extract_mitigation(obj)
            
            # Determine severity based on tactics
            severity = self._determine_severity(tactics)
            
            return {
                'id': technique_id,
                'name': obj.get('name', ''),
                'tactic': ', '.join(tactics) if tactics else 'Unknown',
                'description': description,
                'techniques': techniques,
                'indicators': indicators,
                'detection_methods': detection_methods,
                'mitigation': mitigation,
                'severity': severity,
                'confidence': 0.95,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error processing technique: {e}")
            return None
    
    def _extract_indicators(self, description: str) -> List[str]:
        """Extract indicators from technique description"""
        indicators = []
        
        # Common indicator keywords
        indicator_keywords = [
            'powershell', 'cmd', 'command', 'script', 'shell', 'registry',
            'process', 'service', 'scheduled', 'task', 'startup', 'logon',
            'credential', 'password', 'hash', 'dump', 'brute', 'force',
            'exploit', 'vulnerability', 'cve', 'injection', 'xss', 'sql',
            'phishing', 'email', 'attachment', 'link', 'malware', 'trojan',
            'backdoor', 'rootkit', 'lateral', 'movement', 'exfiltration',
            'data', 'transfer', 'upload', 'download', 'network', 'protocol',
            'dns', 'http', 'https', 'smb', 'rdp', 'ssh', 'ftp'
        ]
        
        # Extract from description
        desc_lower = description.lower()
        for keyword in indicator_keywords:
            if keyword in desc_lower:
                indicators.append(keyword)
        
        return list(set(indicators))
    
    def _extract_detection_methods(self, obj: Dict[str, Any]) -> List[str]:
        """Extract detection methods from technique"""
        methods = []
        
        # From x_mitre_detection field
        if 'x_mitre_detection' in obj:
            detection_text = obj['x_mitre_detection']
            # Split into sentences and clean up
            sentences = [s.strip() for s in detection_text.split('.') if s.strip()]
            methods.extend(sentences[:3])  # Take first 3 sentences
        
        # From data sources
        if 'x_mitre_data_sources' in obj:
            for source in obj['x_mitre_data_sources']:
                methods.append(f"Monitor {source}")
        
        return methods[:5]  # Limit to 5 methods
    
    def _extract_mitigation(self, obj: Dict[str, Any]) -> List[str]:
        """Extract mitigation strategies"""
        mitigations = []
        
        # Common mitigation strategies
        common_mitigations = [
            "Implement strong access controls",
            "Use multi-factor authentication",
            "Regular security training",
            "Network segmentation",
            "Endpoint detection and response",
            "Log monitoring and analysis",
            "Vulnerability management",
            "Application whitelisting",
            "Privilege management",
            "Security configuration management"
        ]
        
        # Add technique-specific mitigations based on tactics
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase.get('phase_name', ''))
        
        if 'initial-access' in tactics:
            mitigations.extend(["Email filtering", "Web application firewall", "Secure configuration"])
        elif 'execution' in tactics:
            mitigations.extend(["Application control", "PowerShell logging", "Process monitoring"])
        elif 'persistence' in tactics:
            mitigations.extend(["Registry monitoring", "Startup item control", "Service management"])
        elif 'privilege-escalation' in tactics:
            mitigations.extend(["Privilege monitoring", "Credential protection", "UAC enforcement"])
        elif 'credential-access' in tactics:
            mitigations.extend(["Credential Guard", "LSASS protection", "Access control"])
        elif 'lateral-movement' in tactics:
            mitigations.extend(["Network segmentation", "Remote access control", "Admin tool monitoring"])
        elif 'exfiltration' in tactics:
            mitigations.extend(["Data loss prevention", "Egress filtering", "SSL inspection"])
        
        return list(set(mitigations[:8]))  # Limit to 8 mitigations
    
    def _determine_severity(self, tactics: List[str]) -> str:
        """Determine severity based on tactics"""
        high_severity_tactics = [
            'initial-access', 'privilege-escalation', 'credential-access',
            'lateral-movement', 'exfiltration', 'impact'
        ]
        
        medium_severity_tactics = [
            'execution', 'persistence', 'defense-evasion', 'discovery'
        ]
        
        for tactic in tactics:
            if tactic in high_severity_tactics:
                return 'critical'
            elif tactic in medium_severity_tactics:
                return 'high'
        
        return 'medium'
    
    def retrieve_relevant_context(self, alert_data: Dict[str, Any], max_results: int = 5) -> List[Dict[str, Any]]:
        """
        Retrieve relevant context using semantic search
        
        Args:
            alert_data: Security alert to analyze
            max_results: Maximum number of results to return
            
        Returns:
            List of relevant knowledge items with metadata
        """
        try:
            # Create query embedding
            alert_text = str(alert_data)
            query_embedding = self.model.encode(alert_text)
            
            # Search all collections
            all_results = []
            
            # Search security knowledge
            security_results = self.collections["security_knowledge"].query(
                query_embeddings=[query_embedding.tolist()],
                n_results=max_results
            )
            
            # Search MITRE techniques
            mitre_results = self.collections["mitre_techniques"].query(
                query_embeddings=[query_embedding.tolist()],
                n_results=max_results
            )
            
            # Combine and rank results
            all_results.extend([
                {
                    'type': 'security_knowledge',
                    'id': result['ids'][0],
                    'document': result['documents'][0],
                    'metadata': result['metadatas'][0],
                    'distance': result['distances'][0],
                    'similarity': 1 - result['distances'][0]
                }
                for result in security_results['ids']
            ])
            
            all_results.extend([
                {
                    'type': 'mitre_technique',
                    'id': result['metadatas'][0]['id'],
                    'document': result['documents'][0],
                    'metadata': result['metadatas'][0],
                    'distance': result['distances'][0],
                    'similarity': 1 - result['distances'][0]
                }
                for result in mitre_results['ids']
            ])
            
            # Sort by similarity (highest first)
            all_results.sort(key=lambda x: x['similarity'], reverse=True)
            
            logger.info(f"Retrieved {len(all_results)} relevant items from ChromaDB")
            return all_results[:max_results]
            
        except Exception as e:
            logger.error(f"Error retrieving context: {e}")
            return []
    
    def add_knowledge(self, item: Dict[str, Any], collection: str = "security_knowledge"):
        """Add new knowledge item to ChromaDB"""
        try:
            text = f"{item['text']} {' '.join(item.get('tags', []))} {item.get('category', '')}"
            embedding = self.model.encode(text)
            
            self.collections[collection].add(
                ids=[item.get('id', f"custom_{datetime.now().timestamp()}")],
                documents=[item['text']],
                embeddings=[embedding.tolist()],
                metadatas=[{
                    'tags': item.get('tags', []),
                    'category': item.get('category', ''),
                    'text': item['text'],
                    'source': 'user_added',
                    'added_date': datetime.now().isoformat()
                }]
            )
            
            logger.info(f"Added new knowledge item to {collection}: {item.get('id', 'unknown')}")
            
        except Exception as e:
            logger.error(f"Error adding knowledge: {e}")
    
    def search_knowledge(self, query: str, collection: str = None, max_results: int = 10) -> List[Dict[str, Any]]:
        """Search knowledge base with semantic query"""
        try:
            query_embedding = self.model.encode(query)
            
            if collection and collection in self.collections:
                results = self.collections[collection].query(
                    query_embeddings=[query_embedding.tolist()],
                    n_results=max_results
                )
                
                return [
                    {
                        'type': collection,
                        'id': result['metadatas'][0].get('id', 'unknown'),
                        'document': result['documents'][0],
                        'metadata': result['metadatas'][0],
                        'similarity': 1 - result['distances'][0]
                    }
                    for result in results['ids']
                ]
            else:
                # Search all collections
                all_results = []
                for coll_name, coll in self.collections.items():
                    results = coll.query(
                        query_embeddings=[query_embedding.tolist()],
                        n_results=max_results
                    )
                    
                    for result in results['ids']:
                        all_results.append({
                            'type': coll_name,
                            'id': result['metadatas'][0].get('id', 'unknown'),
                            'document': result['documents'][0],
                            'metadata': result['metadatas'][0],
                            'similarity': 1 - result['distances'][0]
                        })
                
                # Sort by similarity
                all_results.sort(key=lambda x: x['similarity'], reverse=True)
                return all_results[:max_results]
                
        except Exception as e:
            logger.error(f"Error searching knowledge: {e}")
            return []
    
    def reload_mitre_techniques(self):
        """Reload MITRE techniques from JSON file (hot reload)"""
        try:
            # Clear existing MITRE collection
            self.collections["mitre_techniques"].delete()
            
            # Recreate collection
            self.collections["mitre_techniques"] = self.chroma_client.get_or_create_collection(
                name="mitre_techniques", 
                metadata={"hnsw:space": "cosine"}
            )
            
            # Reload from JSON
            self._load_mitre_techniques()
            
            logger.info("MITRE techniques reloaded successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error reloading MITRE techniques: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get RAG system statistics"""
        try:
            stats = {}
            
            for coll_name, collection in self.collections.items():
                count = collection.count()
                stats[coll_name] = {
                    'item_count': count,
                    'collection_name': coll_name
                }
            
            stats['total_collections'] = len(self.collections)
            stats['total_items'] = sum(coll['item_count'] for coll in stats.values())
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {'error': str(e)}
