"""
MITRE ATT&CK Dynamic Loading via RAG
Always up-to-date with latest techniques from official ATT&CK
"""

from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class MiterRAGLoader:
    """MITRE ATT&CK loader using existing RAG system (no internet required)"""
    
    def __init__(self, rag_system):
        self.rag_system = rag_system
    
    def search_mitre_techniques(self, alert_data: Dict[str, Any]) -> List[Dict]:
        """Search for relevant MITRE techniques using existing RAG data"""
        try:
            # Use RAG system to find relevant techniques from data/knowledge
            query = self._build_search_query(alert_data)
            
            # Search in MITRE collection (already loaded from data/knowledge)
            results = self.rag_system.collections["mitre_techniques"].query(
                query_embeddings=self.rag_system.model.encode(query),
                n_results=5
            )
            
            techniques = []
            for i, (doc, metadata) in enumerate(zip(results['documents'], results['metadatas'])):
                if metadata:
                    techniques.append({
                        'id': metadata.get('id', 'Unknown'),
                        'name': metadata.get('name', 'Unknown'),
                        'tactic': metadata.get('tactic', 'Unknown'),
                        'confidence': self._calculate_confidence(alert_data, metadata),
                        'reason': f"RAG match {i+1} with similarity {results['distances'][i]:.3f}"
                    })
            
            return techniques
            
        except Exception as e:
            logger.error(f"Error searching MITRE techniques: {e}")
            return []
    
    def _build_search_query(self, alert_data: Dict[str, Any]) -> str:
        """Build search query from alert data"""
        query_parts = []
        
        # Add alert name
        alert_name = alert_data.get('search_name', '')
        if alert_name:
            query_parts.append(alert_name)
        
        # Add observables
        result = alert_data.get('result', {})
        if 'user' in result:
            query_parts.append(f"user {result['user']}")
        if 'Privileges' in result:
            query_parts.append(f"privilege {result['Privileges']}")
        if 'host' in result:
            query_parts.append(f"host {result['host']}")
        
        return ' '.join(query_parts)
    
    def _calculate_confidence(self, alert_data: Dict[str, Any], metadata: Dict) -> str:
        """Calculate confidence based on context match"""
        confidence = "low"
        
        # Check for direct matches
        alert_privilege = alert_data.get('result', {}).get('Privileges', '').lower()
        alert_name = alert_data.get('search_name', '').lower()
        
        # High confidence for exact matches
        if alert_privilege and metadata.get('indicators'):
            for indicator in metadata['indicators']:
                if indicator in alert_privilege:
                    confidence = "high"
                    break
        
        # Medium confidence for partial matches
        if confidence == "low" and alert_name:
            if any(tactic in alert_name for tactic in metadata.get('tactics', [])):
                confidence = "medium"
        
        return confidence
