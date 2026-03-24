"""
Clean RAG System - Professional SOC Knowledge Base
Uses markdown files for knowledge, no MITRE loading (handled by mitre_loader.py)
"""

import os
import json
import logging
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AdvancedRAGSystem:
    """Professional RAG system for SOC knowledge base"""
    
    def __init__(self, persist_directory: str = "./data/chroma_db"):
        """Initialize RAG system"""
        try:
            logging.info("Initializing RAG system...")
            
            # Initialize the embedding model
            logging.info("Loading embedding model...")
            self.model = SentenceTransformer('all-MiniLM-L6-v2')
            
            # Set up ChromaDB
            os.makedirs(persist_directory, exist_ok=True)
            self.chroma_client = chromadb.PersistentClient(path=persist_directory)
            
            # Create collections
            self._create_collections()
            
            # Load knowledge base
            self._load_knowledge_base()
            
            logging.info("RAG system initialized successfully!")
            
        except Exception as e:
            logging.error(f"Error initializing RAG system: {e}")
            raise
    
    def _create_collections(self):
        """Create collections in ChromaDB"""
        try:
            # Create collections
            self.collections = {
                "security_knowledge": self.chroma_client.get_or_create_collection(
                    name="security_knowledge",
                    metadata={"hnsw:space": "cosine"}
                )
            }
            
            logger.info("ChromaDB collections created successfully")
            
        except Exception as e:
            logger.error(f"Error creating collections: {e}")
            raise
    
    def _load_knowledge_base(self):
        """Load knowledge base into ChromaDB"""
        try:
            # Load from markdown knowledge files
            knowledge_path = "./data/knowledge/soc_reasoning/"
            if os.path.exists(knowledge_path):
                # Load markdown files
                knowledge_items = []
                for filename in os.listdir(knowledge_path):
                    if filename.endswith('.md'):
                        file_path = os.path.join(knowledge_path, filename)
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            knowledge_items.append({
                                'id': filename.replace('.md', ''),
                                'text': content,
                                'tags': ['soc', 'reasoning', filename.replace('.md', '')],
                                'category': 'soc_reasoning'
                            })
                
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
                
                logger.info(f"Loaded {len(knowledge_items)} knowledge items from markdown files")
                
        except Exception as e:
            logger.error(f"Error loading knowledge base: {e}")
    
    def retrieve_relevant_context(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve relevant context from knowledge base"""
        try:
            # Create query from alert data
            query = str(alert_data)
            query_embedding = self.model.encode(query)
            
            # Search in security_knowledge collection
            results = self.collections["security_knowledge"].query(
                query_embeddings=[query_embedding],
                n_results=3
            )
            
            return {
                "query": query,
                "results": results,
                "total_matches": len(results['documents'][0]) if results['documents'] else 0
            }
            
        except Exception as e:
            logger.error(f"Error retrieving context: {e}")
            return {"query": str(alert_data), "results": {}, "total_matches": 0}
    
    def search_knowledge(self, query: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """Search knowledge base with query"""
        try:
            query_embedding = self.model.encode(query)
            
            results = self.collections["security_knowledge"].query(
                query_embeddings=[query_embedding],
                n_results=n_results
            )
            
            search_results = []
            if results['documents'] and results['documents'][0]:
                for i, (doc, metadata, distance) in enumerate(zip(
                    results['documents'][0],
                    results['metadatas'][0],
                    results['distances'][0]
                )):
                    search_results.append({
                        'document': doc,
                        'metadata': metadata,
                        'similarity': 1 - distance,
                        'rank': i + 1
                    })
            
            return search_results
            
        except Exception as e:
            logger.error(f"Error searching knowledge: {e}")
            return []
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics for collections"""
        try:
            stats = {}
            for name, collection in self.collections.items():
                count = collection.count()
                stats[name] = {
                    'document_count': count,
                    'collection_name': name
                }
            return stats
            
        except Exception as e:
            logger.error(f"Error getting collection stats: {e}")
            return {}
    
    def reload_knowledge(self) -> bool:
        """Reload knowledge base"""
        try:
            # Clear existing collection
            self.collections["security_knowledge"].delete()
            
            # Recreate collection
            self.collections["security_knowledge"] = self.chroma_client.get_or_create_collection(
                name="security_knowledge",
                metadata={"hnsw:space": "cosine"}
            )
            
            # Reload knowledge
            self._load_knowledge_base()
            
            logger.info("Knowledge base reloaded successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Error reloading knowledge base: {e}")
            return False

# Test function
def test_rag_system():
    """Test the RAG system"""
    try:
        rag = AdvancedRAGSystem()
        
        # Test search
        query = "privilege escalation detection"
        results = rag.search_knowledge(query)
        
        print(f"Found {len(results)} results for query: {query}")
        for result in results:
            print(f"- Rank {result['rank']}: {result['metadata']['id']} (Similarity: {result['similarity']:.3f})")
        
        # Get stats
        stats = rag.get_collection_stats()
        print(f"Collection stats: {stats}")
        
        return True
        
    except Exception as e:
        print(f"Error testing RAG system: {e}")
        return False

if __name__ == "__main__":
    test_rag_system()
