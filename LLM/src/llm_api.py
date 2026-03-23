"""
Advanced LLM API - Professional RAG + Llama 3 Analysis

Single endpoint with ChromaDB RAG + VirusTotal + MITRE ATT&CK + Llama 3
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any
import logging
from datetime import datetime

from .config import settings
from .analyses import AdvancedAnalyzer

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(settings.log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Advanced LLM API",
    description="Professional RAG + Llama 3 Alert Analysis",
    version="3.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic model - accepts both formats
class AlertRequest(BaseModel):
    alert: Dict[str, Any] = None
    
    class Config:
        extra = "allow"  # Allow additional fields

# Initialize advanced analyzer
advanced_analyzer = AdvancedAnalyzer()

@app.post("/analyze")
async def analyze_alert(request: AlertRequest):
    """
    Advanced real-time alert analysis with ChromaDB RAG + VirusTotal + MITRE ATT&CK + Llama 3
    Accepts both wrapped and raw Splunk alert formats
    """
    try:
        # Handle both alert formats
        if request.alert:
            # Wrapped format: {"alert": {...}}
            alert_data = request.alert
        else:
            # Raw format: direct Splunk alert fields
            alert_data = request.dict(exclude_unset=True)
        
        # Extract alert ID for logging
        alert_id = alert_data.get('sid', alert_data.get('_id', 'unknown'))
        logger.info(f"Starting advanced analysis for alert: {alert_id}")
        
        # Perform comprehensive analysis
        analysis = advanced_analyzer.analyze_alert(alert_data)
        
        return {
            "success": True,
            "analysis": analysis,
            "timestamp": datetime.utcnow().isoformat(),
            "alert_id": alert_id
        }
        
    except Exception as e:
        logger.error(f"Advanced analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Advanced LLM API",
        "version": "3.0.0",
        "endpoint": "/analyze",
        "features": [
            "ChromaDB RAG",
            "SentenceTransformers",
            "VirusTotal API",
            "MITRE ATT&CK",
            "Llama 3 Local LLM",
            "Semantic Understanding"
        ],
        "status": "running"
    }

@app.post("/reload-mitre")
async def reload_mitre():
    """Reload MITRE techniques from GitHub (hot reload)"""
    try:
        success = advanced_analyzer.rag_system.reload_mitre_techniques()
        
        if success:
            return {
                "success": True,
                "message": "MITRE techniques reloaded successfully from GitHub",
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            return {
                "success": False,
                "message": "Failed to reload MITRE techniques",
                "timestamp": datetime.utcnow().isoformat()
            }
            
    except Exception as e:
        logger.error(f"MITRE reload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test RAG system
        stats = advanced_analyzer.rag_system.get_statistics()
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "rag_system": {
                "status": "operational",
                "collections": stats.get('total_collections', 0),
                "total_items": stats.get('total_items', 0)
            },
            "apis": {
                "virustotal": "available" if advanced_analyzer.virustotal_available else "unavailable",
                "abuseipdb": "available" if advanced_analyzer.tokens.is_configured('abuseipdb') else "unavailable"
            }
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.advanced_llm_api:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
        log_level=settings.log_level.lower()
    )
