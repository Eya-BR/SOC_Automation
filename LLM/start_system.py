"""
Start Advanced Real-Time Alert Analysis Server

Uses ChromaDB RAG + VirusTotal + MITRE ATT&CK + Llama 3
"""

import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.analyze import Analyzer
from src.api_tokens import APITokens
import uvicorn

if __name__ == "__main__":
    print("🚀 Starting ADVANCED Real-Time Alert Analysis Server...")
    print("🧠 RAG System: ChromaDB + SentenceTransformers")
    print("🦠 Threat Intel: VirusTotal + AbuseIPDB")
    print("🎯 MITRE ATT&CK: Local Dataset (835 techniques)")
    print("🎯 LLM: Model LLM (Contextual Recommendations)")
    print("📍 Server: http://10.10.128.17:8001")
    print("🎯 Endpoint: http://10.10.128.17:8001/analyze")
    print("📊 Health: http://10.10.128.17:8001/")
    print("=" * 60)
    
    # Check API configuration
    tokens = APITokens()
    vt_configured = tokens.is_configured('virustotal')
    abuse_configured = tokens.is_configured('abuseipdb')
    
    print(f"🔑 API Status:")
    print(f"   VirusTotal: {'✅ Configured' if vt_configured else '❌ Not configured'}")
    print(f"   AbuseIPDB: {'✅ Configured' if abuse_configured else '❌ Not configured'}")
    print()
    
    if not vt_configured:
        print("⚠️  WARNING: VirusTotal API key not configured!")
        print("   Add your key to src/api_tokens.py")
        print("   VIRUSTOTAL_API_KEY = 'your-api-key-here'")
        print()
    
    uvicorn.run(
        "src.llm_api:app",
        host="10.10.128.17",
        port=8001,
        reload=True,
        log_level="info"
    )
