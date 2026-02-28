#!/usr/bin/env python3
"""
System Diagnosis Script

Checks what's causing the fallback responses
"""

import sys
import os
import requests
import json
from datetime import datetime

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_ollama_connection():
    """Test Ollama connection and Llama 3 model"""
    print("🦙 Testing Ollama Connection")
    print("=" * 40)
    
    try:
        # Test Ollama server
        response = requests.get("http://localhost:11434/api/tags", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Ollama server is running")
            
            # Check available models
            models = data.get('models', [])
            print(f"📊 Available models: {len(models)}")
            
            for model in models:
                print(f"   - {model['name']}")
            
            # Check for llama3.2
            llama_available = any('llama3.2' in model['name'] for model in models)
            
            if llama_available:
                print("✅ Llama 3.2 model is available")
                return True
            else:
                print("❌ Llama 3.2 model not found")
                print("💡 Run: ollama pull llama3.2")
                return False
        else:
            print(f"❌ Ollama server error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Cannot connect to Ollama: {e}")
        print("💡 Start Ollama: ollama serve")
        return False

def test_llama3_generation():
    """Test Llama 3 text generation"""
    print("\n🧠 Testing Llama 3 Generation")
    print("=" * 40)
    
    try:
        payload = {
            "model": "llama3.2",
            "prompt": "Hello, respond with just 'OK'",
            "stream": False,
            "options": {
                "temperature": 0.1,
                "max_tokens": 10
            }
        }
        
        response = requests.post("http://localhost:11434/api/generate", 
                               json=payload, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            response_text = result.get("response", "")
            print(f"✅ Llama 3 responded: '{response_text.strip()}'")
            return True
        else:
            print(f"❌ Llama 3 generation error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Llama 3 generation failed: {e}")
        return False

def test_chromadb():
    """Test ChromaDB connection"""
    print("\n🗄️ Testing ChromaDB")
    print("=" * 40)
    
    try:
        from src.rag_system import AdvancedRAGSystem
        
        rag = AdvancedRAGSystem()
        
        # Test collections
        collections = rag.collections
        print(f"✅ ChromaDB initialized with {len(collections)} collections")
        
        for name, collection in collections.items():
            count = collection.count()
            print(f"   - {name}: {count} items")
        
        # Test context retrieval
        test_alert = {
            "rule": "Test Alert",
            "message": "Test message for context retrieval"
        }
        
        context = rag.retrieve_relevant_context(test_alert, max_results=2)
        print(f"✅ Context retrieval: {len(context)} items found")
        
        return True
        
    except Exception as e:
        print(f"❌ ChromaDB error: {e}")
        return False

def test_api_tokens():
    """Test API token configuration"""
    print("\n🔑 Testing API Tokens")
    print("=" * 40)
    
    try:
        from src.api_tokens import APITokens
        
        tokens = APITokens()
        
        # Check VirusTotal
        vt_configured = tokens.is_configured('virustotal')
        print(f"VirusTotal: {'✅ Configured' if vt_configured else '❌ Not configured'}")
        
        # Check AbuseIPDB
        abuse_configured = tokens.is_configured('abuseipdb')
        print(f"AbuseIPDB: {'✅ Configured' if abuse_configured else '❌ Not configured'}")
        
        return vt_configured or abuse_configured
        
    except Exception as e:
        print(f"❌ API tokens error: {e}")
        return False

def test_full_analysis():
    """Test full alert analysis"""
    print("\n🔍 Testing Full Analysis")
    print("=" * 40)
    
    try:
        from src.analyses import AdvancedAnalyzer
        
        analyzer = AdvancedAnalyzer()
        
        # Test alert
        test_alert = {
            "sid": "test-sid-123",
            "search_name": "Test Alert",
            "app": "test-app",
            "result": {
                "_time": "1234567890",
                "user": "test-user",
                "host": "test-host",
                "severity": "medium"
            }
        }
        
        print("📊 Analyzing test alert...")
        analysis = analyzer.analyze_alert(test_alert)
        
        # Check if it's fallback
        if analysis.get('status') == 'fallback':
            print("❌ Analysis returned fallback response")
            print(f"Error: {analysis.get('error', 'Unknown')}")
            return False
        else:
            print("✅ Full analysis successful!")
            print(f"Threat score: {analysis.get('threat_score', 'N/A')}")
            print(f"Severity: {analysis.get('overall_severity', 'N/A')}")
            return True
            
    except Exception as e:
        print(f"❌ Full analysis error: {e}")
        return False

def main():
    """Main diagnosis"""
    print("🔧 System Diagnosis Tool")
    print("=" * 60)
    print(f"⏰ Started at: {datetime.now()}")
    
    # Run all tests
    tests = [
        ("Ollama Connection", test_ollama_connection),
        ("Llama 3 Generation", test_llama3_generation),
        ("ChromaDB", test_chromadb),
        ("API Tokens", test_api_tokens),
        ("Full Analysis", test_full_analysis)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n🏆 Diagnosis Summary")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    # Recommendations
    print("\n💡 Recommendations")
    print("=" * 60)
    
    if not results.get("Ollama Connection", False):
        print("🦙 Start Ollama: ollama serve")
    
    if not results.get("Llama 3 Generation", False):
        print("📥 Download Llama 3: ollama pull llama3.2")
    
    if not results.get("ChromaDB", False):
        print("🗄️ Check ChromaDB installation and data files")
    
    if not results.get("API Tokens", False):
        print("🔑 Configure API keys in src/api_tokens.py")
    
    if not results.get("Full Analysis", False):
        print("🔧 Fix the above issues to enable full analysis")
    
    print(f"\n⏰ Diagnosis completed at: {datetime.now()}")

if __name__ == "__main__":
    main()
