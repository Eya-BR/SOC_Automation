"""
API Tokens Configuration

Store all your API keys here for easy management
"""

class APITokens:
    """Centralized API token management"""
    
    # Essential APIs for Real-Time Analysis
    VIRUSTOTAL_API_KEY = "c0c330736b931a71eea2762afc47f628e6bf8f5a687011535dbe76763785b32f"
    ABUSEIPDB_API_KEY = "5806bdef7364c42c11f9ed719fa6dd6c9c3b54876276419f6bedd68928d42c2b05efb6ea405620ad"
    
    @classmethod
    def get_all_tokens(cls):
        """Get all API tokens as dict"""
        return {
            'virustotal': cls.VIRUSTOTAL_API_KEY,
            'abuseipdb': cls.ABUSEIPDB_API_KEY
        }
    
    @classmethod
    def is_configured(cls, service: str) -> bool:
        """Check if API token is configured"""
        token = getattr(cls, f"{service.upper()}_API_KEY", None)
        return token and token != f"your-{service}-api-key-here"
