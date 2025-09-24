"""
Elite Threat Intelligence Feed Aggregator Configuration
World-Class Enterprise Grade Platform for International Hackathon Competition
"""
import os
import random
from typing import List, Dict
from dotenv import load_dotenv

class Config:
    """Advanced configuration with enterprise-grade features and AI load balancing."""
    load_dotenv()

    # --- Multi-API Key Load Balancing System ---
    # Try Streamlit secrets first, fallback to environment variables
    try:
        import streamlit as st
        if hasattr(st, 'secrets'):
            GEMINI_API_KEYS = [
                st.secrets.get("GEMINI_API_KEY_1"),
                st.secrets.get("GEMINI_API_KEY_2")
            ]
        else:
            raise ImportError("Streamlit not available")
    except (ImportError, AttributeError):
        GEMINI_API_KEYS = [
            os.getenv("GEMINI_API_KEY_1"),
            os.getenv("GEMINI_API_KEY_2")
        ]
    
    # Filter out None values
    GEMINI_API_KEYS = [key for key in GEMINI_API_KEYS if key]
    
    # AI Provider Configuration
    AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini")
    
    # Advanced AI Model Options for Different Tasks
    GEMINI_MODELS = [
        {
            "name": "gemini-2.5-flash",
            "task": "summary",
            "rpm": 15,  # Requests per minute
            "rpd": 1500,  # Requests per day
            "context_length": 2097152,
            "temperature": 0.3
        },
        {
            "name": "gemini-2.5-flash-lite", 
            "task": "analysis",
            "rpm": 15,
            "rpd": 1500,
            "context_length": 1048576,
            "temperature": 0.5
        },
        {
            "name": "gemini-2.0-flash-lite",
            "task": "classification",
            "rpm": 15,
            "rpd": 1500,
            "context_length": 1048576,
            "temperature": 0.1
        },
        {
            "name": "gemini-2.0-flash",
            "task": "correlation",
            "rpm": 15,
            "rpd": 1500,
            "context_length": 2097152,
            "temperature": 0.7
        }
    ]

    @classmethod
    def get_random_api_key(cls) -> str:
        """Returns a random API key for load balancing."""
        return random.choice(cls.GEMINI_API_KEYS) if cls.GEMINI_API_KEYS else None

    # --- Elite Threat Intelligence Sources ---
    THREAT_FEEDS = [
        # Government & Official Sources
        {"name": "🏛️ US-CERT CISA", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "category": "government", "priority": "critical"},
        {"name": "🏛️ NIST NVD", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "category": "government", "priority": "high"},
        {"name": "🏛️ FBI IC3", "url": "https://www.ic3.gov/RSS/rss.xml", "category": "government", "priority": "critical"},
        
        # Premium Threat Intelligence
        {"name": "🎯 SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "category": "threat_intel", "priority": "high"},
        {"name": "🎯 MITRE ATT&CK", "url": "https://attack.mitre.org/resources/updates/updates.xml", "category": "threat_intel", "priority": "critical"},
        {"name": "🎯 AlienVault OTX", "url": "https://otx.alienvault.com/api/v1/pulses/subscribed", "category": "threat_intel", "priority": "high"},
        
        # Security Research & Blogs
        {"name": "🔬 Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "category": "research", "priority": "medium"},
        {"name": "🔬 MalwareBytes Labs", "url": "https://blog.malwarebytes.com/feed/", "category": "research", "priority": "medium"},
        {"name": "🔬 ThreatPost", "url": "https://threatpost.com/feed/", "category": "news", "priority": "medium"},
        {"name": "🔬 BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "category": "news", "priority": "medium"},
        {"name": "🔬 SecurityWeek", "url": "https://www.securityweek.com/rss", "category": "news", "priority": "medium"},
        
        # Vulnerability Databases
        {"name": "🚨 Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "category": "exploits", "priority": "high"},
        {"name": "🚨 VulnDB", "url": "https://vuldb.com/rss/?type=updates", "category": "vulnerabilities", "priority": "high"},
        
        # Dark Web & Underground
        {"name": "🕵️ ThreatMiner", "url": "https://www.threatminer.org/rss.xml", "category": "darkweb", "priority": "high"},
        {"name": "🕵️ HackerNews", "url": "https://thehackernews.com/feeds/posts/default", "category": "news", "priority": "medium"},
    ]

    # --- Database Configuration ---
    DB_PATH = os.getenv("DATABASE_PATH", "threat_intel.db")
    
    # --- Advanced Application Settings ---
    APP_TITLE = os.getenv("APP_TITLE", "TIFA - Elite Threat Intelligence Aggregator")
    APP_DESCRIPTION = os.getenv("APP_DESCRIPTION", "AI-Powered Global Threat Intelligence Platform")
    APP_ICON = "🛡️"
    
    # --- Performance & Scaling ---
    MAX_ITEMS_PER_FEED = int(os.getenv("MAX_ITEMS_PER_FEED", 50))
    MAX_RECENT_THREATS = int(os.getenv("MAX_RECENT_THREATS", 100))
    MAX_SEARCH_RESULTS = int(os.getenv("MAX_SEARCH_RESULTS", 100))
    MAX_EXPORT_ITEMS = int(os.getenv("MAX_EXPORT_ITEMS", 1000))
    AUTO_REFRESH_INTERVAL = int(os.getenv("AUTO_REFRESH_INTERVAL", 300))
    
    # --- Threat Keywords for Classification ---
    THREAT_KEYWORDS = [
        "malware", "ransomware", "phishing", "trojan", "virus", "botnet", 
        "exploit", "vulnerability", "apt", "backdoor", "rootkit", "spyware",
        "adware", "keylogger", "worm", "ddos", "dos", "injection", "xss",
        "csrf", "rce", "lfi", "rfi", "sqli", "clickjacking", "social engineering",
        "scam", "fraud", "identity theft", "data breach", "cyber attack",
        "zero-day", "0day", "cve", "security", "threat", "risk", "incident",
        "compromise", "breach", "attack", "hacker", "cybercriminal"
    ]
    
    # --- High Severity Keywords for AI Analysis ---
    HIGH_SEVERITY_KEYWORDS = [
        "zero-day", "0day", "critical vulnerability", "active exploitation", 
        "worm", "nation-state", "ransomware", "remote code execution", 
        "privilege escalation", "data breach", "apt", "advanced persistent threat",
        "supply chain attack", "critical", "emergency", "urgent", "immediate action",
        "widespread", "mass exploitation", "botnet", "cryptojacking"
    ]
    
    # --- Multi-threading Configuration ---
    MAX_FEED_WORKERS = int(os.getenv("MAX_FEED_WORKERS", 5))
    
    # --- AI Processing Configuration ---
    AI_REQUEST_TIMEOUT = int(os.getenv("AI_REQUEST_TIMEOUT", 45))
    AI_MAX_RETRIES = int(os.getenv("AI_MAX_RETRIES", 3))  # Reduced retries to save tokens
    AI_RETRY_DELAY = int(os.getenv("AI_RETRY_DELAY", 1))
    MAX_CONCURRENT_AI_REQUESTS = int(os.getenv("MAX_CONCURRENT_AI_REQUESTS", 5))  # Reduced concurrent requests
    
    # --- Token Usage Optimization ---
    MAX_SUMMARY_TOKENS = int(os.getenv("MAX_SUMMARY_TOKENS", 200))  # Limit summary generation tokens
    MAX_SEVERITY_TOKENS = int(os.getenv("MAX_SEVERITY_TOKENS", 50))   # Limit severity analysis tokens
    DAILY_TOKEN_LIMIT = int(os.getenv("DAILY_TOKEN_LIMIT", 40000))    # Conservative daily limit
    MAX_INPUT_CONTENT_LENGTH = int(os.getenv("MAX_INPUT_CONTENT_LENGTH", 500))  # Limit input content
    
    # --- Rate Limiting ---
    RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", 60))
    
    # --- Server Configuration ---
    SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
    SERVER_PORT = int(os.getenv("SERVER_PORT", 7860))
    
    # --- Enhanced IOC Patterns for SOC Teams ---
    IOC_PATTERNS = {
        # Network Indicators
        "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "ipv6": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "domain": r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,})\b',
        "subdomain": r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}\b',
        "url": r'https?://[^\s/$.?#].[^\s]*',
        "ftp_url": r'ftp://[^\s/$.?#].[^\s]*',
        
        # File Hashes
        "md5": r'\b[A-Fa-f0-9]{32}\b',
        "sha1": r'\b[A-Fa-f0-9]{40}\b',
        "sha256": r'\b[A-Fa-f0-9]{64}\b',
        "sha512": r'\b[A-Fa-f0-9]{128}\b',
        "ssdeep": r'\b\d+:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\b',
        
        # Vulnerabilities & CVEs
        "cve": r'CVE-\d{4}-\d{4,7}',
        "cwe": r'CWE-\d+',
        "cpe": r'cpe:2\.3:[aho\*\-]:[^\s:]*(?::[^\s:]*){8}',
        
        # Email & Communication
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "phone": r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
        
        # Cryptocurrency
        "bitcoin": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "ethereum": r'\b0x[a-fA-F0-9]{40}\b',
        "monero": r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
        
        # Malware & Signatures
        "yara_rule": r'rule\s+\w+\s*\{[^}]*\}',
        "mutex": r'Global\\[A-Za-z0-9_-]+',
        "service_name": r'(?:HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\)([A-Za-z0-9_-]+)',
        
        # File System
        "windows_path": r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        "unix_path": r'(?:/[^/\s]+)+/?',
        "filename": r'\b[A-Za-z0-9_.-]+\.(?:exe|dll|bat|cmd|ps1|vbs|jar|zip|rar|doc|docx|pdf|xls|xlsx|ppt|pptx)\b',
        "pdb_path": r'[A-Za-z]:\\[^:]+\.pdb',
        
        # Registry
        "registry_key": r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*',
        "registry_value": r'(?:HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*\\)([^\\]+)',
        
        # Network & Infrastructure
        "user_agent": r'User-Agent:\s*([^\r\n]+)',
        "http_header": r'[A-Za-z-]+:\s*[^\r\n]+',
        "mac_address": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
        "port": r'\b(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\b',
        
        # Attack Patterns
        "attack_pattern": r'T\d{4}(?:\.\d{3})?',  # MITRE ATT&CK
        "malware_family": r'\b(?:emotet|trickbot|ryuk|cobalt.*strike|metasploit|mimikatz|powershell.*empire)\b',
        
        # Cloud & Modern Infrastructure
        "aws_access_key": r'AKIA[0-9A-Z]{16}',
        "gcp_key": r'AIza[0-9A-Za-z\\-_]{35}',
        "docker_image": r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*:[a-z0-9]+(?:[._-][a-z0-9]+)*',
        
        # Mobile & IoT
        "android_package": r'[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+',
        "ios_bundle": r'[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+',
        
        # Certificates & Encryption
        "ssl_cert_serial": r'\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){7,19}\b',
        "base64_encoded": r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    }

    # Social Media Crawling Configuration
    SOCIAL_MEDIA_CONFIG = {
        "twitter": {
            "bearer_token": os.getenv("TWITTER_BEARER_TOKEN", ""),
            "enabled": bool(os.getenv("TWITTER_BEARER_TOKEN"))
        },
        "reddit": {
            "client_id": os.getenv("REDDIT_CLIENT_ID", ""),
            "client_secret": os.getenv("REDDIT_CLIENT_SECRET", ""),
            "user_agent": os.getenv("REDDIT_USER_AGENT", "TIFA:threat-intel:v1.0 (by /u/yourusername)"),
            "enabled": bool(os.getenv("REDDIT_CLIENT_ID") and os.getenv("REDDIT_CLIENT_SECRET"))
        }
    }

    # Default subreddits for threat intelligence
    DEFAULT_THREAT_SUBREDDITS = [
        'cybersecurity', 'netsec', 'malware', 'AskNetsec',
        'ComputerSecurity', 'InfoSecNews', 'blackhat', 'ReverseEngineering'
    ]
    
