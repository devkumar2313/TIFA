"""
Social Media Crawlers for Twitter and Reddit
Live crawling implementation for TIFA
"""
import re
import time
import logging
from datetime import datetime
from typing import List, Dict, Any
import requests
import json
from tifa.core.models import ThreatIntelItem
from tifa.analyzers.ioc_extractor import IOCExtractor

logger = logging.getLogger(__name__)

class TwitterCrawler:
    """Twitter API v2 crawler for threat intelligence"""
    
    def __init__(self, bearer_token: str):
        self.bearer_token = bearer_token
        self.base_url = "https://api.twitter.com/2"
        self.headers = {
            "Authorization": f"Bearer {bearer_token}",
            "User-Agent": "TIFA-ThreatIntel/1.0"
        }
        self.ioc_extractor = IOCExtractor()
    
    def search_threats(self, query: str = None, max_results: int = 100) -> List[ThreatIntelItem]:
        """Search for threat-related tweets"""
        if not query:
            # Default threat intelligence keywords
            query = "(malware OR ransomware OR APT OR IOC OR vulnerability OR exploit OR phishing OR botnet OR trojan) -is:retweet lang:en"
        
        url = f"{self.base_url}/tweets/search/recent"
        params = {
            "query": query,
            "max_results": min(max_results, 100),
            "tweet.fields": "created_at,author_id,public_metrics,context_annotations",
            "expansions": "author_id",
            "user.fields": "username,verified"
        }
        
        threats = []
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            tweets = data.get("data", [])
            users = {user["id"]: user for user in data.get("includes", {}).get("users", [])}
            
            for tweet in tweets:
                try:
                    author = users.get(tweet["author_id"], {})
                    username = author.get("username", "unknown")
                    
                    # Extract IOCs from tweet text
                    iocs = self.ioc_extractor.extract_iocs(tweet["text"])
                    
                    # Only process tweets with IOCs or threat keywords
                    if iocs or self._has_threat_indicators(tweet["text"]):
                        threat_item = ThreatIntelItem(
                            title=f"Twitter Threat Intel from @{username}",
                            source="Twitter",
                            link=f"https://twitter.com/{username}/status/{tweet['id']}",
                            published_date=tweet["created_at"],
                            summary=tweet["text"][:500],
                            iocs=iocs
                        )
                        
                        # Add metadata
                        threat_item.category = self._categorize_threat(tweet["text"])
                        threat_item.confidence = "Medium"
                        threat_item.priority = "Medium"
                        
                        threats.append(threat_item)
                        
                except Exception as e:
                    logger.error(f"Error processing tweet {tweet.get('id', 'unknown')}: {e}")
                    continue
                    
        except requests.RequestException as e:
            logger.error(f"Twitter API error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in Twitter crawler: {e}")
            
        return threats
    
    def _has_threat_indicators(self, text: str) -> bool:
        """Check if text contains threat intelligence indicators"""
        threat_keywords = [
            'malware', 'ransomware', 'apt', 'ioc', 'vulnerability', 'cve-',
            'exploit', 'phishing', 'botnet', 'trojan', 'backdoor', 'c2',
            'command and control', 'threat actor', 'campaign'
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in threat_keywords)
    
    def _categorize_threat(self, text: str) -> str:
        """Categorize threat based on content"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ['ransomware', 'ransom']):
            return 'Ransomware'
        elif any(word in text_lower for word in ['apt', 'advanced persistent']):
            return 'APT'
        elif any(word in text_lower for word in ['phishing', 'phish']):
            return 'Phishing'
        elif any(word in text_lower for word in ['malware', 'trojan', 'backdoor']):
            return 'Malware'
        elif any(word in text_lower for word in ['vulnerability', 'cve-', 'exploit']):
            return 'Vulnerability'
        else:
            return 'General'


class RedditCrawler:
    """Reddit crawler for threat intelligence subreddits"""
    
    def __init__(self, client_id: str, client_secret: str, user_agent: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.user_agent = user_agent
        self.access_token = None
        self.ioc_extractor = IOCExtractor()
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate with Reddit API"""
        try:
            auth = requests.auth.HTTPBasicAuth(self.client_id, self.client_secret)
            data = {
                'grant_type': 'client_credentials'
            }
            headers = {'User-Agent': self.user_agent}
            
            response = requests.post(
                'https://www.reddit.com/api/v1/access_token',
                auth=auth, data=data, headers=headers, timeout=30
            )
            response.raise_for_status()
            
            self.access_token = response.json()['access_token']
            
        except Exception as e:
            logger.error(f"Reddit authentication failed: {e}")
            raise
    
    def crawl_subreddits(self, subreddits: List[str] = None, limit: int = 50) -> List[ThreatIntelItem]:
        """Crawl threat intelligence from specified subreddits"""
        if not subreddits:
            # Default threat intelligence subreddits
            subreddits = [
                'cybersecurity', 'netsec', 'malware', 'AskNetsec',
                'ComputerSecurity', 'InfoSecNews', 'blackhat', 'ReverseEngineering'
            ]
        
        threats = []
        headers = {
            'Authorization': f'bearer {self.access_token}',
            'User-Agent': self.user_agent
        }
        
        for subreddit in subreddits:
            try:
                url = f"https://oauth.reddit.com/r/{subreddit}/hot"
                params = {'limit': limit}
                
                response = requests.get(url, headers=headers, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                posts = data.get('data', {}).get('children', [])
                
                for post_data in posts:
                    try:
                        post = post_data['data']
                        
                        # Combine title and selftext for analysis
                        content = f"{post.get('title', '')} {post.get('selftext', '')}"
                        
                        # Extract IOCs
                        iocs = self.ioc_extractor.extract_iocs(content)
                        
                        # Only process posts with IOCs or threat content
                        if iocs or self._is_threat_related(content):
                            threat_item = ThreatIntelItem(
                                title=post.get('title', 'No title'),
                                source=f"Reddit - r/{subreddit}",
                                link=f"https://reddit.com{post.get('permalink', '')}",
                                published_date=datetime.fromtimestamp(post.get('created_utc', 0)).isoformat(),
                                summary=content[:500],
                                iocs=iocs
                            )
                            
                            # Add metadata
                            threat_item.category = self._categorize_threat(content)
                            threat_item.confidence = "Medium"
                            threat_item.priority = self._assess_priority(post)
                            
                            threats.append(threat_item)
                            
                    except Exception as e:
                        logger.error(f"Error processing Reddit post: {e}")
                        continue
                        
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error crawling r/{subreddit}: {e}")
                continue
                
        return threats
    
    def _is_threat_related(self, content: str) -> bool:
        """Check if content is threat-related"""
        threat_keywords = [
            'malware', 'virus', 'ransomware', 'apt', 'ioc', 'indicator',
            'vulnerability', 'cve', 'exploit', 'phishing', 'botnet',
            'trojan', 'backdoor', 'c2', 'command and control', 'threat',
            'attack', 'breach', 'compromise', 'incident', 'campaign'
        ]
        content_lower = content.lower()
        return any(keyword in content_lower for keyword in threat_keywords)
    
    def _categorize_threat(self, content: str) -> str:
        """Categorize threat based on content"""
        content_lower = content.lower()
        
        if any(word in content_lower for word in ['ransomware', 'ransom']):
            return 'Ransomware'
        elif any(word in content_lower for word in ['apt', 'advanced persistent']):
            return 'APT'
        elif any(word in content_lower for word in ['phishing', 'phish']):
            return 'Phishing'
        elif any(word in content_lower for word in ['malware', 'virus', 'trojan']):
            return 'Malware'
        elif any(word in content_lower for word in ['vulnerability', 'cve', 'exploit']):
            return 'Vulnerability'
        else:
            return 'General'
    
    def _assess_priority(self, post: Dict) -> str:
        """Assess priority based on Reddit metrics"""
        score = post.get('score', 0)
        num_comments = post.get('num_comments', 0)
        
        if score > 100 or num_comments > 50:
            return 'High'
        elif score > 20 or num_comments > 10:
            return 'Medium'
        else:
            return 'Low'


class SocialMediaCrawler:
    """Main social media crawler orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.twitter_crawler = None
        self.reddit_crawler = None
        
        # Initialize Twitter crawler if credentials provided
        if config.get('twitter', {}).get('bearer_token'):
            self.twitter_crawler = TwitterCrawler(
                bearer_token=config['twitter']['bearer_token']
            )
        
        # Initialize Reddit crawler if credentials provided
        reddit_config = config.get('reddit', {})
        if all(reddit_config.get(key) for key in ['client_id', 'client_secret', 'user_agent']):
            self.reddit_crawler = RedditCrawler(
                client_id=reddit_config['client_id'],
                client_secret=reddit_config['client_secret'],
                user_agent=reddit_config['user_agent']
            )
    
    def crawl_all(self, max_items_per_platform: int = 50) -> List[ThreatIntelItem]:
        """Crawl threat intelligence from all configured platforms"""
        all_threats = []
        
        # Crawl Twitter
        if self.twitter_crawler:
            try:
                logger.info("Crawling Twitter for threat intelligence...")
                twitter_threats = self.twitter_crawler.search_threats(max_results=max_items_per_platform)
                all_threats.extend(twitter_threats)
                logger.info(f"Collected {len(twitter_threats)} threats from Twitter")
            except Exception as e:
                logger.error(f"Twitter crawling failed: {e}")
        
        # Crawl Reddit
        if self.reddit_crawler:
            try:
                logger.info("Crawling Reddit for threat intelligence...")
                reddit_threats = self.reddit_crawler.crawl_subreddits(limit=max_items_per_platform)
                all_threats.extend(reddit_threats)
                logger.info(f"Collected {len(reddit_threats)} threats from Reddit")
            except Exception as e:
                logger.error(f"Reddit crawling failed: {e}")
        
        return all_threats
