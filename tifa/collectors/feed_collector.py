"""
Feed collection from RSS/Atom sources and threat intelligence aggregation
Enhanced with social media crawling capabilities
"""

import feedparser
import hashlib
from datetime import datetime
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time
from ..core.models import ThreatIntelItem
from ..database.manager import ThreatIntelDatabase
from ..analyzers.ioc_extractor import IOCExtractor
from ..core.config import Config

logger = logging.getLogger(__name__)

class FeedCollector:
    """Collect threat intelligence from RSS/Atom feeds and social media sources"""
    
    def __init__(self, db: ThreatIntelDatabase, ioc_extractor: IOCExtractor):
        self.db = db
        self.ioc_extractor = ioc_extractor
        self.feeds = Config.THREAT_FEEDS
        self.social_crawler = None
        self._init_social_media()
    
    def _init_social_media(self):
        """Initialize social media crawler if configured"""
        try:
            from .social_crawler import SocialMediaCrawler
            from ..core.config import SOCIAL_MEDIA_CONFIG
            
            # Check if any social media platform is configured
            if (SOCIAL_MEDIA_CONFIG.get('twitter', {}).get('enabled') or 
                SOCIAL_MEDIA_CONFIG.get('reddit', {}).get('enabled')):
                self.social_crawler = SocialMediaCrawler(SOCIAL_MEDIA_CONFIG)
                logger.info("Social media crawler initialized successfully")
        except ImportError:
            logger.warning("Social media crawler not available - install required dependencies")
        except Exception as e:
            logger.error(f"Failed to initialize social media crawler: {e}")
    
    def collect_from_feed(self, feed_info: dict) -> List[ThreatIntelItem]:
        """Collect threat intelligence from a single RSS/Atom feed"""
        items = []
        
        try:
            logger.info(f"Fetching feed: {feed_info['name']}")
            feed = feedparser.parse(feed_info['url'])
            
            if not hasattr(feed, 'entries'):
                logger.warning(f"No entries found in feed: {feed_info['name']}")
                return items
            
            for entry in feed.entries[:Config.MAX_ITEMS_PER_FEED]:
                try:
                    # Generate unique ID
                    item_id = hashlib.md5(f"{entry.link}_{entry.title}".encode()).hexdigest()
                    
                    # Skip if already exists
                    if self.db and self.db.item_exists(item_id):
                        continue
                    
                    # Extract text content
                    content = self._extract_content(entry)
                    
                    # Extract IOCs
                    iocs = self.ioc_extractor.extract_iocs(content)
                    
                    # Create threat intel item
                    item = ThreatIntelItem(
                        title=entry.title,
                        summary=self._truncate_description(getattr(entry, 'summary', '')),
                        source=feed_info['name'],
                        published_date=getattr(entry, 'published', datetime.now().isoformat()),
                        link=entry.link,
                        iocs=iocs
                    )
                    
                    # Set additional metadata
                    item.id = item_id
                    item.category = self._categorize_content(content)
                    item.tags = self._extract_tags(content)
                    item.confidence = "High"  # RSS feeds are generally reliable
                    item.priority = self._assess_priority(content, iocs)
                    
                    items.append(item)
                    
                except Exception as e:
                    logger.error(f"Error processing entry from {feed_info['name']}: {str(e)}")
                    continue
            
            logger.info(f"Collected {len(items)} items from {feed_info['name']}")
            
        except Exception as e:
            logger.error(f"Error collecting from {feed_info['name']}: {str(e)}")
        
        return items
    
    def collect_social_media(self) -> List[ThreatIntelItem]:
        """Collect threats from social media platforms"""
        if not self.social_crawler:
            logger.warning("Social media crawler not initialized")
            return []
        
        try:
            logger.info("Starting social media threat collection...")
            start_time = time.time()
            
            # Collect from all configured platforms
            threats = self.social_crawler.crawl_all(max_items_per_platform=50)
            
            # Process and enhance each threat
            processed_threats = []
            for threat in threats:
                try:
                    # Generate unique ID for social media content
                    threat.id = hashlib.md5(f"{threat.link}_{threat.title}".encode()).hexdigest()
                    
                    # Skip if already exists
                    if self.db and self.db.item_exists(threat.id):
                        continue
                    
                    # Enhance with additional processing
                    threat.tags = self._extract_tags(f"{threat.title} {threat.summary}")
                    threat.created_at = datetime.now().isoformat()
                    
                    processed_threats.append(threat)
                    
                    # Save to database immediately for social media content
                    if self.db:
                        self.db.save_item(threat)
                        
                except Exception as e:
                    logger.error(f"Error processing social media threat: {e}")
                    continue
            
            elapsed_time = time.time() - start_time
            logger.info(f"Social media collection completed in {elapsed_time:.2f}s - {len(processed_threats)} new threats")
            
            return processed_threats
            
        except Exception as e:
            logger.error(f"Social media collection failed: {e}")
            return []
    
    def collect_all_feeds(self, include_social_media: bool = True) -> List[ThreatIntelItem]:
        """Collect from all configured feeds and social media using multi-threading"""
        all_items = []
        
        # Collect from RSS/Atom feeds
        with ThreadPoolExecutor(max_workers=Config.MAX_FEED_WORKERS) as executor:
            future_to_feed = {
                executor.submit(self.collect_from_feed, feed): feed
                for feed in self.feeds
            }
            
            for future in as_completed(future_to_feed):
                feed = future_to_feed[future]
                try:
                    items = future.result()
                    all_items.extend(items)
                except Exception as e:
                    logger.error(f"Error in feed collection for {feed['name']}: {str(e)}")
        
        logger.info(f"RSS/Atom feeds collected: {len(all_items)} items")
        
        # Collect from social media if enabled
        if include_social_media and self.social_crawler:
            try:
                social_items = self.collect_social_media()
                all_items.extend(social_items)
                logger.info(f"Social media items collected: {len(social_items)}")
            except Exception as e:
                logger.error(f"Social media collection error: {e}")
        
        logger.info(f"Total items collected from all sources: {len(all_items)}")
        return all_items
    
    def collect_live_feeds(self, max_items_total: int = 100) -> Dict[str, Any]:
        """Collect threats with live updates and streaming capability"""
        results = {
            "rss_items": 0,
            "social_items": 0,
            "total_items": 0,
            "new_items": 0,
            "sources_processed": 0,
            "errors": [],
            "processing_time": 0
        }
        
        start_time = time.time()
        
        try:
            # Collect from RSS feeds (limited for speed)
            rss_items = []
            sources_processed = 0
            
            for feed in self.feeds[:5]:  # Limit to first 5 feeds for live updates
                try:
                    items = self.collect_from_feed(feed)
                    rss_items.extend(items[:10])  # Limit items per feed
                    sources_processed += 1
                except Exception as e:
                    results["errors"].append(f"RSS {feed['name']}: {str(e)}")
                    
            results["rss_items"] = len(rss_items)
            results["sources_processed"] = sources_processed
            
            # Collect from social media
            social_items = []
            if self.social_crawler:
                try:
                    social_items = self.collect_social_media()
                    results["social_items"] = len(social_items)
                except Exception as e:
                    results["errors"].append(f"Social Media: {str(e)}")
            
            # Combine and process
            all_items = rss_items + social_items
            new_items = 0
            
            for item in all_items:
                if self.db and not self.db.item_exists(item.id):
                    self.db.save_item(item)
                    new_items += 1
            
            results.update({
                "total_items": len(all_items),
                "new_items": new_items,
                "processing_time": round(time.time() - start_time, 2)
            })
            
        except Exception as e:
            results["errors"].append(f"General error: {str(e)}")
        
        return results
    
    def _extract_content(self, entry) -> str:
        """Extract full content from feed entry"""
        content_parts = []
        
        if hasattr(entry, 'title'):
            content_parts.append(entry.title)
        
        if hasattr(entry, 'summary'):
            content_parts.append(entry.summary)
        
        if hasattr(entry, 'content'):
            for content_item in entry.content:
                content_parts.append(content_item.value)
        
        return " ".join(content_parts)
    
    def _truncate_description(self, description: str, max_length: int = 500) -> str:
        """Truncate description to reasonable length"""
        if len(description) > max_length:
            return description[:max_length] + "..."
        return description
    
    def _extract_tags(self, text: str) -> List[str]:
        """Extract relevant tags from text"""
        tags = []
        text_lower = text.lower()
        
        # Use config threat keywords if available
        threat_keywords = getattr(Config, 'THREAT_KEYWORDS', [
            'malware', 'ransomware', 'apt', 'vulnerability', 'exploit',
            'phishing', 'botnet', 'trojan', 'backdoor', 'c2', 'ioc'
        ])
        
        for keyword in threat_keywords:
            if keyword in text_lower:
                tags.append(keyword)
        
        return list(set(tags))  # Remove duplicates
    
    def _categorize_content(self, content: str) -> str:
        """Categorize content based on threat intelligence patterns"""
        content_lower = content.lower()
        
        # Category mapping based on keywords
        categories = {
            'Ransomware': ['ransomware', 'ransom', 'lockbit', 'conti', 'revil'],
            'APT': ['apt', 'advanced persistent', 'nation state', 'sponsored'],
            'Malware': ['malware', 'virus', 'trojan', 'backdoor', 'rootkit'],
            'Phishing': ['phishing', 'phish', 'spear phishing', 'business email'],
            'Vulnerability': ['cve-', 'vulnerability', 'exploit', 'zero-day', 'patch'],
            'Botnet': ['botnet', 'c2', 'command and control', 'bot'],
            'Breach': ['breach', 'leak', 'data breach', 'compromise'],
            'Campaign': ['campaign', 'operation', 'attack campaign']
        }
        
        for category, keywords in categories.items():
            if any(keyword in content_lower for keyword in keywords):
                return category
        
        return 'General'
    
    def _assess_priority(self, content: str, iocs: Dict) -> str:
        """Assess priority based on content and IOCs"""
        content_lower = content.lower()
        
        # High priority indicators
        high_priority_keywords = [
            'zero-day', 'critical', 'urgent', 'active campaign',
            'widespread', 'supply chain', 'infrastructure'
        ]
        
        # Count IOCs
        ioc_count = sum(len(ioc_list) for ioc_list in iocs.values())
        
        if any(keyword in content_lower for keyword in high_priority_keywords):
            return 'High'
        elif ioc_count >= 5:
            return 'High'
        elif ioc_count >= 2:
            return 'Medium'
        else:
            return 'Low'
    
    def get_collection_status(self) -> Dict[str, Any]:
        """Get current status of collection capabilities"""
        status = {
            "rss_feeds": {
                "enabled": True,
                "count": len(self.feeds),
                "sources": [feed["name"] for feed in self.feeds[:5]]
            },
            "social_media": {
                "enabled": self.social_crawler is not None,
                "twitter": False,
                "reddit": False
            }
        }
        
        if self.social_crawler:
            try:
                from ..core.config import SOCIAL_MEDIA_CONFIG
                status["social_media"]["twitter"] = SOCIAL_MEDIA_CONFIG.get('twitter', {}).get('enabled', False)
                status["social_media"]["reddit"] = SOCIAL_MEDIA_CONFIG.get('reddit', {}).get('enabled', False)
            except:
                pass
        
        return status
