"""
Threat intelligence data structures and types
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List
from datetime import datetime
from enum import Enum


class ThreatType(Enum):
    """Types of threats"""
    PHISHING = "phishing"
    MALWARE = "malware"
    SPAM = "spam"
    C2_COMMUNICATION = "c2_communication"
    ABUSE = "abuse"
    EXPLOIT = "exploit"
    PUP = "pup"
    UNKNOWN = "unknown"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FileReputation:
    """
    File reputation information
    Represents threat intelligence about a file
    """
    file_hash: str  # SHA-256
    filename: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    
    # Threat data
    is_malicious: bool = False
    threat_types: List[ThreatType] = field(default_factory=list)
    threat_severity: ThreatSeverity = ThreatSeverity.INFO
    
    # Detection info
    detection_count: int = 0
    detection_engines: List[str] = field(default_factory=list)
    
    # Metadata
    last_analysis_date: Optional[datetime] = None
    first_submission_date: Optional[datetime] = None
    last_submission_date: Optional[datetime] = None
    
    # Intelligence source
    source: str = "local"  # local, virustotal, abuse.ch, etc.
    confidence_score: float = 0.0  # 0-1
    
    def is_suspicious(self) -> bool:
        """Determine if file should be considered suspicious"""
        return self.detection_count > 0 or self.is_malicious
    
    def get_threat_score(self) -> float:
        """
        Calculate threat score based on reputation
        
        Returns:
            Threat score (0-100)
        """
        if self.is_malicious:
            return 100.0
        if self.detection_count == 0:
            return 0.0
        # Score based on detection count (assume max 70 vendors)
        return min(100.0, (self.detection_count / 70.0) * 80.0)


@dataclass
class URLReputation:
    """
    URL reputation information
    """
    url: str
    domain: str
    
    # Threat data
    is_malicious: bool = False
    threat_types: List[ThreatType] = field(default_factory=list)
    threat_severity: ThreatSeverity = ThreatSeverity.INFO
    
    # Detection info
    detection_count: int = 0
    detection_engines: List[str] = field(default_factory=list)
    
    # Category
    categories: List[str] = field(default_factory=list)
    
    # Metadata
    last_analysis_date: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    
    # Intelligence source
    source: str = "local"
    confidence_score: float = 0.0
    
    def is_suspicious(self) -> bool:
        """Determine if URL should be considered suspicious"""
        return self.detection_count > 0 or self.is_malicious
    
    def get_threat_score(self) -> float:
        """
        Calculate threat score
        
        Returns:
            Threat score (0-100)
        """
        if self.is_malicious:
            return 100.0
        if self.detection_count == 0:
            return 0.0
        return min(100.0, (self.detection_count / 70.0) * 80.0)


@dataclass
class DomainReputation:
    """
    Domain reputation information
    """
    domain: str
    
    # Threat data
    is_malicious: bool = False
    threat_types: List[ThreatType] = field(default_factory=list)
    threat_severity: ThreatSeverity = ThreatSeverity.INFO
    
    # Reputation
    abuse_score: float = 0.0  # 0-100
    trust_score: float = 100.0  # 0-100
    
    # Metadata
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    
    # Intelligence source
    source: str = "local"
    
    def is_suspicious(self) -> bool:
        """Determine if domain should be considered suspicious"""
        return self.abuse_score > 25 or self.is_malicious
    
    def get_threat_score(self) -> float:
        """
        Calculate threat score
        
        Returns:
            Threat score (0-100)
        """
        if self.is_malicious:
            return 100.0
        return self.abuse_score


@dataclass
class ThreatIntelligenceCache:
    """
    In-memory cache for threat intelligence
    Prevents repeated lookups during analysis
    """
    files: Dict[str, FileReputation] = field(default_factory=dict)
    urls: Dict[str, URLReputation] = field(default_factory=dict)
    domains: Dict[str, DomainReputation] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    def add_file(self, reputation: FileReputation) -> None:
        """Add file reputation to cache"""
        self.files[reputation.file_hash] = reputation
    
    def add_url(self, reputation: URLReputation) -> None:
        """Add URL reputation to cache"""
        self.urls[reputation.url] = reputation
    
    def add_domain(self, reputation: DomainReputation) -> None:
        """Add domain reputation to cache"""
        self.domains[reputation.domain] = reputation
    
    def get_file(self, file_hash: str) -> Optional[FileReputation]:
        """Get file reputation from cache"""
        return self.files.get(file_hash)
    
    def get_url(self, url: str) -> Optional[URLReputation]:
        """Get URL reputation from cache"""
        return self.urls.get(url)
    
    def get_domain(self, domain: str) -> Optional[DomainReputation]:
        """Get domain reputation from cache"""
        return self.domains.get(domain)
    
    def clear(self) -> None:
        """Clear all cached data"""
        self.files.clear()
        self.urls.clear()
        self.domains.clear()
        self.last_updated = datetime.utcnow()
