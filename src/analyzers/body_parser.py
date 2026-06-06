"""
Email body parser and URL analyzer
Extracts URLs and analyzes them against malicious patterns
Detects phishing keywords and suspicious content
"""

import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from src.models.email_model import EmailMessage, URLAnalysis
from src.config import (
    SUSPICIOUS_TLDS,
    PHISHING_KEYWORDS,
    KNOWN_MALICIOUS_DOMAINS,
    CREDENTIAL_HARVESTING_KEYWORDS,
    RED_FLAGS,
)
from src.utils.validators import URLValidator
from src.utils.logger import get_logger

logger = get_logger(__name__)


class BodyParser:
    """
    Analyzes email body for malicious content
    Extracts and validates URLs
    Detects phishing indicators and suspicious patterns
    """

    # URL extraction regex (simplified but effective)
    URL_PATTERN = re.compile(
        r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)"
    )

    def __init__(self):
        """Initialize body parser"""
        self.threat_score = 0.0

    def analyze(self, email: EmailMessage) -> dict:
        """
        Perform complete body analysis
        
        Args:
            email: EmailMessage object
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting body analysis for email: {email.subject[:50]}")
        self.threat_score = 0.0

        body = email.get_body()
        if not body:
            logger.warning("Email has no body content")
            return {
                "urls": [],
                "suspicious_keywords": [],
                "phishing_indicators": [],
                "threat_score": 0.0,
            }

        # Extract and analyze URLs
        urls = self._extract_urls(body)
        url_analyses = [self._analyze_url(url) for url in urls]

        # Detect phishing keywords
        phishing_keywords = self._detect_phishing_keywords(body)

        # Detect credential harvesting attempts
        credential_harvesting = self._detect_credential_harvesting(body, url_analyses)

        result = {
            "urls_found": len(urls),
            "url_analyses": [self._url_to_dict(ua) for ua in url_analyses],
            "phishing_keywords": phishing_keywords,
            "credential_harvesting_indicators": credential_harvesting,
            "threat_score": self.threat_score,
        }

        logger.info(f"Body analysis complete. Found {len(urls)} URLs. Threat score: {self.threat_score}")
        return result

    def _extract_urls(self, text: str) -> List[str]:
        """
        Extract URLs from email body
        
        Args:
            text: Email body text
            
        Returns:
            List of URLs found
        """
        if not text:
            return []

        urls = []
        for match in self.URL_PATTERN.finditer(text):
            url = match.group()
            # Validate before adding
            is_valid, _ = URLValidator.validate_url(url)
            if is_valid:
                urls.append(url)

        logger.debug(f"Extracted {len(urls)} URLs from body")
        return urls

    def _analyze_url(self, url: str) -> URLAnalysis:
        """
        Analyze single URL for malicious indicators
        
        Args:
            url: URL to analyze
            
        Returns:
            URLAnalysis object
        """
        analysis = URLAnalysis(url=url, is_valid=True)

        # Validate URL
        is_valid, error = URLValidator.validate_url(url)
        if not is_valid:
            analysis.is_valid = False
            analysis.error = error
            analysis.threat_score = 50.0
            self.threat_score += RED_FLAGS.get("suspicious_url", 20)
            logger.warning(f"Invalid URL detected: {error}")
            return analysis

        # Extract domain
        domain = URLValidator.extract_domain(url)
        analysis.domain = domain

        if not domain:
            analysis.is_suspicious = True
            analysis.threat_indicators.append("Could not extract domain from URL")
            return analysis

        # Check for IP-based URLs (suspicious)
        if URLValidator.is_ip_address(url):
            analysis.threat_indicators.append("URL uses IP address instead of domain")
            analysis.is_suspicious = True
            analysis.threat_score += 30
            self.threat_score += 15
            logger.warning(f"IP-based URL detected: {url}")

        # Check against known malicious domains
        if self._is_malicious_domain(domain):
            analysis.is_suspicious = True
            analysis.threat_indicators.append(f"Domain {domain} is in malicious database")
            analysis.threat_score = 90.0
            self.threat_score += RED_FLAGS.get("suspicious_url", 20)
            logger.warning(f"Malicious domain detected: {domain}")
            return analysis

        # Check for suspicious TLDs
        suspicious_tld = self._check_suspicious_tld(domain)
        if suspicious_tld:
            analysis.threat_indicators.append(f"Suspicious TLD: {suspicious_tld}")
            analysis.is_suspicious = True
            analysis.threat_score += 25
            self.threat_score += 12
            logger.warning(f"Suspicious TLD detected in {domain}")

        # Check for credential harvesting keywords in URL
        if self._contains_credential_keywords(url):
            analysis.threat_indicators.append("URL contains credential harvesting keywords")
            analysis.is_suspicious = True
            analysis.threat_score += 35
            self.threat_score += 15
            logger.warning(f"Credential harvesting attempt detected in URL: {url}")

        return analysis

    def _is_malicious_domain(self, domain: str) -> bool:
        """
        Check if domain is in malicious database
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain is malicious
        """
        domain_lower = domain.lower()
        return domain_lower in KNOWN_MALICIOUS_DOMAINS

    def _check_suspicious_tld(self, domain: str) -> Optional[str]:
        """
        Check if domain uses suspicious TLD
        
        Args:
            domain: Domain to check
            
        Returns:
            Suspicious TLD or None
        """
        domain_lower = domain.lower()
        for tld in SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                return tld
        return None

    def _contains_credential_keywords(self, url: str) -> bool:
        """
        Check if URL contains credential harvesting keywords
        
        Args:
            url: URL to check
            
        Returns:
            True if credential keywords found
        """
        url_lower = url.lower()
        for keyword in CREDENTIAL_HARVESTING_KEYWORDS:
            if keyword in url_lower:
                return True
        return False

    def _detect_phishing_keywords(self, text: str) -> List[str]:
        """
        Detect phishing keywords in email body
        
        Args:
            text: Email body text
            
        Returns:
            List of detected keywords
        """
        detected = []
        text_lower = text.lower()

        for keyword in PHISHING_KEYWORDS:
            # Count occurrences
            if keyword in text_lower:
                detected.append(keyword)
                self.threat_score += 5
                logger.debug(f"Phishing keyword detected: {keyword}")

        # Remove duplicates
        return list(set(detected))

    def _detect_credential_harvesting(self, body: str, url_analyses: List[URLAnalysis]) -> List[str]:
        """
        Detect credential harvesting attempts
        
        Args:
            body: Email body
            url_analyses: Analyzed URLs
            
        Returns:
            List of harvesting indicators
        """
        indicators = []

        # Check for requests to verify account/credentials
        harvesting_patterns = [
            r"verify.*account",
            r"confirm.*password",
            r"update.*information",
            r"validate.*credential",
        ]

        body_lower = body.lower()
        for pattern in harvesting_patterns:
            if re.search(pattern, body_lower):
                indicators.append(pattern)
                self.threat_score += 20
                logger.warning(f"Credential harvesting pattern detected: {pattern}")

        # Check if suspicious URLs combined with harvesting language
        suspicious_urls = [ua for ua in url_analyses if ua.is_suspicious]
        if suspicious_urls and indicators:
            logger.warning("Credential harvesting attempt detected (suspicious URLs + harvesting language)")

        return indicators

    @staticmethod
    def _url_to_dict(analysis: URLAnalysis) -> dict:
        """
        Convert URLAnalysis to dictionary
        
        Args:
            analysis: URLAnalysis object
            
        Returns:
            Dictionary representation
        """
        return {
            "url": analysis.url,
            "is_valid": analysis.is_valid,
            "domain": analysis.domain,
            "is_suspicious": analysis.is_suspicious,
            "threat_indicators": analysis.threat_indicators,
            "threat_score": analysis.threat_score,
            "error": analysis.error,
        }
