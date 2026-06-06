"""
Attachment analyzer module
Extracts attachments, calculates SHA-256 hashes
Performs threat intelligence lookups
Detects dangerous file types
"""

import os
import hashlib
from typing import List, Optional, Tuple
from src.models.email_model import EmailMessage, EmailAttachment
from src.models.threat_intel import FileReputation, ThreatType, ThreatSeverity
from src.config import (
    DANGEROUS_EXTENSIONS,
    MAX_ATTACHMENT_SIZE,
    FILE_SIGNATURES,
    RED_FLAGS,
)
from src.utils.security import CryptoUtils
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AttachmentChecker:
    """
    Analyzes email attachments for threats
    Calculates cryptographic hashes
    Performs threat intelligence lookups
    Detects dangerous file types
    """

    def __init__(self):
        """Initialize attachment checker"""
        self.threat_score = 0.0
        self.threat_intel_cache = {}

    def analyze(self, email: EmailMessage) -> dict:
        """
        Perform complete attachment analysis
        
        Args:
            email: EmailMessage object
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting attachment analysis for email: {email.subject[:50]}")
        self.threat_score = 0.0

        if not email.has_attachments():
            logger.info("No attachments found")
            return {
                "attachments_found": 0,
                "attachment_analyses": [],
                "has_dangerous_files": False,
                "threat_score": 0.0,
            }

        # Analyze each attachment
        attachment_analyses = []
        dangerous_count = 0

        for attachment in email.attachments:
            analysis = self._analyze_attachment(attachment)
            attachment_analyses.append(analysis)
            if analysis["is_suspicious"]:
                dangerous_count += 1

        result = {
            "attachments_found": len(email.attachments),
            "attachment_analyses": attachment_analyses,
            "has_dangerous_files": dangerous_count > 0,
            "dangerous_count": dangerous_count,
            "threat_score": self.threat_score,
        }

        logger.info(
            f"Attachment analysis complete. Found {len(email.attachments)} attachments, "
            f"{dangerous_count} suspicious. Threat score: {self.threat_score}"
        )
        return result

    def _analyze_attachment(self, attachment: EmailAttachment) -> dict:
        """
        Analyze single attachment
        
        Args:
            attachment: EmailAttachment object
            
        Returns:
            Dictionary with analysis results
        """
        logger.debug(f"Analyzing attachment: {attachment.filename}")
        analysis = {
            "filename": attachment.filename,
            "content_type": attachment.content_type,
            "size_bytes": attachment.size_bytes,
            "is_suspicious": False,
            "threat_indicators": [],
            "threat_score": 0.0,
            "file_hash": None,
        }

        # Check file size
        if attachment.size_bytes > MAX_ATTACHMENT_SIZE:
            analysis["threat_indicators"].append(
                f"File exceeds maximum size ({attachment.size_bytes} bytes)"
            )
            analysis["is_suspicious"] = True
            analysis["threat_score"] += 20
            self.threat_score += 10
            logger.warning(f"File size exceeds limit: {attachment.filename}")

        # Check file extension
        dangerous_ext = self._check_dangerous_extension(attachment.filename)
        if dangerous_ext:
            analysis["threat_indicators"].append(
                f"Dangerous file extension: {dangerous_ext}"
            )
            analysis["is_suspicious"] = True
            analysis["threat_score"] += 40
            self.threat_score += RED_FLAGS.get("malicious_attachment", 50)
            logger.warning(f"Dangerous extension detected: {dangerous_ext}")

        # Check for double extension attacks
        if self._has_double_extension(attachment.filename):
            analysis["threat_indicators"].append("Double extension attack detected")
            analysis["is_suspicious"] = True
            analysis["threat_score"] += 35
            self.threat_score += 20
            logger.warning(f"Double extension detected: {attachment.filename}")

        # Simulate hash calculation (actual hash would be calculated from file content)
        file_hash = self._simulate_file_hash(attachment.filename)
        analysis["file_hash"] = file_hash

        # Perform threat intelligence lookup (simulated)
        reputation = self._lookup_threat_intelligence(file_hash, attachment.filename)
        if reputation.is_malicious:
            analysis["threat_indicators"].append(
                f"File detected as malicious by {len(reputation.detection_engines)} engines"
            )
            analysis["is_suspicious"] = True
            analysis["threat_score"] = 95.0
            self.threat_score += RED_FLAGS.get("malicious_attachment", 50)
            logger.warning(f"Malicious file detected: {attachment.filename}")
        elif reputation.detection_count > 0:
            analysis["threat_indicators"].append(
                f"File flagged by {reputation.detection_count} threat engines"
            )
            analysis["is_suspicious"] = True
            analysis["threat_score"] += 60
            self.threat_score += 25
            logger.warning(f"Suspicious file detected: {attachment.filename}")

        return analysis

    def _check_dangerous_extension(self, filename: str) -> Optional[str]:
        """
        Check if file has dangerous extension
        
        Args:
            filename: Filename to check
            
        Returns:
            Dangerous extension or None
        """
        if not filename:
            return None

        filename_lower = filename.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if filename_lower.endswith(ext):
                return ext
        return None

    def _has_double_extension(self, filename: str) -> bool:
        """
        Detect double extension attack (e.g., file.exe.pdf)
        
        Args:
            filename: Filename to check
            
        Returns:
            True if double extension detected
        """
        if not filename:
            return False

        # Split filename by dots
        parts = filename.split(".")
        if len(parts) < 3:
            return False

        # Check if second-to-last extension is executable
        filename_lower = filename.lower()
        for ext in DANGEROUS_EXTENSIONS:
            # Check if dangerous extension appears before final extension
            pattern = ext + "."
            if pattern in filename_lower:
                return True

        return False

    def _simulate_file_hash(self, filename: str) -> str:
        """
        Simulate file hash calculation
        In production, this would hash actual file content
        
        Args:
            filename: Filename
            
        Returns:
            Simulated SHA-256 hash
        """
        # For lab purposes, generate hash from filename
        hash_obj = hashlib.sha256()
        hash_obj.update(filename.encode("utf-8"))
        return hash_obj.hexdigest()

    def _lookup_threat_intelligence(self, file_hash: str, filename: str) -> FileReputation:
        """
        Lookup file in threat intelligence database
        Simulated for lab purposes
        
        Args:
            file_hash: SHA-256 hash of file
            filename: Original filename
            
        Returns:
            FileReputation object
        """
        # Check cache first
        if file_hash in self.threat_intel_cache:
            return self.threat_intel_cache[file_hash]

        # Simulate threat intelligence lookup
        reputation = FileReputation(
            file_hash=file_hash,
            filename=filename,
            is_malicious=False,
            threat_types=[],
            detection_count=0,
            source="simulated_virustotal",
        )

        # Simulate detection for known malicious patterns
        if self._is_known_malicious_hash(file_hash):
            reputation.is_malicious = True
            reputation.threat_types = [ThreatType.MALWARE]
            reputation.threat_severity = ThreatSeverity.CRITICAL
            reputation.detection_count = 45
            reputation.detection_engines = ["Avast", "Norton", "Kaspersky", "McAfee"]
            logger.warning(f"Known malicious file detected: {filename}")
        elif filename.endswith(".exe") or filename.endswith(".bat"):
            # Simulate higher detection for executable files
            reputation.detection_count = 5
            reputation.detection_engines = ["Generic.Trojan"]
            logger.debug(f"Executable file with simulated detections: {filename}")

        # Cache result
        self.threat_intel_cache[file_hash] = reputation
        return reputation

    def _is_known_malicious_hash(self, file_hash: str) -> bool:
        """
        Check if hash is in known malicious list
        
        Args:
            file_hash: File hash to check
            
        Returns:
            True if hash is known malicious
        """
        # Simulated known malicious hashes
        known_malicious = {
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5 example
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1 example
        }
        return file_hash in known_malicious
