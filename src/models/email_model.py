"""
Data models for Email Phishing Detector
Defines core data structures for email analysis
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum


class AuthenticationResult(Enum):
    """Email authentication verification results"""
    PASS = "PASS"
    FAIL = "FAIL"
    NEUTRAL = "NEUTRAL"
    SOFTFAIL = "SOFTFAIL"
    UNKNOWN = "UNKNOWN"


@dataclass
class EmailHeader:
    """
    Represents an email header field
    Immutable representation of header data
    """
    name: str
    value: str
    raw: str = ""

    def __post_init__(self):
        """Validate header data"""
        if not self.name:
            raise ValueError("Header name cannot be empty")
        if len(self.name) > 100:
            raise ValueError("Header name is too long")


@dataclass
class EmailRecipient:
    """
    Represents an email recipient
    """
    address: str
    display_name: Optional[str] = None
    is_valid: bool = True


@dataclass
class EmailAttachment:
    """
    Represents an email attachment
    Stores metadata without actual file content
    """
    filename: str
    content_type: str
    size_bytes: int
    sha256_hash: Optional[str] = None
    is_suspicious: bool = False
    threat_score: float = 0.0
    error: Optional[str] = None


@dataclass
class URLAnalysis:
    """
    Results of URL analysis
    """
    url: str
    is_valid: bool
    domain: Optional[str] = None
    is_suspicious: bool = False
    threat_indicators: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    error: Optional[str] = None


@dataclass
class SPFResult:
    """
    SPF verification result
    """
    result: AuthenticationResult
    domain: str
    record: Optional[str] = None
    mechanisms: List[Dict] = field(default_factory=list)
    explanation: str = ""
    error: Optional[str] = None


@dataclass
class DKIMResult:
    """
    DKIM verification result
    """
    result: AuthenticationResult
    domain: str
    selector: Optional[str] = None
    signature: Optional[str] = None
    is_valid_structure: bool = False
    explanation: str = ""
    error: Optional[str] = None


@dataclass
class DMARCResult:
    """
    DMARC verification result
    """
    result: AuthenticationResult
    domain: str
    record: Optional[str] = None
    policy: Optional[str] = None
    alignment_dkim: bool = False
    alignment_spf: bool = False
    explanation: str = ""
    error: Optional[str] = None


@dataclass
class HeaderAnalysisResult:
    """
    Complete header analysis results
    """
    spf_result: SPFResult
    dkim_result: DKIMResult
    dmarc_result: DMARCResult
    from_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    headers_suspicious: bool = False
    header_issues: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BodyAnalysisResult:
    """
    Email body analysis results
    """
    urls_found: List[URLAnalysis] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    phishing_indicators: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AttachmentAnalysisResult:
    """
    Attachment analysis results
    """
    attachments: List[EmailAttachment] = field(default_factory=list)
    total_suspicious: int = 0
    has_dangerous_files: bool = False
    threat_score: float = 0.0
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EmailMessage:
    """
    Core email message representation
    Stores parsed email data for analysis
    """
    subject: str
    sender: str
    recipients: List[EmailRecipient] = field(default_factory=list)
    cc: List[EmailRecipient] = field(default_factory=list)
    bcc: List[EmailRecipient] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body_plain: str = ""
    body_html: str = ""
    attachments: List[EmailAttachment] = field(default_factory=list)
    date_received: Optional[datetime] = None
    message_id: Optional[str] = None
    size_bytes: int = 0
    is_encrypted: bool = False
    error: Optional[str] = None

    def has_attachments(self) -> bool:
        """Check if email has attachments"""
        return len(self.attachments) > 0

    def get_body(self) -> str:
        """Get email body (prefer plain text)"""
        return self.body_plain if self.body_plain else self.body_html

    @staticmethod
    def from_file(file_path: str) -> 'EmailMessage':
        """
        Create EmailMessage from EML file
        
        Args:
            file_path: Path to .eml file
            
        Returns:
            EmailMessage instance
        """
        from email import message_from_file
        import os

        try:
            if not os.path.exists(file_path):
                msg = EmailMessage(
                    subject="",
                    sender="",
                    error=f"File not found: {file_path}"
                )
                return msg

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_msg = message_from_file(f)

            # Extract basic fields
            email = EmailMessage(
                subject=email_msg.get('Subject', ''),
                sender=email_msg.get('From', ''),
                headers=dict(email_msg.items()),
                body_plain=email_msg.get_payload()
                if isinstance(email_msg.get_payload(), str)
                else "",
                message_id=email_msg.get('Message-ID'),
            )

            # Extract recipients
            if email_msg.get('To'):
                email.recipients = [
                    EmailRecipient(address=addr.strip())
                    for addr in email_msg.get('To').split(',')
                ]

            return email

        except Exception as e:
            return EmailMessage(
                subject="",
                sender="",
                error=f"Error parsing email file: {str(e)}"
            )
