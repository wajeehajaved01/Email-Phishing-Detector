"""
Input validation utilities for Email Phishing Detector
Provides strict validation to prevent injection attacks and malformed input
"""

import re
from typing import Tuple, Optional
from urllib.parse import urlparse
from src.config import (
    MAX_EMAIL_SIZE,
    MAX_HEADER_LINE_LENGTH,
    MAX_FROM_ADDRESS_LENGTH,
    MAX_URLS_TO_ANALYZE,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ValidationError(Exception):
    """Custom exception for validation errors"""

    pass


class EmailValidator:
    """
    Comprehensive email validation
    Validates structure, size, and format without executing anything
    """

    # RFC 5322 simplified email regex
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    )

    HEADER_INJECTION_PATTERN = re.compile(r"[\r\n](?![ \t])")

    @staticmethod
    def validate_email_address(address: str) -> Tuple[bool, str]:
        """
        Validate email address format
        
        Args:
            address: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not address:
            return False, "Email address cannot be empty"

        if len(address) > MAX_FROM_ADDRESS_LENGTH:
            return False, f"Email address exceeds max length of {MAX_FROM_ADDRESS_LENGTH}"

        if not EmailValidator.EMAIL_PATTERN.match(address):
            return False, "Invalid email address format"

        return True, ""

    @staticmethod
    def validate_header_line(header_line: str) -> Tuple[bool, str]:
        """
        Validate email header line (prevent header injection)
        
        Args:
            header_line: Header line to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not header_line:
            return False, "Header line cannot be empty"

        if len(header_line) > MAX_HEADER_LINE_LENGTH:
            return False, f"Header line exceeds max length of {MAX_HEADER_LINE_LENGTH}"

        if EmailValidator.HEADER_INJECTION_PATTERN.search(header_line):
            return False, "Header injection detected (newline in header)"

        return True, ""

    @staticmethod
    def validate_email_file_size(file_size: int) -> Tuple[bool, str]:
        """
        Validate email file size
        
        Args:
            file_size: Size in bytes
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if file_size <= 0:
            return False, "Email file size must be positive"

        if file_size > MAX_EMAIL_SIZE:
            return False, f"Email file exceeds maximum size of {MAX_EMAIL_SIZE} bytes"

        return True, ""


class URLValidator:
    """
    URL validation and sanitization
    Detects suspicious patterns and obfuscation
    """

    SUSPICIOUS_SCHEMES = {"data:", "javascript:", "vbscript:", "file:", "about:"}

    @staticmethod
    def validate_url(url_string: str) -> Tuple[bool, str]:
        """
        Validate URL format and detect suspicious characteristics
        
        Args:
            url_string: URL to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url_string:
            return False, "URL cannot be empty"

        # Check for suspicious schemes
        for scheme in URLValidator.SUSPICIOUS_SCHEMES:
            if url_string.lower().startswith(scheme):
                return False, f"Suspicious URL scheme detected: {scheme}"

        # Try to parse URL
        try:
            parsed = urlparse(url_string)
            if not parsed.scheme or not parsed.netloc:
                return False, "URL is missing scheme or netloc"
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"

        # Check for suspicious length (obfuscation indicator)
        if len(url_string) > 500:
            return False, "URL is unusually long (potential obfuscation)"

        return True, ""

    @staticmethod
    def extract_domain(url_string: str) -> Optional[str]:
        """
        Safely extract domain from URL
        
        Args:
            url_string: URL string
            
        Returns:
            Domain name or None if invalid
        """
        try:
            parsed = urlparse(url_string)
            return parsed.netloc.lower() if parsed.netloc else None
        except Exception as e:
            logger.warning(f"Failed to extract domain from URL: {e}")
            return None

    @staticmethod
    def is_ip_address(url_string: str) -> bool:
        """
        Check if URL contains IP address instead of domain
        (potential phishing indicator)
        
        Args:
            url_string: URL string
            
        Returns:
            True if URL uses IP address
        """
        domain = URLValidator.extract_domain(url_string)
        if not domain:
            return False

        # Simple IPv4 check
        parts = domain.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except (ValueError, TypeError):
                return False

        return False


class FileValidator:
    """
    File and attachment validation
    """

    @staticmethod
    def validate_file_path(file_path: str) -> Tuple[bool, str]:
        """
        Validate file path (prevent directory traversal)
        
        Args:
            file_path: File path to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not file_path:
            return False, "File path cannot be empty"

        # Prevent directory traversal
        if ".." in file_path:
            return False, "Directory traversal detected in file path"

        if file_path.startswith("/etc/") or file_path.startswith("C:\\Windows\\"):
            return False, "Access to system directories denied"

        return True, ""

    @staticmethod
    def validate_filename(filename: str) -> Tuple[bool, str]:
        """
        Validate filename (prevent injection)
        
        Args:
            filename: Filename to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not filename:
            return False, "Filename cannot be empty"

        # Check for suspicious characters
        if any(char in filename for char in ["\0", "\n", "\r"]):
            return False, "Filename contains null or control characters"

        # Maximum filename length (filesystem limit)
        if len(filename) > 255:
            return False, "Filename exceeds maximum length"

        return True, ""


class InputSanitizer:
    """
    Input sanitization utilities
    """

    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 1000) -> str:
        """
        Sanitize string input
        
        Args:
            input_str: Input string
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not isinstance(input_str, str):
            return ""

        # Remove null bytes
        sanitized = input_str.replace("\0", "")

        # Limit length
        sanitized = sanitized[:max_length]

        return sanitized.strip()

    @staticmethod
    def normalize_email_address(address: str) -> str:
        """
        Normalize email address (lowercase, strip whitespace)
        
        Args:
            address: Email address
            
        Returns:
            Normalized address
        """
        if not address:
            return ""
        return address.lower().strip()
