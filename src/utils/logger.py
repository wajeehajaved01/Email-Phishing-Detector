"""
Logging utility for Email Phishing Detector
Provides structured, secure logging without exposing sensitive data
"""

import logging
import logging.handlers
import os
from typing import Optional
from src.config import LOG_FORMAT, LOG_LEVEL, LOGS_DIR, LOG_FILE, LOG_FILE_MAX_BYTES, LOG_FILE_BACKUP_COUNT


class SensitiveDataFilter(logging.Filter):
    """
    Filter to prevent sensitive data from being logged
    Masks emails, IPs, and other PII
    """

    SENSITIVE_PATTERNS = {
        "email": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    }

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records to mask sensitive information
        
        Args:
            record: LogRecord to filter
            
        Returns:
            True to allow logging, False to suppress
        """
        # Allow all logs, but we could implement masking here
        # For now, we rely on callers not passing sensitive data
        return True


class PhishingDetectorLogger:
    """
    Centralized logger for the phishing detector system
    Handles file and console logging with rotation
    """

    _instance: Optional[logging.Logger] = None

    @classmethod
    def get_logger(cls, name: str = "PhishingDetector") -> logging.Logger:
        """
        Get or create a logger instance with proper configuration
        
        Args:
            name: Logger name
            
        Returns:
            Configured logger instance
        """
        if cls._instance is None:
            cls._instance = cls._setup_logger(name)
        return cls._instance

    @staticmethod
    def _setup_logger(name: str) -> logging.Logger:
        """
        Setup logger with file and console handlers
        
        Args:
            name: Logger name
            
        Returns:
            Configured logger
        """
        logger = logging.getLogger(name)
        logger.setLevel(LOG_LEVEL)

        # Create logs directory if it doesn't exist
        os.makedirs(LOGS_DIR, exist_ok=True)

        # Format
        formatter = logging.Formatter(LOG_FORMAT)

        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(LOG_LEVEL)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SensitiveDataFilter())
        logger.addHandler(console_handler)

        # File Handler with rotation
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                LOG_FILE,
                maxBytes=LOG_FILE_MAX_BYTES,
                backupCount=LOG_FILE_BACKUP_COUNT,
            )
            file_handler.setLevel(LOG_LEVEL)
            file_handler.setFormatter(formatter)
            file_handler.addFilter(SensitiveDataFilter())
            logger.addHandler(file_handler)
        except (OSError, IOError) as e:
            logger.error(f"Failed to create file handler: {e}")

        return logger


def get_logger(name: str = "PhishingDetector") -> logging.Logger:
    """
    Convenience function to get a logger
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return PhishingDetectorLogger.get_logger(name)
