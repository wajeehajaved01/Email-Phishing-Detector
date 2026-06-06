"""
Email Phishing and Header Analyzer System
A comprehensive security tool for analyzing emails and detecting phishing attempts
"""

__version__ = "1.0.0"
__author__ = "Wajeeha Javed"
__license__ = "MIT"

from src.config import ThreatLevel, get_threat_level, get_recommendations
from src.models.email_model import EmailMessage
from src.models.analysis_report import AnalysisReport

__all__ = [
    "EmailMessage",
    "AnalysisReport",
    "ThreatLevel",
    "get_threat_level",
    "get_recommendations",
]
