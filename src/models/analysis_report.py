"""
Analysis report generation and formatting
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum
from src.config import ThreatLevel, RECOMMENDATIONS


class ReportFormat(Enum):
    """Output report formats"""
    CONSOLE = "console"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


@dataclass
class AnalysisReport:
    """
    Comprehensive analysis report
    Aggregates all analysis results
    """
    email_subject: str
    sender: str
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Analysis results
    header_analysis: Dict = field(default_factory=dict)
    body_analysis: Dict = field(default_factory=dict)
    attachment_analysis: Dict = field(default_factory=dict)
    
    # Aggregated scores
    overall_threat_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.SAFE
    
    # Detailed findings
    threat_indicators: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_duration_ms: int = 0
    modules_executed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def add_threat_indicator(self, indicator: str) -> None:
        """Add a threat indicator to the report"""
        if indicator not in self.threat_indicators:
            self.threat_indicators.append(indicator)
    
    def add_security_issue(self, issue: str) -> None:
        """Add a security issue to the report"""
        if issue not in self.security_issues:
            self.security_issues.append(issue)
    
    def add_error(self, error: str) -> None:
        """Add an error to the report"""
        if error not in self.errors:
            self.errors.append(error)
    
    def set_threat_level(self, score: float) -> None:
        """
        Set threat level based on score
        
        Args:
            score: Threat score (0-100)
        """
        self.overall_threat_score = min(100, max(0, score))
        
        if score < 20:
            self.threat_level = ThreatLevel.SAFE
        elif score < 40:
            self.threat_level = ThreatLevel.LOW
        elif score < 60:
            self.threat_level = ThreatLevel.MEDIUM
        elif score < 80:
            self.threat_level = ThreatLevel.HIGH
        else:
            self.threat_level = ThreatLevel.CRITICAL
        
        # Auto-generate recommendations
        self.recommendations = RECOMMENDATIONS.get(
            self.threat_level.value, []
        )
    
    def to_dict(self) -> Dict:
        """
        Convert report to dictionary (for JSON export)
        
        Returns:
            Dictionary representation of report
        """
        return {
            "email": {
                "subject": self.email_subject,
                "sender": self.sender,
            },
            "analysis": {
                "timestamp": self.analysis_timestamp.isoformat(),
                "duration_ms": self.analysis_duration_ms,
                "modules_executed": self.modules_executed,
            },
            "threat_assessment": {
                "overall_score": self.overall_threat_score,
                "threat_level": self.threat_level.value,
                "indicators": self.threat_indicators,
                "issues": self.security_issues,
            },
            "detailed_analysis": {
                "headers": self.header_analysis,
                "body": self.body_analysis,
                "attachments": self.attachment_analysis,
            },
            "recommendations": self.recommendations,
            "errors": self.errors,
        }
    
    def to_console_string(self) -> str:
        """
        Format report for console output
        
        Returns:
            Formatted string for console display
        """
        lines = []
        lines.append("\n" + "="*70)
        lines.append("EMAIL PHISHING DETECTOR - ANALYSIS REPORT")
        lines.append("="*70)
        
        # Email info
        lines.append(f"\nEMAIL INFORMATION:")
        lines.append(f"  Subject: {self.email_subject}")
        lines.append(f"  From: {self.sender}")
        lines.append(f"  Analysis Time: {self.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Threat assessment
        lines.append(f"\nTHREAT ASSESSMENT:")
        lines.append(f"  Overall Score: {self.overall_threat_score:.1f}/100")
        lines.append(f"  Threat Level: {self.threat_level.value}")
        
        # Indicators
        if self.threat_indicators:
            lines.append(f"\nTHREAT INDICATORS:")
            for indicator in self.threat_indicators:
                lines.append(f"  ⚠ {indicator}")
        
        # Security issues
        if self.security_issues:
            lines.append(f"\nSECURITY ISSUES:")
            for issue in self.security_issues:
                lines.append(f"  ✗ {issue}")
        
        # Recommendations
        if self.recommendations:
            lines.append(f"\nRECOMMENDATIONS:")
            for rec in self.recommendations:
                lines.append(f"  → {rec}")
        
        # Errors
        if self.errors:
            lines.append(f"\nERRORS/WARNINGS:")
            for error in self.errors:
                lines.append(f"  ⚠ {error}")
        
        lines.append("\n" + "="*70)
        
        return "\n".join(lines)
