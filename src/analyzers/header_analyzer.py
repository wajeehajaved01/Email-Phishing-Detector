"""
Email header analyzer module
Verifies SPF, DKIM, and DMARC authentication
Detects header injection and spoofing attempts
"""

from typing import Optional, Tuple
from email.utils import parseaddr
from src.models.email_model import EmailMessage, SPFResult, DKIMResult, DMARCResult, AuthenticationResult
from src.models.analysis_report import AnalysisReport
from src.analyzers.dns_validator import DNSValidator
from src.utils.security import SPFValidator, DKIMVerifier
from src.config import (
    RED_FLAGS,
    LEGITIMATE_INDICATORS,
    CRITICAL_HEADERS,
    AUTHENTICATION_HEADERS,
    SPOOFING_INDICATORS,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class HeaderAnalyzer:
    """
    Analyzes email headers for authentication and security
    Performs SPF, DKIM, DMARC verification via DNS lookups
    """

    def __init__(self):
        """Initialize header analyzer"""
        self.dns_validator = DNSValidator()
        self.threat_score = 0.0

    def analyze(self, email: EmailMessage) -> dict:
        """
        Perform complete header analysis
        
        Args:
            email: EmailMessage object
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting header analysis for email: {email.subject[:50]}")
        self.threat_score = 0.0

        # Extract domain from sender
        sender_domain = self._extract_domain(email.sender)
        if not sender_domain:
            logger.warning(f"Could not extract domain from sender: {email.sender}")
            return {"error": "Invalid sender address"}

        # Perform authentication checks
        spf_result = self._verify_spf(sender_domain)
        dkim_result = self._verify_dkim(sender_domain, email.headers)
        dmarc_result = self._verify_dmarc(sender_domain, spf_result, dkim_result)

        # Check for header anomalies
        header_issues = self._check_header_anomalies(email.headers, sender_domain)

        # Check for spoofing indicators
        spoofing_risks = self._check_spoofing_indicators(email.headers, sender_domain)

        # Compile results
        result = {
            "spf": self._result_to_dict(spf_result),
            "dkim": self._result_to_dict(dkim_result),
            "dmarc": self._result_to_dict(dmarc_result),
            "sender_domain": sender_domain,
            "header_issues": header_issues,
            "spoofing_risks": spoofing_risks,
            "threat_score": self.threat_score,
        }

        logger.info(f"Header analysis complete. Threat score: {self.threat_score}")
        return result

    def _extract_domain(self, email_address: str) -> Optional[str]:
        """
        Extract domain from email address
        
        Args:
            email_address: Email address string
            
        Returns:
            Domain name or None
        """
        if not email_address:
            return None

        _, address = parseaddr(email_address)
        if "@" in address:
            return address.split("@")[1].lower()
        return None

    def _verify_spf(self, domain: str) -> SPFResult:
        """
        Verify SPF record for domain
        
        Args:
            domain: Domain to verify
            
        Returns:
            SPFResult object
        """
        logger.debug(f"Verifying SPF for domain: {domain}")
        result = SPFResult(
            result=AuthenticationResult.UNKNOWN,
            domain=domain,
        )

        # Lookup SPF record
        found, record, error = self.dns_validator.lookup_spf_record(domain)

        if not found:
            result.result = AuthenticationResult.FAIL
            result.error = error
            result.explanation = "No SPF record found for domain"
            self.threat_score += RED_FLAGS.get("spf_fail", 30)
            logger.warning(f"SPF verification failed: {error}")
            return result

        result.record = record
        result.explanation = "SPF record found and valid"
        result.result = AuthenticationResult.PASS
        self.threat_score += LEGITIMATE_INDICATORS.get("spf_pass", 20) * -1  # Subtract
        logger.info(f"SPF verification passed for {domain}")

        # Parse SPF mechanisms (simplified)
        is_valid, mechanisms = SPFValidator.parse_spf_record(record)
        if is_valid:
            result.mechanisms = mechanisms.get("mechanisms", [])

        return result

    def _verify_dkim(self, domain: str, headers: dict) -> DKIMResult:
        """
        Verify DKIM signature
        
        Args:
            domain: Domain to verify
            headers: Email headers dict
            
        Returns:
            DKIMResult object
        """
        logger.debug(f"Verifying DKIM for domain: {domain}")
        result = DKIMResult(
            result=AuthenticationResult.UNKNOWN,
            domain=domain,
        )

        # Extract DKIM signature from headers
        dkim_sig = None
        for key, value in headers.items():
            if key.lower() == "dkim-signature":
                dkim_sig = value
                break

        if not dkim_sig:
            result.result = AuthenticationResult.FAIL
            result.error = "No DKIM signature found in headers"
            result.explanation = "Email not signed with DKIM"
            self.threat_score += RED_FLAGS.get("dkim_fail", 25)
            logger.warning("No DKIM signature found")
            return result

        result.signature = dkim_sig

        # Validate DKIM signature structure
        is_valid, message = DKIMVerifier.validate_dkim_signature(dkim_sig)
        result.is_valid_structure = is_valid
        result.explanation = message

        if not is_valid:
            result.result = AuthenticationResult.FAIL
            self.threat_score += RED_FLAGS.get("dkim_fail", 25)
            logger.warning(f"DKIM validation failed: {message}")
        else:
            result.result = AuthenticationResult.PASS
            self.threat_score += LEGITIMATE_INDICATORS.get("dkim_pass", 20) * -1
            logger.info("DKIM signature valid")

        return result

    def _verify_dmarc(self, domain: str, spf_result: SPFResult, dkim_result: DKIMResult) -> DMARCResult:
        """
        Verify DMARC policy
        
        Args:
            domain: Domain to verify
            spf_result: SPF verification result
            dkim_result: DKIM verification result
            
        Returns:
            DMARCResult object
        """
        logger.debug(f"Verifying DMARC for domain: {domain}")
        result = DMARCResult(
            result=AuthenticationResult.UNKNOWN,
            domain=domain,
        )

        # Lookup DMARC record
        found, record, error = self.dns_validator.lookup_dmarc_record(domain)

        if not found:
            result.result = AuthenticationResult.NEUTRAL
            result.error = error
            result.explanation = "No DMARC policy found"
            logger.info(f"No DMARC record found: {error}")
            return result

        result.record = record

        # Parse policy
        if "p=reject" in record:
            result.policy = "reject"
        elif "p=quarantine" in record:
            result.policy = "quarantine"
        elif "p=none" in record:
            result.policy = "none"

        # Check alignment
        result.alignment_spf = spf_result.result == AuthenticationResult.PASS
        result.alignment_dkim = dkim_result.result == AuthenticationResult.PASS

        if result.alignment_spf or result.alignment_dkim:
            result.result = AuthenticationResult.PASS
            result.explanation = "DMARC policy aligned"
            self.threat_score += LEGITIMATE_INDICATORS.get("dmarc_pass", 20) * -1
            logger.info("DMARC alignment verified")
        else:
            result.result = AuthenticationResult.FAIL
            result.explanation = "DMARC alignment failed"
            self.threat_score += RED_FLAGS.get("dmarc_fail", 35)
            logger.warning("DMARC alignment failed")

        return result

    def _check_header_anomalies(self, headers: dict, sender_domain: str) -> list:
        """
        Check for suspicious header patterns
        
        Args:
            headers: Email headers
            sender_domain: Sender domain
            
        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Check for critical headers
        for header in CRITICAL_HEADERS:
            if header not in [h for h in headers.keys()]:
                anomalies.append(f"Missing critical header: {header}")
                self.threat_score += 5

        # Check for multiple From headers
        from_count = sum(1 for h in headers if h.lower() == "from")
        if from_count > 1:
            anomalies.append(f"Multiple From headers detected ({from_count})")
            self.threat_score += RED_FLAGS.get("header_injection", 40)

        logger.debug(f"Found {len(anomalies)} header anomalies")
        return anomalies

    def _check_spoofing_indicators(self, headers: dict, sender_domain: str) -> list:
        """
        Check for email spoofing indicators
        
        Args:
            headers: Email headers
            sender_domain: Sender domain
            
        Returns:
            List of spoofing risks
        """
        risks = []

        # Check Reply-To matches From domain
        reply_to = headers.get("Reply-To", "")
        if reply_to:
            reply_domain = self._extract_domain(reply_to)
            if reply_domain and reply_domain != sender_domain:
                risks.append(
                    f"Reply-To domain ({reply_domain}) differs from sender domain ({sender_domain})"
                )
                self.threat_score += 10

        # Check Return-Path
        return_path = headers.get("Return-Path", "")
        if return_path:
            return_domain = self._extract_domain(return_path)
            if return_domain and return_domain != sender_domain:
                risks.append(
                    f"Return-Path domain ({return_domain}) differs from sender domain"
                )
                self.threat_score += 15

        logger.debug(f"Found {len(risks)} spoofing indicators")
        return risks

    @staticmethod
    def _result_to_dict(result) -> dict:
        """
        Convert result object to dictionary
        
        Args:
            result: Result object (SPF/DKIM/DMARC)
            
        Returns:
            Dictionary representation
        """
        return {
            "result": result.result.value if hasattr(result.result, "value") else str(result.result),
            "domain": result.domain,
            "explanation": getattr(result, "explanation", ""),
            "error": getattr(result, "error"),
        }
