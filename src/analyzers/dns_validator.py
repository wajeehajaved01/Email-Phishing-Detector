"""
DNS validation utilities for email authentication
Provides DNS lookups for SPF, DKIM, and DMARC records
"""

import dns.resolver
import dns.exception
from typing import Optional, Tuple, List
from src.config import DNS_TIMEOUT_SECONDS, DNS_RETRY_ATTEMPTS
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DNSValidator:
    """
    DNS lookup utilities for email authentication verification
    Safely queries DNS records without executing anything
    """

    @staticmethod
    def lookup_spf_record(domain: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Lookup SPF record for domain via DNS
        
        Args:
            domain: Domain name to query
            
        Returns:
            Tuple of (found, record, error_message)
        """
        if not domain:
            return False, None, "Domain cannot be empty"

        try:
            answers = dns.resolver.resolve(
                domain, "TXT", lifetime=DNS_TIMEOUT_SECONDS
            )
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt = txt_string.decode("utf-8")
                    if txt.startswith("v=spf1"):
                        logger.info(f"SPF record found for {domain}")
                        return True, txt, None
            return False, None, "No SPF record found"
        except dns.resolver.NXDOMAIN:
            return False, None, f"Domain {domain} does not exist"
        except dns.resolver.NoAnswer:
            return False, None, f"No answer for TXT record query"
        except dns.exception.Timeout:
            return False, None, f"DNS lookup timeout for {domain}"
        except Exception as e:
            error_msg = f"DNS lookup error: {str(e)}"
            logger.warning(error_msg)
            return False, None, error_msg

    @staticmethod
    def lookup_dkim_record(
        domain: str, selector: str = "default"
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Lookup DKIM public key record
        
        Args:
            domain: Domain name
            selector: DKIM selector (default: "default")
            
        Returns:
            Tuple of (found, record, error_message)
        """
        if not domain or not selector:
            return False, None, "Domain and selector cannot be empty"

        dkim_query = f"{selector}._domainkey.{domain}"

        try:
            answers = dns.resolver.resolve(
                dkim_query, "TXT", lifetime=DNS_TIMEOUT_SECONDS
            )
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt = txt_string.decode("utf-8")
                    if "v=DKIM1" in txt:
                        logger.info(f"DKIM record found for {dkim_query}")
                        return True, txt, None
            return False, None, "No DKIM public key found"
        except dns.resolver.NXDOMAIN:
            return False, None, f"DKIM record {dkim_query} does not exist"
        except dns.resolver.NoAnswer:
            return False, None, "No answer for DKIM TXT query"
        except dns.exception.Timeout:
            return False, None, f"DNS lookup timeout for {dkim_query}"
        except Exception as e:
            error_msg = f"DKIM lookup error: {str(e)}"
            logger.warning(error_msg)
            return False, None, error_msg

    @staticmethod
    def lookup_dmarc_record(domain: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Lookup DMARC policy record
        
        Args:
            domain: Domain name
            
        Returns:
            Tuple of (found, record, error_message)
        """
        if not domain:
            return False, None, "Domain cannot be empty"

        dmarc_query = f"_dmarc.{domain}"

        try:
            answers = dns.resolver.resolve(
                dmarc_query, "TXT", lifetime=DNS_TIMEOUT_SECONDS
            )
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt = txt_string.decode("utf-8")
                    if txt.startswith("v=DMARC1"):
                        logger.info(f"DMARC record found for {domain}")
                        return True, txt, None
            return False, None, "No DMARC record found"
        except dns.resolver.NXDOMAIN:
            return False, None, f"DMARC record {dmarc_query} does not exist"
        except dns.resolver.NoAnswer:
            return False, None, "No answer for DMARC TXT query"
        except dns.exception.Timeout:
            return False, None, f"DNS lookup timeout for {dmarc_query}"
        except Exception as e:
            error_msg = f"DMARC lookup error: {str(e)}"
            logger.warning(error_msg)
            return False, None, error_msg

    @staticmethod
    def lookup_mx_records(domain: str) -> Tuple[bool, List[str], Optional[str]]:
        """
        Lookup MX records for domain
        
        Args:
            domain: Domain name
            
        Returns:
            Tuple of (found, mx_hosts, error_message)
        """
        if not domain:
            return False, [], "Domain cannot be empty"

        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=DNS_TIMEOUT_SECONDS)
            mx_hosts = [str(rdata.exchange).rstrip(".") for rdata in answers]
            logger.info(f"Found {len(mx_hosts)} MX records for {domain}")
            return True, mx_hosts, None
        except dns.resolver.NXDOMAIN:
            return False, [], f"Domain {domain} does not exist"
        except dns.resolver.NoAnswer:
            return False, [], "No MX records found"
        except dns.exception.Timeout:
            return False, [], f"DNS lookup timeout"
        except Exception as e:
            error_msg = f"MX lookup error: {str(e)}"
            logger.warning(error_msg)
            return False, [], error_msg

    @staticmethod
    def lookup_ptr_record(ip_address: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Lookup reverse DNS (PTR) record for IP address
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Tuple of (found, hostname, error_message)
        """
        if not ip_address:
            return False, None, "IP address cannot be empty"

        try:
            answers = dns.resolver.resolve(
                dns.reversename.from_address(ip_address), "PTR"
            )
            hostname = str(answers[0]).rstrip(".")
            logger.info(f"PTR record found for {ip_address}")
            return True, hostname, None
        except Exception as e:
            error_msg = f"PTR lookup error: {str(e)}"
            logger.debug(error_msg)
            return False, None, error_msg
