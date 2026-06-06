"""
Security utilities for Email Phishing Detector
Provides cryptographic operations and secure data handling
"""

import hashlib
import hmac
from typing import Tuple, Optional
from src.config import HASH_ALGORITHM, HASH_BLOCK_SIZE
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CryptoUtils:
    """
    Cryptographic utilities using standard library
    Implements secure hashing for file integrity verification
    """

    @staticmethod
    def calculate_file_hash(
        file_path: str, algorithm: str = HASH_ALGORITHM
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Calculate cryptographic hash of a file
        Uses streaming to handle large files safely
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (default: sha256)
            
        Returns:
            Tuple of (success, hash_value, error_message)
        """
        try:
            hash_obj = hashlib.new(algorithm)

            # Read file in chunks to avoid memory issues
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(HASH_BLOCK_SIZE)
                    if not chunk:
                        break
                    hash_obj.update(chunk)

            return True, hash_obj.hexdigest(), None
        except FileNotFoundError:
            msg = f"File not found: {file_path}"
            logger.error(msg)
            return False, "", msg
        except IOError as e:
            msg = f"Error reading file: {str(e)}"
            logger.error(msg)
            return False, "", msg
        except Exception as e:
            msg = f"Unexpected error calculating hash: {str(e)}"
            logger.error(msg)
            return False, "", msg

    @staticmethod
    def calculate_string_hash(
        data: str, algorithm: str = HASH_ALGORITHM
    ) -> str:
        """
        Calculate hash of string data
        
        Args:
            data: String to hash
            algorithm: Hash algorithm
            
        Returns:
            Hex digest of hash
        """
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data.encode("utf-8"))
        return hash_obj.hexdigest()

    @staticmethod
    def verify_hash(
        data: bytes, expected_hash: str, algorithm: str = HASH_ALGORITHM
    ) -> bool:
        """
        Verify data against expected hash
        
        Args:
            data: Data to verify
            expected_hash: Expected hash value
            algorithm: Hash algorithm
            
        Returns:
            True if hash matches
        """
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data)
        return hmac.compare_digest(hash_obj.hexdigest(), expected_hash)

    @staticmethod
    def supported_algorithms() -> list:
        """
        Get list of supported hash algorithms
        
        Returns:
            List of algorithm names
        """
        return hashlib.algorithms_available


class DKIMVerifier:
    """
    DKIM signature verification
    Validates digital signatures on emails
    """

    @staticmethod
    def extract_dkim_signature(headers: dict) -> Optional[str]:
        """
        Extract DKIM-Signature header
        
        Args:
            headers: Email headers dict
            
        Returns:
            DKIM signature or None
        """
        for key, value in headers.items():
            if key.lower() == "dkim-signature":
                return value
        return None

    @staticmethod
    def parse_dkim_signature(signature: str) -> dict:
        """
        Parse DKIM signature into components
        Note: Simplified parsing for lab purposes
        
        Args:
            signature: DKIM signature string
            
        Returns:
            Dictionary of signature components
        """
        components = {}
        # Simple tag=value parsing
        for part in signature.split(";"):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                components[key.strip()] = value.strip()

        return components

    @staticmethod
    def validate_dkim_signature(signature: str) -> Tuple[bool, str]:
        """
        Validate DKIM signature structure
        
        Args:
            signature: DKIM signature string
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not signature:
            return False, "No DKIM signature found"

        components = DKIMVerifier.parse_dkim_signature(signature)

        # Check required components
        required = {"v", "a", "c", "d", "s", "h", "bh", "b"}
        if not required.issubset(set(components.keys())):
            return False, f"Missing required DKIM components: {required - set(components.keys())}"

        # Validate algorithm
        if components.get("a") not in ["rsa-sha256", "ed25519-sha256"]:
            return False, f"Unsupported DKIM algorithm: {components.get('a')}"

        return True, "DKIM signature structure is valid"


class SPFValidator:
    """
    SPF record validation and interpretation
    """

    VALID_MECHANISMS = {"ip4", "ip6", "a", "mx", "ptr", "exists", "redirect", "exp"}

    @staticmethod
    def parse_spf_record(spf_record: str) -> Tuple[bool, dict]:
        """
        Parse SPF record
        
        Args:
            spf_record: SPF record string
            
        Returns:
            Tuple of (is_valid, components)
        """
        if not spf_record.startswith("v=spf1"):
            return False, {}

        components = {"version": "spf1", "mechanisms": [], "qualifiers": {}}
        tokens = spf_record.split()

        for token in tokens[1:]:
            # Parse qualifier (+ - ~ ?)
            qualifier = "+"
            if token[0] in "+-~?":
                qualifier = token[0]
                mechanism = token[1:]
            else:
                mechanism = token

            # Extract mechanism type
            if "=" in mechanism:
                mech_type = mechanism.split("=")[0]
            else:
                mech_type = mechanism

            components["mechanisms"].append({"type": mech_type, "value": mechanism})
            components["qualifiers"][mechanism] = qualifier

        return True, components


class DataCleaner:
    """
    Secure data cleanup utilities
    Prevents sensitive information leakage
    """

    @staticmethod
    def clear_sensitive_data(data: bytearray) -> None:
        """
        Clear sensitive data from memory
        
        Args:
            data: Bytearray to clear
        """
        if data:
            for i in range(len(data)):
                data[i] = 0

    @staticmethod
    def sanitize_output(text: str, max_length: int = 1000) -> str:
        """
        Sanitize text for safe output
        Removes potential injection sequences
        
        Args:
            text: Text to sanitize
            max_length: Maximum output length
            
        Returns:
            Sanitized text
        """
        if not text:
            return ""

        # Remove ANSI escape codes
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        text = ansi_escape.sub("", text)

        # Limit length
        text = text[:max_length]

        return text


import re
