"""
Text Preprocessor and Normalizer for Security Analysis.

De-obfuscates text before rule matching:
- Base64 detection and recursive decoding
- Hex / URL / ASCII-escape decoding
- Unicode normalization and Homoglyph mapping (Cyrillic/Greek lookalikes -> Latin)
- Leetspeak normalization (1337 -> leet)
- Invisible / zero-width characters removal
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from typing import List, Tuple

# Common Homoglyphs mapping (Cyrillic, Greek, lookalike Unicode characters to Latin)
HOMOGLYPHS_MAP = {
    'а': 'a', 'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ѵ': 'v',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
    'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X',
    'Ү': 'Y', 'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ι': 'i',
    'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
}

# Leetspeak translation table
LEETSPEAK_MAP = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '5': 's',
    '$': 's',
    '7': 't',
    '+': 't',
    '8': 'b',
}

# Regex to detect potential Base64 chunks (min 16 chars, valid base64 alphabet)
BASE64_PATTERN = re.compile(r'\b[A-Za-z0-9+/]{16,}={0,2}\b')

# Zero-width / invisible characters regex
INVISIBLE_CHARS_PATTERN = re.compile(r'[\u200B-\u200D\uFEFF\u00A0\u2000-\u200A\u2028\u2029]')

# Arabic Diacritics (Tashkeel) and Tatweel (Kashida)
ARABIC_TASHKEEL_PATTERN = re.compile(r'[\u064B-\u065F\u0670]')
ARABIC_TATWEEL_PATTERN = re.compile(r'[\u0640]')


class TextNormalizer:
    """De-obfuscates and extracts hidden text payloads."""

    @classmethod
    def clean_invisible_chars(cls, text: str) -> str:
        """Strip zero-width and invisible formatting characters."""
        return INVISIBLE_CHARS_PATTERN.sub('', text)

    @classmethod
    def normalize_arabic(cls, text: str) -> str:
        """Remove Arabic Tatweel, Tashkeel, and normalize letter-spaced words."""
        # 1. Remove Tashkeel and Tatweel
        no_tashkeel = ARABIC_TASHKEEL_PATTERN.sub('', text)
        no_tatweel = ARABIC_TATWEEL_PATTERN.sub('', no_tashkeel)

        # 2. Normalize spaced Arabic letters e.g. "ت ج ا ه ل" -> "تجاهل"
        def collapse_spaced_arabic(match: re.Match) -> str:
            return match.group(0).replace(' ', '')

        collapsed = re.sub(r'[\u0621-\u064A](\s+[\u0621-\u064A]){2,}', collapse_spaced_arabic, no_tatweel)
        return collapsed

    @classmethod
    def normalize_unicode_and_homoglyphs(cls, text: str) -> str:
        """Convert Unicode lookalikes and homoglyphs to standard ASCII characters."""
        # 1. NFKD normalization
        norm = unicodedata.normalize('NFKD', text)
        # 2. Map known Cyrillic/Greek homoglyphs
        result = []
        for char in norm:
            result.append(HOMOGLYPHS_MAP.get(char, char))
        return "".join(result)

    @classmethod
    def normalize_leetspeak(cls, text: str) -> str:
        """Convert common leetspeak substitutions (e.g. 1gn0r3 -> ignore)."""
        # Only substitute inside alphanumeric tokens to prevent destroying math
        def replace_word(match: re.Match) -> str:
            word = match.group(0)
            # Only convert if the word has letters + numbers mixed
            has_alpha = any(c.isalpha() for c in word)
            has_digit = any(c.isdigit() or c in '@$+' for c in word)
            if has_alpha and has_digit:
                return "".join(LEETSPEAK_MAP.get(c, c) for c in word)
            return word

        return re.sub(r'[A-Za-z0-9@$+]{3,}', replace_word, text)

    @classmethod
    def extract_base64_payloads(cls, text: str) -> List[str]:
        """Find and decode Base64 encoded strings hidden in text."""
        decoded_payloads = []
        for match in BASE64_PATTERN.finditer(text):
            chunk = match.group(0)
            try:
                # Add padding if necessary
                padded = chunk + "=" * ((4 - len(chunk) % 4) % 4)
                decoded_bytes = base64.b64decode(padded, validate=True)
                # Check if decoded is valid readable UTF-8 text
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                # Must contain mostly printable characters
                if sum(c.isprintable() for c in decoded_str) / max(1, len(decoded_str)) > 0.85:
                    decoded_payloads.append(decoded_str)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
        return decoded_payloads

    @classmethod
    def extract_url_encoded_payloads(cls, text: str) -> List[str]:
        """Detect and decode URL-encoded text (%20, %2F, etc.)."""
        if '%' in text:
            try:
                unquoted = urllib.parse.unquote(text)
                if unquoted != text:
                    return [unquoted]
            except Exception:
                pass
        return []

    @classmethod
    def extract_variable_concatenations(cls, text: str) -> List[str]:
        """
        Detects payload splitting via variables:
        e.g. Let A = "Ignore all ", Let B = "previous instructions", Combine A and B
        """
        # Find variable assignments: (Let )?Var = "text" or 'text'
        var_assign_pattern = re.compile(r'(?:let\s+)?([A-Za-z0-9_]+)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        assignments = var_assign_pattern.findall(text)
        
        if len(assignments) >= 2:
            # Concatenate all assigned variable string values in order
            combined_all = "".join(val for _, val in assignments)
            joined_space = " ".join(val.strip() for _, val in assignments)
            return [combined_all, joined_space]
        return []

    @classmethod
    def get_all_normalized_variants(cls, raw_text: str) -> List[Tuple[str, str]]:
        """
        Produce multiple normalized representations of the input text.
        Returns a list of tuples: (variant_text, source_description)
        """
        variants: List[Tuple[str, str]] = []
        if not raw_text or not raw_text.strip():
            return variants

        # 1. Cleaned direct text
        cleaned = cls.clean_invisible_chars(raw_text)
        variants.append((cleaned, "direct_text"))

        # 2. Arabic Normalized (Tatweel, Tashkeel, Spacing stripped)
        ar_norm = cls.normalize_arabic(cleaned)
        if ar_norm != cleaned:
            variants.append((ar_norm, "arabic_normalized"))

        # 3. Unicode & Homoglyphs Normalized
        homoglyph_norm = cls.normalize_unicode_and_homoglyphs(ar_norm)
        if homoglyph_norm != ar_norm:
            variants.append((homoglyph_norm, "homoglyph_normalized"))

        # 4. Leetspeak Normalized (aggressive)
        leet_norm = cls.normalize_leetspeak(homoglyph_norm)
        if leet_norm != homoglyph_norm:
            variants.append((leet_norm, "leetspeak_normalized"))

        # Full character-by-character leet mapping variant
        full_leet = "".join(LEETSPEAK_MAP.get(c.lower(), c) for c in homoglyph_norm)
        if full_leet != leet_norm and full_leet != homoglyph_norm:
            variants.append((full_leet, "full_leetspeak_normalized"))

        # 4. Decoded Base64 payloads
        for b64_decoded in cls.extract_base64_payloads(cleaned):
            variants.append((b64_decoded, "base64_decoded_payload"))
            b64_norm = cls.normalize_unicode_and_homoglyphs(b64_decoded)
            if b64_norm != b64_decoded:
                variants.append((b64_norm, "base64_homoglyph_normalized"))
            b64_leet = cls.normalize_leetspeak(b64_norm)
            if b64_leet != b64_norm:
                variants.append((b64_leet, "base64_leetspeak_normalized"))

        # 5. Variable concatenation reconstruction (Token Smuggling)
        for var_combined in cls.extract_variable_concatenations(cleaned):
            variants.append((var_combined, "variable_concatenation_payload"))
            var_norm = cls.normalize_unicode_and_homoglyphs(var_combined)
            if var_norm != var_combined:
                variants.append((var_norm, "var_homoglyph_normalized"))

        # 6. URL-decoded payloads
        for url_decoded in cls.extract_url_encoded_payloads(cleaned):
            variants.append((url_decoded, "url_decoded_payload"))

        return variants
