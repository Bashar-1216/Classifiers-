"""
Text Preprocessor and Normalizer for Security Analysis.

De-obfuscates text before rule matching:
- Base64 detection and recursive decoding
- Hex / URL / ASCII-escape decoding
- Unicode normalization and Homoglyph mapping (Cyrillic/Greek lookalikes -> Latin)
- Leetspeak normalization (1337 -> leet)
- Invisible / zero-width characters removal
- Character spacing de-obfuscation (English & Arabic)
- Arabic character elongation & orthographic normalization
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse

# Common Homoglyphs mapping (Cyrillic, Greek, lookalike Unicode characters to Latin)
# Common Homoglyphs mapping (Cyrillic, Greek, Armenian lookalike Unicode characters to Latin)
HOMOGLYPHS_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ѵ': 'v',
    'һ': 'h', 'ո': 'n', 'г': 'r', 'ս': 'u', 'ո': 'n', 'տ': 't',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
    'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X',
    'Ү': 'Y', 'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ι': 'i',
    'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
    'ɡ': 'g',
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
        """Remove Arabic Tatweel, Tashkeel, character elongation, and normalize letter-spaced words."""
        # 1. Remove Tashkeel and Tatweel
        no_tashkeel = ARABIC_TASHKEEL_PATTERN.sub('', text)
        no_tatweel = ARABIC_TATWEEL_PATTERN.sub('', no_tashkeel)

        # 2. Collapse elongated repeated characters (e.g. هكّرررر -> هكر)
        no_elongation = re.sub(r'([\u0621-\u064A])\1{2,}', r'\1', no_tatweel)

        # 3. Orthographic normalization (alef variants, taa marboota, yaa)
        norm_alef = re.sub(r'[أإآ]', 'ا', no_elongation)
        norm_letters = re.sub(r'[ة]', 'ه', norm_alef)
        norm_letters = re.sub(r'[ى]', 'ي', norm_letters)

        # 4. Normalize spaced Arabic letters e.g. "ت ج ا ه ل" -> "تجاهل"
        def collapse_spaced_arabic(match: re.Match) -> str:
            return match.group(0).replace(' ', '')

        collapsed = re.sub(r'[\u0621-\u064A](\s+[\u0621-\u064A]){2,}', collapse_spaced_arabic, norm_letters)
        return collapsed

    @classmethod
    def normalize_spaced_english(cls, text: str) -> str:
        """Collapse spaced English letters e.g. 's y s t e m   p r o m p t' -> 'system   prompt'."""
        parts = re.split(r'(\s{2,}|\n|[.,;:!?])', text)
        out = []
        for p in parts:
            trimmed = p.strip()
            if re.match(r'^[a-zA-Z]( [a-zA-Z])+$', trimmed):
                out.append(p.replace(' ', ''))
            else:
                out.append(p)
        return "".join(out)

    @classmethod
    def normalize_punctuated_words(cls, text: str) -> str:
        """Collapse internal punctuation/hyphens inside words e.g. 's-y-s-t-e-m' -> 'system', 'sys.tem' -> 'system'."""
        parts = re.split(r'(\s+|\n)', text)
        out = []
        for p in parts:
            trimmed = p.strip()
            # If word is composed of single letters separated by hyphens or dots (e.g. s-y-s-t-e-m)
            if re.match(r'^[a-zA-Z]([-._][a-zA-Z])+$', trimmed):
                out.append(re.sub(r'[-._]', '', p))
            elif re.match(r'^[a-zA-Z]{2,}[-._][a-zA-Z]{2,}$', trimmed):
                out.append(re.sub(r'[-._]', '', p))
            else:
                out.append(p)
        return "".join(out)

    @classmethod
    def normalize_unicode_and_homoglyphs(cls, text: str) -> str:
        """Convert Unicode lookalikes and homoglyphs to standard ASCII characters."""
        norm = unicodedata.normalize('NFKD', text)
        result = []
        for char in norm:
            result.append(HOMOGLYPHS_MAP.get(char, char))
        return "".join(result)

    @classmethod
    def normalize_leetspeak(cls, text: str) -> str:
        """Convert common leetspeak substitutions (e.g. 1gn0r3 -> ignore)."""
        def replace_word(match: re.Match) -> str:
            word = match.group(0)
            has_alpha = any(c.isalpha() for c in word)
            has_digit = any(c.isdigit() or c in '@$+' for c in word)
            if has_alpha and has_digit:
                return "".join(LEETSPEAK_MAP.get(c, c) for c in word)
            return word

        return re.sub(r'[A-Za-z0-9@$+]{3,}', replace_word, text)

    @classmethod
    def extract_base64_payloads(cls, text: str) -> list[str]:
        """Find and decode Base64 encoded strings hidden in text."""
        decoded_payloads = []
        for match in BASE64_PATTERN.finditer(text):
            chunk = match.group(0)
            try:
                padded = chunk + "=" * ((4 - len(chunk) % 4) % 4)
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                if sum(c.isprintable() for c in decoded_str) / max(1, len(decoded_str)) > 0.85:
                    decoded_payloads.append(decoded_str)
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
        return decoded_payloads

    @classmethod
    def extract_url_encoded_payloads(cls, text: str) -> list[str]:
        """Decode URL encoded strings (%20, %3C, etc.)."""
        if '%' in text:
            try:
                unquoted = urllib.parse.unquote(text)
                if unquoted != text:
                    return [unquoted]
            except Exception:
                pass
        return []

    @classmethod
    def extract_variable_concatenations(cls, text: str) -> list[str]:
        """Detect and reconstruct token-splitting via variable assignments."""
        var_assign_pattern = re.compile(r'(?:let\s+)?([A-Za-z0-9_]+)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        assignments = var_assign_pattern.findall(text)
        
        if len(assignments) >= 2:
            combined_all = "".join(val for _, val in assignments)
            joined_space = " ".join(val.strip() for _, val in assignments)
            return [combined_all, joined_space]
        return []

    @classmethod
    def get_all_normalized_variants(cls, raw_text: str) -> list[tuple[str, str]]:
        """
        Produce multiple normalized representations of the input text.
        Returns a list of tuples: (variant_text, source_description)
        """
        variants: list[tuple[str, str]] = []
        if not raw_text or not raw_text.strip():
            return variants

        # 1. Cleaned direct text
        cleaned = cls.clean_invisible_chars(raw_text)
        variants.append((cleaned, "direct_text"))

        # 2. Spaced English Normalized
        spaced_en = cls.normalize_spaced_english(cleaned)
        if spaced_en != cleaned:
            variants.append((spaced_en, "spaced_english_normalized"))

        # 3. Punctuated / Hyphenated words Normalized e.g. s-y-s-t-e-m -> system, sys.tem -> system
        punc_norm = cls.normalize_punctuated_words(cleaned)
        if punc_norm != cleaned:
            variants.append((punc_norm, "punctuated_words_normalized"))

        # 4. Arabic Normalized (Tatweel, Tashkeel, Elongation, Spacing stripped)
        ar_norm = cls.normalize_arabic(spaced_en)
        if ar_norm != spaced_en:
            variants.append((ar_norm, "arabic_normalized"))

        # 4. Unicode & Homoglyphs Normalized
        homoglyph_norm = cls.normalize_unicode_and_homoglyphs(ar_norm)
        if homoglyph_norm != ar_norm:
            variants.append((homoglyph_norm, "homoglyph_normalized"))

        # 5. Leetspeak Normalized
        leet_norm = cls.normalize_leetspeak(homoglyph_norm)
        if leet_norm != homoglyph_norm:
            variants.append((leet_norm, "leetspeak_normalized"))

        # Full character-by-character leet mapping variant
        full_leet = "".join(LEETSPEAK_MAP.get(c.lower(), c) for c in homoglyph_norm)
        if full_leet != leet_norm and full_leet != homoglyph_norm:
            variants.append((full_leet, "full_leetspeak_normalized"))

        # 6. Decoded Base64 payloads
        for b64_decoded in cls.extract_base64_payloads(cleaned):
            variants.append((b64_decoded, "base64_decoded_payload"))
            b64_norm = cls.normalize_unicode_and_homoglyphs(b64_decoded)
            if b64_norm != b64_decoded:
                variants.append((b64_norm, "base64_homoglyph_normalized"))
            b64_leet = cls.normalize_leetspeak(b64_norm)
            if b64_leet != b64_norm:
                variants.append((b64_leet, "base64_leetspeak_normalized"))

        # 7. Variable concatenation reconstruction (Token Smuggling)
        for var_combined in cls.extract_variable_concatenations(cleaned):
            variants.append((var_combined, "variable_concatenation_payload"))
            var_norm = cls.normalize_unicode_and_homoglyphs(var_combined)
            if var_norm != var_combined:
                variants.append((var_norm, "var_homoglyph_normalized"))

        # 8. URL-decoded payloads
        for url_decoded in cls.extract_url_encoded_payloads(cleaned):
            variants.append((url_decoded, "url_decoded_payload"))

        return variants

    @classmethod
    def extract_script_profile(cls, text: str) -> dict[str, Any]:
        """
        Extract descriptive script and linguistic context metadata.
        IMPORTANT: This is observational context metadata, NEVER an autonomous risk signal.
        """
        has_arabic = bool(re.search(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]', text))
        has_latin = bool(re.search(r'[a-zA-Z]', text))
        mixed_script = has_arabic and has_latin

        # Check for Arabizi character/numeral substitution patterns in Latin tokens
        arabizi_tokens = re.findall(r'\b[a-zA-Z]*[2356789][a-zA-Z]+\b|\b[a-zA-Z]+[2356789][a-zA-Z0-9]*\b', text)
        arabizi_likelihood = min(1.0, len(arabizi_tokens) * 0.35) if arabizi_tokens else 0.0

        detected_scripts = []
        if has_arabic:
            detected_scripts.append("arabic")
        if has_latin:
            detected_scripts.append("latin")

        obfuscation_types = []
        if INVISIBLE_CHARS_PATTERN.search(text):
            obfuscation_types.append("zero_width_chars")
        if BASE64_PATTERN.search(text):
            obfuscation_types.append("base64_candidate")
        if any(c in HOMOGLYPHS_MAP for c in text):
            obfuscation_types.append("unicode_homoglyphs")

        return {
            "arabic_script": has_arabic,
            "latin_script": has_latin,
            "mixed_script": mixed_script,
            "arabizi_likelihood": round(arabizi_likelihood, 2),
            "detected_scripts": detected_scripts,
            "obfuscation_types": obfuscation_types,
        }

