from __future__ import annotations

import re
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class SafetyDetector:
    """
    Detects safety-related risks in text, including hate speech, violence,
    illegal activities, cyber abuse, and social engineering.
    
    Specifically ignores simple insults or toxicity that do not pose a direct
    safety threat. Returns independent scores for different safety categories.
    """
    
    # Hate Speech & Discrimination
    # Focuses on group-based discrimination, dehumanization, and calls for persecution.
    HATE_SPEECH_PATTERN = re.compile(
        r'(?i)\b(?:inferior|subhuman|discriminate\s+against|should\s+be\s+(?:eliminated|exterminated?))\b'
        r'|\b(?:أقل\s+قيمة|اضطهاد|إبادة|تمييز\s+ضد)\b'
    )
    HATE_SPEECH_CONTEXT = re.compile(
        r'(?i)\b(?:race|religion|gender|ethnic(?:ity)?|muslims?|christians?|jews?|black|white|arab|asian|women|men)\b'
        r'|\b(?:دين|عرق|جنس|مسلمين|مسيحيين|يهود|عرب|نساء|رجال)\b'
    )

    # Violence & Threats
    # Focuses on physical harm and direct threats.
    VIOLENCE_PATTERN = re.compile(
        r'(?i)\b(?:how\s+to\s+(?:hurt|harm|kill|assassinate)|threaten(?:ing)?\s+to\s+kill|I\s+will\s+kill)\b'
        r'|\b(?:كيف\s+(?:أؤذي|أقتل|أغتال)|سأقتلك|تهديد\s+بالقتل)\b'
    )
    VIOLENCE_CONTEXT = re.compile(
        r'(?i)\b(?:someone|person|him|her|them|without\s+being\s+caught|get\s+away\s+with\s+it)\b'
        r'|\b(?:شخص|أحد|دون\s+أن\s+يتم\s+القبض|أفلت\s+منه)\b'
    )

    # Illegal Activities
    # Focuses on forgery, drugs, weapons, fraud.
    ILLEGAL_PATTERN = re.compile(
        r'(?i)\b(?:fake\s+(?:documents?|passports?|ID)|forged?\s+(?:documents?|passports?|money)|counterfeit\s+money|how\s+to\s+make\s+(?:drugs?|meth|cocaine|weapons?|bombs?|guns?|explosives?))\b'
        r'|\b(?:وثائق\s+مزورة|جوازات\s+(?:مزورة|غير\s+قانونية)|أموال\s+مزيفة|صناعة\s+(?:مخدرات|أسلحة|متفجرات|قنبلة))\b'
    )

    # Cyber Abuse / Malware
    # Focuses on malware, exploits, password stealing.
    CYBER_ABUSE_PATTERN = re.compile(
        r'(?i)\b(?:write\s+(?:malware|ransomware|virus|trojan)|steal\s+(?:passwords?|credentials?)|exploit\s+(?:script|code|vulnerability))\b'
        r'|\b(?:برنامج\s+خبيث|فيروس|برمجيات\s+فدية|يسرق\s+كلمات\s+المرور|استغلال\s+ثغرة)\b'
    )

    # Social Engineering
    # Focuses on impersonation, authority spoofing, urgency manipulation.
    SOCIAL_ENG_PATTERN = re.compile(
        r'(?i)\b(?:pretend\s+(?:to\s+be|you\s+are)\s+(?:my\s+)?(?:manager|admin|boss|ceo)|impersonate\s+(?:my\s+)?(?:manager|admin|boss)|approve\s+this\s+(?:transfer|payment)\s+(?:immediately|now))\b'
        r'|\b(?:تظاهر\s+أنك\s+(?:مديري|المسؤول|المدير)|انتحل\s+شخصية|وافق\s+على\s+هذا\s+(?:التحويل|الدفع)\s+فورا)\b'
    )

    def evaluate(self, text: str) -> Dict[str, float]:
        """
        Evaluates the text for safety risks across multiple categories.

        Args:
            text (str): The input text to evaluate.

        Returns:
            Dict[str, float]: A dictionary mapping category names to scores
                              (between 0.0 and 1.0). Only includes categories
                              where the score is greater than 0.
        """
        scores: Dict[str, float] = {}
        
        # 1. Hate Speech & Discrimination
        hate_matches = self.HATE_SPEECH_PATTERN.findall(text)
        if hate_matches:
            # Requires context (targeting a group) to be considered high confidence
            context_matches = self.HATE_SPEECH_CONTEXT.findall(text)
            if context_matches:
                scores['safety_hate_speech'] = 0.95
            else:
                # Lower score if group context is missing, might just be edgy text
                scores['safety_hate_speech'] = 0.50

        # 2. Violence & Threats
        violence_matches = self.VIOLENCE_PATTERN.findall(text)
        if violence_matches:
            context_matches = self.VIOLENCE_CONTEXT.findall(text)
            if context_matches:
                scores['safety_violence'] = 0.95
            else:
                scores['safety_violence'] = 0.85

        # 3. Illegal Activities
        illegal_matches = self.ILLEGAL_PATTERN.findall(text)
        if illegal_matches:
            scores['safety_illegal'] = 0.95

        # 4. Cyber Abuse / Malware
        cyber_matches = self.CYBER_ABUSE_PATTERN.findall(text)
        if cyber_matches:
            scores['safety_cyber_abuse'] = 0.95

        # 5. Social Engineering
        social_eng_matches = self.SOCIAL_ENG_PATTERN.findall(text)
        if social_eng_matches:
            scores['safety_social_engineering'] = 0.95

        # Filter out 0 scores (redundant with the dictionary construction, but ensuring compliance)
        final_scores = {k: v for k, v in scores.items() if v > 0.0}
        
        if final_scores:
            logger.debug(f"Safety risks detected: {final_scores}")
            
        return final_scores
