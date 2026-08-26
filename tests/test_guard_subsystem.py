"""
Unit Tests for Phase 1 Guard Subsystem: Contracts, Parser, Client, Fail-Closed.
"""

import pytest
from classifier.guard_models import GuardEvidence, GuardMode, GuardVerdict
from classifier.guard_parser import GuardOutputParser
from classifier.guard_client import GuardServiceClient


def test_guard_parser_safe():
    parser = GuardOutputParser()
    verdict, raw_cats, canonical_cats = parser.parse("safe")
    assert verdict == GuardVerdict.SAFE
    assert raw_cats == []
    assert canonical_cats == []


def test_guard_parser_unsafe_single_category():
    parser = GuardOutputParser()
    verdict, raw_cats, canonical_cats = parser.parse("unsafe\nS2")
    assert verdict == GuardVerdict.UNSAFE
    assert raw_cats == ["S2"]
    assert canonical_cats == ["non_violent_crimes"]


def test_guard_parser_unsafe_multiple_categories():
    parser = GuardOutputParser()
    verdict, raw_cats, canonical_cats = parser.parse("unsafe\nS1, S9, S11")
    assert verdict == GuardVerdict.UNSAFE
    assert set(raw_cats) == {"S1", "S9", "S11"}
    assert set(canonical_cats) == {"violent_crimes", "indiscriminate_weapons", "suicide_self_harm"}


def test_guard_parser_malformed_empty():
    parser = GuardOutputParser()
    verdict, raw_cats, canonical_cats = parser.parse("")
    assert verdict == GuardVerdict.ERROR


def test_guard_parser_malformed_unrecognized():
    parser = GuardOutputParser()
    verdict, raw_cats, canonical_cats = parser.parse("I cannot answer this question.")
    assert verdict == GuardVerdict.ERROR


@pytest.mark.asyncio
async def test_guard_client_fail_closed_on_unreachable_service():
    client = GuardServiceClient(service_url="http://127.0.0.1:59999", timeout=0.2)
    evidence = await client.evaluate("Test prompt for fail closed")
    
    assert evidence.verdict == GuardVerdict.UNAVAILABLE
    assert evidence.status == "service_unavailable"
    assert not evidence.is_unsafe
    assert not evidence.is_available
    await client.close()
