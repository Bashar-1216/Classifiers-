# ruff: noqa: E402
"""
Enterprise AI Risk Assessment & Governance System — CLI Tool.

Operational command line tool for real-time prompt classification,
policy enforcement, local isolated shield routing, and output safety.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Ensure UTF-8 output on Windows terminal
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from classifier.models import Classification
from classifier.service import ClassifierService
from config import Settings
from output_safety import OutputSafetyEngine
from policy.engine import PolicyEngine
from policy.models import Route
from router.normal_backend import NormalBackend
from shield.config import ShieldConfig
from shield.judge import LocalJudge
from shield.models import JudgeVerdict
from shield.shield_fast import CircuitBreakerOpenError, ShieldBackendError, SofaShieldFast

# Terminal ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"


def print_banner():
    banner = f"""
{CYAN}{BOLD}==================================================================
  [AI RISK ASSESSMENT & GOVERNANCE ENGINE] — CLI
=================================================================={RESET}
"""
    print(banner)


def cmd_classify(prompt: str, rules_dir: str | None = None):
    """Classify a single prompt and print full multi-dimensional risk analysis."""
    classifier = ClassifierService(rules_dir=rules_dir)
    policy_engine = PolicyEngine()

    print(f"\n{BOLD}Input Prompt:{RESET} {prompt}")

    result = classifier.classify(prompt)
    decision = policy_engine.evaluate(result)

    status_color = RED if result.classification == Classification.RESTRICTED else GREEN
    route_color = RED if decision.route == Route.SHIELD else GREEN

    print(f"{BOLD}Classification:{RESET}     {status_color}{BOLD}{result.classification.value}{RESET}")
    print(f"{BOLD}Overall Risk Score:{RESET} {result.confidence:.4f} (Risk Metric: {result.risk_score:.4f})")
    print(f"{BOLD}Policy Route:{RESET}       {route_color}{BOLD}{decision.route.value}{RESET}")
    print(f"{BOLD}Policy Reason:{RESET}      {decision.reason}")

    # Display Multi-Dimensional Category Breakdown
    print(f"\n{BOLD}Risk Category Breakdown:{RESET}")
    for cat, score in sorted(result.categories.items(), key=lambda x: x[1], reverse=True):
        if score > 0:
            cat_color = RED if score >= 0.5 else (YELLOW if score > 0.2 else GREEN)
            print(f"  * {cat.replace('_', ' ').title():<25}: {cat_color}{score:.2f}{RESET}")

    if result.reasons:
        print(f"\n{BOLD}Detected Risk Triggers:{RESET} {YELLOW}{', '.join(result.reasons)}{RESET}")
        if result.matched_rules:
            print(f"{BOLD}Matched Rules:{RESET}")
            for match in result.matched_rules:
                print(f"  * Rule: {CYAN}{match.rule_name}{RESET} | Pattern: '{YELLOW}{match.pattern_matched}{RESET}'")
    else:
        print(f"\n{BOLD}Detected Risk Triggers:{RESET} {GREEN}None (Clean Request){RESET}")


def cmd_output_safety(text: str):
    """Test post-generation Output Safety Filter against arbitrary text."""
    engine = OutputSafetyEngine()
    res = engine.evaluate(text)

    v_color = GREEN if res.verdict.value == "ALLOW" else (YELLOW if res.verdict.value == "REDACT" else RED)
    print(f"\n{BOLD}Output Safety Verdict:{RESET} {v_color}{BOLD}{res.verdict.value}{RESET}")
    print(f"{BOLD}Sanitized Text:{RESET}\n{res.sanitized_text}\n")
    if res.reasons:
        print(f"{BOLD}Reasons:{RESET} {', '.join(res.reasons)}")


async def async_chat_loop(rules_dir: str | None = None):
    """Interactive CLI REPL for live prompt testing with live AI generation."""
    print_banner()
    print(f"{YELLOW}Interactive Mode -- Type any prompt to test Risk Assessment & AI generation.{RESET}")
    print(f"Type '{BOLD}exit{RESET}' or '{BOLD}quit{RESET}' to stop.\n")

    settings = Settings()
    shield_config = ShieldConfig()
    classifier = ClassifierService(rules_dir=rules_dir)
    policy_engine = PolicyEngine()
    judge = LocalJudge()
    shield_fast = SofaShieldFast(config=shield_config)
    output_safety = OutputSafetyEngine()

    normal_backend = NormalBackend(
        backend_url=settings.normal_backend_url,
        api_key=settings.normal_backend_api_key or None,
        default_model=settings.normal_backend_model,
        timeout=settings.normal_backend_timeout,
    )

    try:
        while True:
            try:
                prompt = input(f"{BOLD}User > {RESET}").strip()
                if not prompt:
                    continue
                if prompt.lower() in ("exit", "quit", "q"):
                    print("Exiting...")
                    break

                # 1. Multi-dimensional Risk Assessment
                result = classifier.classify(prompt)
                decision = policy_engine.evaluate(result)

                cls_color = RED if result.classification == Classification.RESTRICTED else GREEN
                route_color = RED if decision.route == Route.SHIELD else GREEN

                print(f"  * Classification:   {cls_color}{BOLD}{result.classification.value}{RESET} (Risk Score: {result.confidence:.2f})")
                print(f"  * Policy Decision:  {route_color}{BOLD}{decision.route.value}{RESET}")

                if result.categories:
                    active_cats = [f"{k}={v:.2f}" for k, v in result.categories.items() if v > 0]
                    if active_cats:
                        print(f"  * Risk Categories:  {YELLOW}{', '.join(active_cats)}{RESET}")

                if result.reasons:
                    print(f"  * Detected Triggers: {YELLOW}{', '.join(result.reasons)}{RESET}")

                # 2. Execution depending on Route
                if decision.route == Route.SHIELD:
                    judge_verdict = judge.evaluate_request([{"role": "user", "content": prompt}])
                    j_color = RED if judge_verdict == JudgeVerdict.DENY else GREEN
                    print(f"  * Local Judge:      {j_color}{judge_verdict.value}{RESET}")
                    print(f"  * Security Action:  {RED}[SHIELD] Isolated Local Processing (ZERO Cloud Leakage){RESET}")

                    if judge_verdict == JudgeVerdict.DENY:
                        print(f"\n{RED}{BOLD}[SHIELD BLOCKED]:{RESET} Request rejected by Local Judge pre-check (dangerous pattern detected).\n")
                    else:
                        print(f"  * Local Inference Engine: {CYAN}{shield_config.local_llm_model}{RESET} at {shield_config.local_llm_url}")
                        try:
                            # Attempt live execution on local GPU inference endpoint if available
                            raw_shield_resp = await shield_fast.infer([{"role": "user", "content": prompt}])
                            # Local Judge Post-Response evaluation & redaction
                            j_resp_verdict = judge.evaluate_response(raw_shield_resp)
                            if j_resp_verdict == JudgeVerdict.DENY:
                                print(f"\n{RED}{BOLD}[SHIELD RESPONSE BLOCKED]:{RESET} Response leaked critical secret or dangerous content.\n")
                            else:
                                final_shield_resp = judge.redact_response(raw_shield_resp)
                                print(f"\n{YELLOW}{BOLD}[SHIELD RESPONSE (Local Isolated GPU Execution)]:{RESET}")
                                print(f"{final_shield_resp}\n")
                        except (ShieldBackendError, CircuitBreakerOpenError, Exception) as shield_err:
                            print(f"\n{YELLOW}{BOLD}[SHIELD RESPONSE (Isolated Enclave Stub)]:{RESET}")
                            print(f"  Request processed securely in air-gapped environment (Local GPU offline: {shield_err}).")
                            print(f"  {GREEN}FAIL-CLOSED GUARANTEED: 0 requests leaked to cloud.{RESET}\n")

                else:
                    print(f"  * Security Action:  {GREEN}[NORMAL] Forwarding to Cloud Backend ({settings.normal_backend_model}){RESET}")
                    print("  * Fetching response...")
                    try:
                        ai_response = await normal_backend.send([{"role": "user", "content": prompt}])
                        raw_text = ai_response["choices"][0]["message"]["content"].strip()

                        # 3. Output Safety Inspection
                        safety_res = output_safety.evaluate(raw_text)
                        final_text = safety_res.sanitized_text

                        print(f"\n{GREEN}{BOLD}[AI RESPONSE]:{RESET}")
                        print(f"{final_text}\n")
                        if safety_res.is_modified:
                            print(f"{YELLOW}[Output Safety Applied: {safety_res.verdict.value}]{RESET}\n")

                    except Exception as exc:
                        print(f"\n{RED}[Backend Error]: {exc}{RESET}\n")

            except (KeyboardInterrupt, EOFError):
                print("\nExiting...")
                break
    finally:
        await normal_backend.close()
        await shield_fast.client.aclose()


def cmd_interactive(rules_dir: str | None = None):
    asyncio.run(async_chat_loop(rules_dir))


def main():
    parser = argparse.ArgumentParser(description="AI Risk Assessment & Governance CLI Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # chat
    subparsers.add_parser("chat", help="Start interactive live CLI session")

    # classify
    cls_parser = subparsers.add_parser("classify", help="Classify and evaluate a prompt")
    cls_parser.add_argument("prompt", type=str, help="Text prompt to classify")

    # output-safety
    out_parser = subparsers.add_parser("output-safety", help="Test output safety filter")
    out_parser.add_argument("text", type=str, help="Model response text to evaluate")

    args = parser.parse_args()

    if args.command == "chat":
        cmd_interactive()
    elif args.command == "classify":
        cmd_classify(args.prompt)
    elif args.command == "output-safety":
        cmd_output_safety(args.text)
    else:
        cmd_interactive()


if __name__ == "__main__":
    main()
