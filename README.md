# 🛡️ AI Risk Assessment Gateway (Enterprise Architecture)

A production-grade, multi-tiered AI Security & Risk Assessment Ingress Gateway that evaluates threat levels across **Semantic Intent, Conversation Context, User Metadata, and Deterministic Rules**, dispatching requests either to standard cloud AI providers or an air-gapped, isolated **Shield** environment with **Fail-Closed** security guarantees.

---

## 📐 Enterprise Architecture

```
                         AI Application / User
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │    AI Gateway (Ingress) │  (Auth, Rate Limit, Audit)
                     └────────────┬────────────┘
                                  │
                                  ▼
           ┌──────────────────────────────────────────────┐
           │          AI Risk Assessment Layer            │
           │                                              │
           │  ┌────────────────┐      ┌────────────────┐  │
           │  │ Semantic Model │      │Context Analyzer│  │
           │  │(Intent & Nuance│      │ (Multi-turn)   │  │
           │  └───────┬────────┘      └───────┬────────┘  │
           │          │                       │           │
           │          ├───────────────────────┤           │
           │          │                       │           │
           │  ┌───────┴────────┐      ┌───────┴────────┐  │
           │  │Metadata Analyzer│     │ De-Obfuscator  │  │
           │  │ (Role & Privacy)│     │(Base64/Leet/AST│  │
           │  └───────┬────────┘      └───────┬────────┘  │
           │          │                       │           │
           │          └───────────┬───────────┘           │
           │                      ▼                       │
           │          ┌───────────────────────┐           │
           │          │Risk Aggregator Engine │           │
           │          │(Multi-Category Scoring│           │
           │          └───────────────────────┘           │
           └──────────────────────┬───────────────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │  Policy Decision Engine │  (Decoupled Business Rules)
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │    Execution Router     │  (Stateless Traffic Dispatch)
                     └──────┬────────────┬─────┘
                            │            │
              ┌─────────────┘            └─────────────┐
              ▼                                        ▼
       [ NORMAL ROUTE ]                         [ SHIELD ROUTE ]
              │                                        │
              ▼                                        ▼
      Approved Cloud AI                     ┌──────────────────────┐
    (e.g., Google Gemini)                   │ Air-Gapped Shield    │
                                            │ (No Internet Egress) │
                                            │                      │
                                            │ 1. Local Judge       │
                                            │ 2. sofa-shield-fast  │
                                            │ 3. Local LLM Runtime │
                                            └──────────────────────┘
                                                       │
                                             [ FAIL-CLOSED (SR-3) ]
                                             (Zero Cloud Fallback)
```

---

## 🧩 Architectural Components

| Component | Responsibility |
|---|---|
| **AI Gateway (Ingress)** | Receives all traffic, validates API Keys via constant-time comparison, enforces sliding-window rate limits, and prevents direct backend access. |
| **AI Risk Assessment Layer** | Orchestrates 3 threat pillars: **Semantic Classifier**, **Context Analyzer**, and **Metadata Analyzer**, alongside deterministic rule de-obfuscation. |
| **Risk Aggregator Engine** | Synthesizes multi-dimensional risk scores (Security, Privacy, Business Confidentiality) using probabilistic union math. |
| **Policy Decision Engine** | Decoupled governance layer determining routing actions (`NORMAL` vs `SHIELD`) based on risk thresholds. |
| **Execution Router** | High-performance stateless dispatcher executing the policy decision. |
| **Isolated Shield Environment** | Air-gapped local environment with **Local Judge** (pre/post LLM safety evaluation), **sofa-shield-fast** (Circuit Breaker resilience), and **Local LLM**. |
| **Fail-Closed Guarantee (SR-3)** | On any backend failure or outage, returns error response with **0 cloud API calls**. |

---

## 🚀 Quick Start (CLI Testing)

### 1. Install Dependencies
```bash
pip install -e ".[dev]"
```

### 2. Configure Environment (`.env`)
```env
GATEWAY_API_KEYS=sk-test-key-1,sk-test-key-2
RATE_LIMIT_PER_MINUTE=60
NORMAL_BACKEND_URL=https://generativelanguage.googleapis.com
NORMAL_BACKEND_API_KEY=your_gemini_api_key
NORMAL_BACKEND_MODEL=gemini-2.5-flash
SHIELD_SERVICE_URL=http://localhost:8001
RULES_DIR=./rules
```

### 3. Interactive CLI Chat Mode
```bash
python cli.py chat
```

### 4. Run Full Test Suite (94 Automated Tests)
```bash
pytest tests/ -v
```

---

## 📂 Modular Package Structure

```
task3/
├── gateway/                        # AI Gateway Ingress
│   ├── main.py                     # FastAPI Ingress application
│   ├── config.py                   # Environment settings loader
│   ├── middleware/                 # Auth & Rate Limiters
│   ├── routes/                     # /v1/chat/completions & /health
│   └── models/                     # Request & Response schemas
│
├── classifier/                     # AI Risk Assessment Layer
│   ├── service.py                  # Risk Assessment Orchestrator
│   ├── semantic_classifier.py      # Semantic Intent & Business Confidentiality
│   ├── context_analyzer.py         # Multi-turn History & Salami Attack Detector
│   ├── metadata_analyzer.py        # User Role & Project Sensitivity Evaluator
│   ├── risk_aggregator.py          # Multi-Dimensional Risk Synthesis Engine
│   ├── normalizer.py               # De-obfuscation (Base64/Leet/AST Var Splitting)
│   ├── rule_engine.py              # Deterministic Signature Matcher
│   └── models.py                   # Risk & Classification Data Models
│
├── policy/                         # Policy Governance Layer
│   ├── engine.py                   # Deterministic Policy Evaluator
│   └── models.py                   # Route & Decision Models
│
├── router/                         # Execution Layer
│   ├── service.py                  # Dispatcher
│   ├── normal_backend.py           # Cloud AI Client (Gemini/OpenAI)
│   └── shield_backend.py           # Isolated Shield Client (Fail-Closed)
│
├── shield/                         # Air-Gapped Shield Environment
│   ├── main.py                     # Shield Microservice
│   ├── judge.py                    # Local Judge (Pre/Post Safety & PII Redactor)
│   ├── shield_fast.py              # sofa-shield-fast (Circuit Breaker Gateway)
│   └── config.py                   # Shield Service Configuration
│
├── rules/                          # Versioned Security Rules (YAML)
│   ├── default_rules.yaml          # Standard High-Precision Rules
│   └── custom_rules.yaml           # Organization Custom Rules
│
├── tests/                          # 94 Comprehensive Unit & Integration Tests
│   ├── test_classifier.py          # Semantic, Context, Metadata, and De-obfuscation tests
│   ├── test_policy.py              # Policy routing & threshold tests
│   ├── test_gateway.py             # Auth & Rate Limit tests
│   ├── test_router.py              # Routing dispatch tests
│   ├── test_shield.py              # Local Judge & Circuit Breaker tests
│   ├── test_fail_closed.py         # SR-3 Fail Closed verification
│   ├── test_bypass.py              # Ingress bypass prevention
│   └── test_integration.py         # Full pipeline integration tests
│
├── cli.py                          # Interactive CLI Test Tool
├── mock_llm.py                     # Mock Local Model Server
├── pyproject.toml                  # Package Configuration
└── docker-compose.yml              # Production Network Isolation Deployments
```
