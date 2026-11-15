# Inspectra — Complete Project Master Guide & Developer Handbook

Welcome to **Inspectra**. This document is the definitive, all-inclusive technical guide for the Inspectra platform. It is written specifically so that any developer, collaborator, or researcher can understand the entire project, run it, modify it, extend it, and **plug in any AI/LLM model of their choice** (e.g., local Ollama, OpenAI GPT-4o, Anthropic Claude, Groq, Together AI, DeepSeek, or LM Studio).

Nothing is skipped. Every feature, rule, algorithm, mathematical formula, design trade-off, and configuration option is documented in detail below.

---

## Table of Contents
1. [Project Overview & Philosophy](#1-project-overview--philosophy)
2. [Why Each Technology Was Chosen](#2-why-each-technology-was-chosen)
3. [Plugging In Any AI Model (The Model Swapping Guide)](#3-plugging-in-any-ai-model-the-model-swapping-guide)
   - [How the AI Analyzer Works](#how-the-ai-analyzer-works)
   - [Supported AI Providers & Integration Types](#supported-ai-providers--integration-types)
   - [Configuration Reference for Different Models](#configuration-reference-for-different-models)
   - [System Prompt & Expected JSON Output](#system-prompt--expected-json-output)
   - [Fail-Safe AI Architecture (Zero Single-Point-of-Failure)](#fail-safe-ai-architecture-zero-single-point-of-failure)
4. [Architecture & System Flow](#4-architecture--system-flow)
5. [Complete Feature & Detection Criteria Catalog](#5-complete-feature--detection-criteria-catalog)
   - [A. Message & Social Engineering Analysis](#a-message--social-engineering-analysis)
   - [B. URL & Link Analysis](#b-url--link-analysis)
   - [C. Mobile App Request & Toxic Permission Analysis](#c-mobile-app-request--toxic-permission-analysis)
   - [D. QR Code & Quishing Scanner](#d-qr-code--quishing-scanner)
   - [E. User Interface & Security Controls](#e-user-interface--security-controls)
6. [Heuristic Scoring Methodology & Mathematical Formulas](#6-heuristic-scoring-methodology--mathematical-formulas)
7. [API Contracts & Schema Reference](#7-api-contracts--schema-reference)
8. [Project Directory & File Structure](#8-project-directory--file-structure)
9. [Step-by-Step Installation & Running Instructions](#9-step-by-step-installation--running-instructions)
10. [Automated Security Test Suite](#10-automated-security-test-suite)
11. [Privacy Guarantees, Limitations & Disclaimers](#11-privacy-guarantees-limitations--disclaimers)

---

## 1. Project Overview & Philosophy

**Inspectra** is an explainable, privacy-first cybersecurity analysis web platform. It evaluates user-submitted text messages, URLs, mobile application permission requests, and QR codes to determine whether they represent malicious threats or appear safe.

### Core Problems Inspectra Solves:
1. **SMS & WhatsApp Phishing (Smishing):** Fake electricity bills, courier parcel seizure notices, and urgent account blocking alerts.
2. **Digital-Arrest & Authority Impersonation Scams:** Extortion operations where fraudsters impersonate the CBI, Police, ED, Customs, or TRAI via WhatsApp/Skype/video calls, threatening imminent arrest and demanding secret bail transfers.
3. **Deceptive & Evasive Web Links:** Lookalike domains, punycode homoglyphs, brand-spoofing subdomains, raw IP addresses, and embedded `@` credential lures.
4. **Malicious Android Apps & Banking Trojans:** Sideloaded APKs requesting dangerous toxic permission pairs (e.g., Accessibility Service + SMS Interception) designed to bypass 2FA and hijack bank accounts.
5. **QR Code Quishing:** Malicious payloads hidden inside physical or digital QR codes.

### Guiding Principles:
* **Explainability First:** Instead of providing an opaque "black-box" decision, every assessment displays granular findings: the specific rule triggered, the severity level, the exact evidence excerpt, and a clear plain-English explanation.
* **Zero Persistence & Absolute Privacy:** Inspectra **never** writes submitted content to disk or a database. Content is analyzed entirely in-memory and discarded immediately after the HTTP response is sent.
* **Deterministic Heuristics + Hybrid AI:** Heuristic rules provide instant, reproducible, zero-hallucination detection. An optional AI layer adds semantic reasoning for novel conversational tactics. If the AI is offline or fails, the heuristic engine functions at 100% capacity.
* **Fail-Safe Security:** If suspicious heuristic indicators are detected, external API timeouts or model crashes will **never** downgrade a verdict to clean.

---

## 2. Why Each Technology Was Chosen

| Component | Technology | Why It Was Chosen |
|---|---|---|
| **Backend Framework** | **Python 3.9+ & FastAPI** | Fast execution, native asynchronous I/O (`async`/`await`) allowing external checks and AI inference to run concurrently without blocking request workers, automatic OpenAPI (Swagger) documentation, and lightweight resource usage. |
| **Data Validation** | **Pydantic v2** | High-performance Rust-backed data validation. Enforces strict type schemas, sanitizes string inputs, validates length constraints, and defends against malformed JSON or prototype pollution. |
| **ASGI Server** | **Uvicorn** | Battle-tested, lightning-fast ASGI server capable of serving thousands of concurrent requests with low memory footprint. |
| **Domain Parsing** | **tldextract (offline mode)** | Standard Python `urllib.parse` confuses subdomains and multi-level TLDs (e.g. `paypal.com.fraud.co.uk`). `tldextract` accurately separates the subdomain, registrable domain, and suffix using the Public Suffix List. It runs offline (`suffix_list_urls=None`) to prevent DNS lookups or information leakage. |
| **External HTTP** | **httpx** | Fully asynchronous HTTP client for Python with built-in connection pooling, strict timeouts, and modern TLS support. Used for querying VirusTotal and external LLMs. |
| **Automated Testing** | **pytest** | Industry-standard Python testing suite. Inspectra includes 68 automated unit, boundary, matrix, and regression tests. |
| **Frontend Framework** | **React 18 + TypeScript** | Static type safety prevents runtime bugs. Modular component architecture enables clear separation between inputs, meters, indicator lists, and technical breakdowns. |
| **Build Tool** | **Vite** | Sub-second Hot Module Replacement (HMR) during development, highly optimized tree-shaken static production bundles. |
| **Styling** | **Tailwind CSS** | Utility-first styling enabling a clean, responsive **Dark Neo-Brutalist** aesthetic with high-contrast status badges (Critical, High, Medium, Low) and accessible typography. |
| **QR Code Scanner** | **jsQR** | Pure client-side JavaScript QR code decoder. Scans images and camera video frames directly in the browser canvas. **Why this matters:** The user's image or camera feed is never sent over the network to the server, preserving complete privacy. |
| **Icons** | **lucide-react** | Lightweight, clean SVG icon set with zero runtime bloat. |

---

## 3. Plugging In Any AI Model (The Model Swapping Guide)

Inspectra features a dedicated **Hybrid Semantic Defense Layer** in `backend/app/engine/ai_analyzer.py`. This layer allows you or your friend to plug in **any LLM** without changing the backend logic.

### How the AI Analyzer Works
1. When a user submits content, Inspectra's coordinator runs the text through `llama_analyzer.analyze_content()`.
2. The analyzer sends the content to your configured model endpoint along with a strict cybersecurity system prompt.
3. The model returns a structured JSON payload indicating whether the content is suspicious, its confidence score (0–100), detected tactics, and evidence snippets.
4. If `confidence >= 75`, Inspectra flags a `High` severity finding (+25 score). If `50 <= confidence < 75`, it flags a `Medium` severity finding (+15 score).
5. If the model returns `confidence < 50` or `is_suspicious: false`, no finding is added.

---

### Supported AI Providers & Integration Types

The code supports two major integration standards via the `LLAMA_PROVIDER` environment variable:
1. **`ollama`**: Native API for local Ollama instances (`POST /api/generate` with `"format": "json"`).
2. **`openai_compatible`**: Standard OpenAI REST format (`POST /v1/chat/completions` with Bearer auth and JSON object mode). This works with **almost every model in existence**:
   - OpenAI (GPT-4o, GPT-4o-mini, GPT-3.5)
   - Groq (Ultra-fast cloud inference for LLaMA 3.3, Mixtral)
   - Anthropic Claude (via LiteLLM proxy or OpenRouter)
   - Local LM Studio (Runs on your laptop at `http://127.0.0.1:1234/v1`)
   - vLLM / LocalAI / Jan / Text-Generation-WebUI
   - Together AI / DeepSeek / Mistral AI

---

### Configuration Reference for Different Models

All AI settings are controlled via environment variables (in your shell or in a `.env` file). Here are plug-and-play recipes for every popular setup:

#### Recipe 1: Local Ollama (Default, Free & Completely Private)
Run any model locally on your Mac, Windows, or Linux machine with Ollama:
```bash
# 1. Install and start Ollama (https://ollama.com)
# 2. Pull your desired model
ollama pull llama3.1:8b
# or: ollama pull mistral
# or: ollama pull qwen2.5:7b

# 3. Export environment variables
export LLAMA_ENABLED=true
export LLAMA_PROVIDER=ollama
export LLAMA_BASE_URL=http://127.0.0.1:11434
export LLAMA_MODEL=llama3.1:8b
```

#### Recipe 2: OpenAI (GPT-4o or GPT-4o-mini)
```bash
export LLAMA_ENABLED=true
export LLAMA_PROVIDER=openai_compatible
export LLAMA_BASE_URL=https://api.openai.com
export LLAMA_MODEL=gpt-4o-mini
export LLAMA_API_KEY=sk-proj-your-openai-api-key-here
export LLAMA_TIMEOUT_SECONDS=15.0
```

#### Recipe 3: Groq Cloud (Blazing Fast Inference, Free Tier Available)
Groq processes LLaMA 3.3 at over 300 tokens/second:
```bash
export LLAMA_ENABLED=true
export LLAMA_PROVIDER=openai_compatible
export LLAMA_BASE_URL=https://api.groq.com/openai
export LLAMA_MODEL=llama-3.3-70b-versatile
export LLAMA_API_KEY=gsk_your-groq-api-key-here
export LLAMA_TIMEOUT_SECONDS=10.0
```

#### Recipe 4: DeepSeek API
```bash
export LLAMA_ENABLED=true
export LLAMA_PROVIDER=openai_compatible
export LLAMA_BASE_URL=https://api.deepseek.com
export LLAMA_MODEL=deepseek-chat
export LLAMA_API_KEY=your-deepseek-api-key-here
export LLAMA_TIMEOUT_SECONDS=15.0
```

#### Recipe 5: LM Studio (Local Desktop GUI for any GGUF Model)
1. Download LM Studio (https://lmstudio.ai).
2. Download any GGUF model (e.g. Llama-3.1, Gemma-2, Mistral).
3. Click the "Local Server" tab in LM Studio and start the server on port `1234`.
4. Configure Inspectra:
```bash
export LLAMA_ENABLED=true
export LLAMA_PROVIDER=openai_compatible
export LLAMA_BASE_URL=http://127.0.0.1:1234
export LLAMA_MODEL=local-model
export LLAMA_API_KEY=""
```

#### Recipe 6: OpenRouter (Access Claude 3.5 Sonnet, Gemini 1.5, etc.)
```bash
export LLAMA_ENABLED=true
export LLAMA_PROVIDER=openai_compatible
export LLAMA_BASE_URL=https://openrouter.ai/api
export LLAMA_MODEL=anthropic/claude-3.5-sonnet
export LLAMA_API_KEY=sk-or-v1-your-openrouter-key-here
```

#### Recipe 7: Disable AI Completely (Pure Heuristic Mode)
If you want to run Inspectra with zero external model dependencies and zero network calls:
```bash
export LLAMA_ENABLED=false
```
Inspectra will rely entirely on its heuristic rules and will mark `checks.ai_semantic_analysis = "not_configured"`.

---

### System Prompt & Expected JSON Output

The system prompt is defined in `backend/app/engine/ai_analyzer.py`:
```text
You are an explainable cybersecurity threat analyzer for Inspectra.
Analyze the user-submitted message, URL, or app request strictly for social engineering, phishing, authority extortion, or malware installation risks.

You must respond ONLY with a raw valid JSON object without markdown fences, with these exact keys:
{
  "is_suspicious": true or false,
  "confidence": integer between 0 and 100,
  "primary_threat": "phishing" or "digital_arrest" or "suspicious_app" or "none",
  "detected_tactics": ["list of detected coercive tactics or null"],
  "evidence_excerpt": "exact short substring from input or null",
  "explanation": "concise factual explanation of the threat or why it appears safe"
}
Do not provide advice, recovery steps, or conversational chat.
```

#### How the Output is Parsed & Hardened:
* **String Boolean Defense (Finding 13):** LLMs sometimes output string `"false"` instead of boolean `false`. The parser strictly normalizes strings so `"false"` will never be evaluated as truthy.
* **Type Validation:** Validates that `confidence` is a valid integer and `detected_tactics` is a list of strings.
* **Evidence Truncation:** Substrings are safely sliced to prevent UI layout breaking.

---

### Fail-Safe AI Architecture (Zero Single-Point-of-Failure)
1. **Timeout Protection:** The HTTP client has a strict timeout (`LLAMA_TIMEOUT_SECONDS`, default 15s). If the model hangs or is overloaded, the request aborts gracefully.
2. **Non-Blocking Operation:** An LLM crash, invalid JSON, or 500 error will **never crash Inspectra**. The error is logged, `checks.ai_semantic_analysis` is flagged as `"failed"`, and the heuristic analysis completes normally.
3. **Suspicious Precedence:** If the heuristic engine found a suspicious link or OTP harvesting rule, an AI failure will **not** change the verdict to "unable to assess". The suspicious verdict is preserved.

---

## 4. Architecture & System Flow

```
                      +-----------------------------------+
                      |         User Submission           |
                      | (Message, URL, App, or QR Code)   |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |     Input Validation Layer        |
                      |  - Length checks (max 10,000)     |
                      |  - Scheme validation              |
                      |  - Sufficiency check (>= 4 chars) |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |      Text Normalization Layer     |
                      |  - NFKC unicode decomposition     |
                      |  - Zero-width character stripping |
                      |  - Smart quote & dash alignment   |
                      +-----------------+-----------------+
                                        |
                 +----------------------+----------------------+
                 |                      |                      |
                 v                      v                      v
     +--------------------+   +-------------------+   +--------------------+
     |  URL Parser Engine |   |  Message Engine   |   | App Request Engine |
     | - tldextract split |   | - Regex heuristics|   | - Toxic permission |
     | - Homoglyph check  |   | - Digital arrest  |   |   combinations     |
     | - IP / TLD checks  |   | - OTP harvesting  |   | - Purpose mismatch |
     | - Defanging        |   | - Negation filter |   | - Sideload alert   |
     +---------+----------+   +---------+---------+   +---------+----------+
               |                        |                       |
               +------------------------+-----------------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |  Hybrid AI Semantic Layer (LLM)   |
                      |  - Ollama / OpenAI / Groq / vLLM  |
                      |  - Fallback / Timeout protection  |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |    Heuristic Scorer & Synergy     |
                      |  - Signal family diminishing math |
                      |  - Multi-vector synergy bonuses   |
                      |  - Anti-dilution URL max scoring  |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |    Verdict & Summary Packaging    |
                      |  - appears_safe / suspicious /    |
                      |    unable_to_assess               |
                      |  - Mandatory limitation notices   |
                      +-----------------------------------+
```

---

## 5. Complete Feature & Detection Criteria Catalog

### A. Message & Social Engineering Analysis

Implemented in `backend/app/engine/rules/message_rules.py`:

| Rule ID | Rule Name | Severity | Base Score | Detection Criteria & Target Threat Patterns |
|---|---|---|---|---|
| `cred_harvest_request` | Sensitive Credential / OTP Request | Critical | 45 | Matches direct solicitations for one-time passwords, OTPs, PINs, passwords, CVVs, net banking credentials, or debit/credit card numbers. |
| `urgent_demand_language` | Artificial Urgency Phrases | Medium | 20 | Detects artificial time constraints: *"within 2 hours"*, *"immediately"*, *"account will be suspended today"*, *"urgent action required"*, *"act fast"*. |
| `threatening_consequences` | Coercive Threats & Adverse Consequences | High | 35 | Flags severe negative outcomes: arrest warrants, legal court action, police complaints, FIR filings, electricity power cuts, account freezes, SIM deactivation. |
| `authority_impersonation` | Law Enforcement / Regulatory Impersonation | High | 35 | Detects claims of acting on behalf of judicial or governmental bodies: CBI, Mumbai Police, Cyber Crime Cell, ED (Enforcement Directorate), TRAI, Supreme Court, Customs Office. |
| `payment_transfer_demand` | Coercive Fund Transfer / Bail Demand | High | 35 | Detects direct requests to transfer funds into "clearing accounts", "safe escrow accounts", "bail deposits", "penalty clearing", or unknown UPI IDs. |
| `secrecy_isolation_pressure` | Secrecy & Isolation Pressure | High | 30 | Hall-mark tactic of digital-arrest scams: ordering the victim not to disconnect the call, stay in a closed room, not speak to family members, or maintain absolute confidentiality. |
| `remote_access_software_request` | Remote Access Software Lure | High | 40 | Requests instructing the victim to install remote monitoring tools: AnyDesk, TeamViewer, RustDesk, QuickSupport, AirDroid, Screen Share. |
| `security_disable_instruction` | Device Protection Tampering Instructions | Critical | 45 | Instructions telling the user to disable Google Play Protect, turn off security shields, or allow "install from unknown sources". |
| `unofficial_sender_mobile_number` | Personal Mobile Number SMS Header Anomaly | High | 35 | Flags official-sounding bank or institutional messages sent from standard personal mobile numbers (e.g. `+91-9876543210`) instead of approved alphanumeric sender IDs (e.g. `VK-HDFCBK`). |
| `courier_customs_contraband_parcel` | Contraband Parcel Seizure Extortion | High | 35 | Detects extortion scenarios claiming a FedEx, DHL, or Blue Dart parcel containing narcotics, illegal passports, MDMA, or counterfeit currency has been seized at customs. |
| `utility_service_disconnection_threat` | Utility / Power Disconnection Threat | High | 35 | Flags fraudulent electricity disconnection threats stating power will be terminated tonight at 9:30 PM due to an unpaid bill, urging the victim to call a personal mobile number. |
| `digital_arrest_composite_pattern` | Digital-Arrest Composite Pattern Synergy | Critical | 30 (Bonus) | Triggered when **Authority Claim** + **Adverse Threat** + (**Payment Demand** OR **Secrecy Pressure**) co-occur in the same message. |
| `credential_phishing_composite` | Credential Phishing Synergy | High | 25 (Bonus) | Triggered when **Urgent Demand** or **Threat** is directly paired with a **Credential / OTP Request**. |

#### Defensive Negation & Educational Text Guard
Scammers often trigger false positives in simple keyword filters. Inspectra features an educational guard:
* Sentences like *"Never share your OTP or password with anyone, bank officials will never ask for PIN"* are detected via defensive negation phrases (*"never share"*, *"do not give"*, *"awareness alert"*).
* When detected, credential rules are **suppressed**, preventing false alarms on legitimate bank security advisories.

#### Zero-Width & Unicode Evasion Stripping
* Attackers often inject invisible zero-width characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, `\u00AD`) inside keywords (e.g., `O\u200BTP`) to bypass naive regexes.
* Inspectra normalizes all incoming text via Unicode **NFKC** normalization and strips all zero-width characters before analysis.

---

### B. URL & Link Analysis

Implemented in `backend/app/engine/url_parser.py` and `backend/app/engine/rules/url_rules.py`:

| Rule ID | Rule Name | Severity | Base Score | Detection Criteria |
|---|---|---|---|---|
| `url_misleading_subdomain` | Deceptive Brand Subdomain Routing | High | 40 | Detects well-known brand names (e.g. `paypal`, `apple`, `google`, `chase`) placed in subdomains while the actual registered root domain belongs to an unrelated third party (e.g., `paypal.com.account-verify.xyz`). |
| `url_homoglyph_punycode` | Confusable Homoglyph / Punycode (IDN) | High | 40 | Detects internationalized domain names (IDN) starting with `xn--` or domains using visually confusable Cyrillic/Greek characters that mimic Latin letters (e.g. replacing Latin `a` with Cyrillic `а`). |
| `url_raw_ip_host` | Raw IP Address Hostname | High | 35 | Flags links where the host is an IPv4 or IPv6 address (e.g. `http://192.168.1.50/login`) instead of a registered domain. |
| `url_embedded_credentials` | Embedded Credentials with `@` Obfuscation | Critical | 45 | Flags URLs using the HTTP basic auth syntax `https://legitimate.com@evil-destination.com/` which tricks victims into believing they are visiting `legitimate.com`. |
| `url_dangerous_scheme` | Dangerous Execution URI Scheme | Critical | 60 | Flags execution schemes: `javascript:`, `data:`, `vbscript:`, `file:`, `blob:`, `about:`. |
| `url_direct_executable_download` | Direct Executable / APK Download | High | 40 | Detects links whose path terminates in executable or app package extensions: `.apk`, `.exe`, `.scr`, `.bat`, `.cmd`, `.msi`, `.vbs`, `.ps1`, `.dmg`, `.dex`, `.iso`. |
| `url_shortened_destination` | Concealing URL Shortener | Low | 15 | Detects URL shortening services (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, `rebrand.ly`, `t.me`, etc.) that obscure the true destination. |
| `url_suspicious_tld` | High-Risk Disposable TLD | Medium | 20 | Flags top-level domains statistically overrepresented in spam and disposable phishing: `.top`, `.xyz`, `.zip`, `.mov`, `.fit`, `.kim`, `.tk`, `.ml`, `.cf`, `.gq`, `.buzz`, `.icu`, `.vip`. |
| `url_suspicious_encoding` | Double / Obfuscated URL Encoding | Medium | 25 | Detects multi-level percent encoding (`%252e`, `%252f`) used to bypass web application firewalls and basic URL parsers. |

#### URL Defanging Engine
To ensure safety in the user interface:
* All displayed URLs are rendered as **non-clickable, defanged text**:
  * Protocol: `https://` becomes `hxxps[://]`
  * Dots: `domain.com` becomes `domain[.]com`
* Users can safely inspect or copy indicators without risking accidental clicks.

#### Multi-URL Anti-Dilution Formula
If an email or message contains 5 benign links and 1 malicious link:
* Traditional scoring systems average the score, diluting the malicious link.
* Inspectra computes:
  $$\text{UrlRiskScore} = \max(\text{URL}_1, \dots, \text{URL}_n) + \min(15, 5 \times (N_{\text{suspicious}} - 1))$$
* The single most dangerous link sets the baseline score, and additional suspicious links add cumulative penalties.

---

### C. Mobile App Request & Toxic Permission Analysis

Implemented in `backend/app/engine/rules/app_rules.py`:

| Rule ID | Rule Name | Severity | Base Score | Detection Criteria |
|---|---|---|---|---|
| `app_accessibility_sms_trojan_pattern` | Toxic Trojan Permission Pair (Accessibility + SMS) | Critical | 50 | Detects the classic Android banking trojan pattern (Cerberus, TeaBot, SharkBot): requesting **Accessibility Service** alongside **SMS Reading/Receiving** or **Notification Listener**, allowing the app to read 2FA codes and autonomously click buttons. |
| `app_purpose_permission_mismatch` | Claimed Purpose vs Requested Permission Mismatch | High | 40 | Flags apps whose stated function has zero justification for high-privilege permissions (e.g., a "Calculator", "Flashlight", or "Wallpaper" app requesting Contacts, SMS, Microphone, Location, or Call Logs). |
| `app_sideload_untrusted_source` | Untrusted Direct Sideloading Source | High | 35 | Flags apps distributed outside official stores (Google Play / Apple App Store): direct `.apk` downloads, Telegram channels, WhatsApp attachments, or third-party web forums. |
| `app_device_admin_privilege` | High-Risk Device Administrator Privilege | High | 35 | Flags requests for `BIND_DEVICE_ADMIN`, which prevents uninstallation, enforces lockscreen policies, and can remotely wipe the device. |
| `app_overlay_notification_combo` | Screen Overlay + Notification Stealing Combo | High | 35 | Detects `SYSTEM_ALERT_WINDOW` (display over other apps) combined with `BIND_NOTIFICATION_LISTENER_SERVICE`, standard for phishing overlay attacks over banking apps. |
| `app_context_insufficient` | Insufficient App Context Notice | Low | 0 | Informs the user when no permissions or purpose were provided. |

#### Android Prefix & Label Normalization (Finding 11)
Users may input permissions as raw manifest strings (`android.permission.BIND_ACCESSIBILITY_SERVICE`) or plain English labels (*"Accessibility Service"*, *"Read SMS messages"*). Inspectra normalizes both formats into uniform permission tokens before analysis.

#### Benign App Context Handling (Finding 14)
Legitimate apps (e.g., messaging apps requesting SMS/Camera, or navigation apps requesting Location) are evaluated in context with their claimed purpose to prevent false positives.

---

### D. QR Code & Quishing Scanner

Implemented in `frontend/src/components/QrCodeInput.tsx`:
* **Zero Server Uploads:** Uses `jsQR` to decode the QR code strictly within the user's browser canvas.
* **Dual Input Modes:** Supports drag-and-drop of QR code image files (`.png`, `.jpg`, `.webp`) or live camera scanning via `navigator.mediaDevices.getUserMedia`.
* **Smart Protocol Routing:** Automatically parses the decoded QR payload. If it's a URL, it switches to URL analysis; if it's text or contact data, it routes to Message analysis.

---

### E. User Interface & Security Controls

Implemented in `frontend/src/` and `backend/app/main.py`:
1. **Sliding Window Rate Limiter:** Backend middleware enforces a limit of 60 requests per minute per IP to prevent automated denial-of-service, with periodic cleanup of stale records.
2. **HTTP Hardening Headers:** Every response includes `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Permissions-Policy`.
3. **In-Memory Session History:** The frontend stores the last 5 scans in tab memory only. Refreshing or closing the tab completely clears all traces.
4. **Report Export:** Provides one-click sanitized export of findings in clean JSON and Markdown format.
5. **Dark Neo-Brutalist Aesthetic:** High-contrast design optimized for rapid triage, featuring distinct color coding:
   - Critical: Red (`#EF4444`)
   - High: Amber-Orange (`#F97316`)
   - Medium: Yellow (`#F59E0B`)
   - Low: Blue (`#3B82F6`)
   - Safe: Emerald (`#10B981`)

---

## 6. Heuristic Scoring Methodology & Mathematical Formulas

Inspectra computes a deterministic risk score between **0 and 100**.

### 1. Signal Families & Diminishing Returns Formula
To prevent repetitive keywords from artificially maxing out the score (e.g., an attacker repeating *"urgent immediately right now within 1 hour"*), all rules belong to **Signal Families**:
* `credentials`
* `urgency`
* `threat`
* `authority`
* `payment`
* `secrecy`
* `remote_access`
* `security_tamper`
* `dangerous_permissions`
* `purpose_mismatch`
* `device_admin`
* `installation_source`
* `brand_spoof`
* `homoglyph`
* `host_type`
* `payload`
* `tld`
* `shortener`

For any signal family $F$ with rule contributions $s_1 \ge s_2 \ge \dots \ge s_k$:
$$\text{FamilyScore}(F) = s_1 + \sum_{i=2}^{k} \lfloor 0.20 \times s_i \rfloor$$

The strongest indicator contributes 100% of its weight, while secondary indicators in that same family contribute only 20%.

### 2. Cross-Vector Text + URL Synergy
When a message contains both deceptive text and a malicious URL:
$$\text{CombinedScore} = \max\Big(\text{TextScore},\; \text{UrlScore},\; \lfloor 0.75 \times \text{TextScore} + 0.55 \times \text{UrlScore} \rfloor\Big)$$

### 3. Verdict Determination & Precedence Rule

| Verdict | Condition | Meaning |
|---|---|---|
| **`appears_safe`** | Risk score $< 25$ **AND** no High/Critical indicators **AND** all checks completed | No meaningful suspicious signals were detected. |
| **`suspicious`** | Risk score $\ge 25$ **OR** any High or Critical indicator detected | Content exhibits known attack patterns or deceptive indicators. |
| **`unable_to_assess`** | Input is insufficient ($< 4$ characters) **OR** an essential external check failed on otherwise-clean content | Inconclusive assessment state. |

> **Fail-Safe Precedence Rule:** Suspicious heuristic evidence **always** takes precedence over external check failures. If an external model or reputation check times out or fails, but heuristics detected an OTP harvest or suspicious URL, the verdict **remains `suspicious`**.

---

## 7. API Contracts & Schema Reference

### Health Check Endpoint
* **URL:** `GET /api/health`
* **Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "engine": "inspectra-rules-v1"
}
```

---

### Analysis Endpoint
* **URL:** `POST /api/analyze`
* **Headers:** `Content-Type: application/json`

#### Request Schema:
```json
{
  "input_type": "message",
  "content": "URGENT: Mumbai Police CBI Cyber Crime Cell has issued a digital arrest warrant for illegal money laundering. Transfer bail deposit to UPI id: clearing@bank immediately.",
  "context": {
    "claimed_app_purpose": null,
    "installation_source": null,
    "requested_permissions": []
  }
}
```

* For **App Requests**, supply context:
```json
{
  "input_type": "app_request",
  "content": "Flashlight Torch Pro APK",
  "context": {
    "claimed_app_purpose": "Flashlight utility",
    "installation_source": "Telegram link (Direct APK)",
    "requested_permissions": [
      "android.permission.BIND_ACCESSIBILITY_SERVICE",
      "android.permission.RECEIVE_SMS"
    ]
  }
}
```

#### Response Schema:
```json
{
  "verdict": "suspicious",
  "risk_score": 85,
  "category": "digital_arrest_and_authority_impersonation",
  "summary": "The submitted content exhibits indicators consistent with a digital-arrest / authority impersonation scam. Key signals detected: Law Enforcement / Regulatory Authority Impersonation; Coercive Threats & Adverse Consequences; Demands for Immediate Fund / Bail Transfer.",
  "findings": [
    {
      "rule_id": "authority_impersonation",
      "name": "Law Enforcement / Regulatory Authority Impersonation",
      "severity": "high",
      "evidence": "mumbai police cbi cyber crime cell",
      "explanation": "Content claims association with judicial, police, or regulatory authorities."
    },
    {
      "rule_id": "digital_arrest_composite_pattern",
      "name": "Digital-Arrest Composite Pattern Synergy",
      "severity": "critical",
      "evidence": "digital arrest warrant",
      "explanation": "Multiple high-consequence digital-arrest indicators co-occur: authority impersonation + adverse threat + payment demand."
    }
  ],
  "urls": [],
  "checks": {
    "text_analysis": "completed",
    "url_structure": "not_applicable",
    "reputation": "not_configured",
    "ai_semantic_analysis": "completed"
  },
  "limitations": [
    "This assessment is based on the submitted content and available checks. It does not guarantee safety or confirm malicious intent.",
    "This assessment does not verify the sender's identity or inspect remote server infrastructure.",
    "The risk score is heuristic, not a statistically validated probability of fraud."
  ],
  "engine_version": "1.0.0"
}
```

---

## 8. Project Directory & File Structure

```
CP/
├── backend/
│   ├── app/
│   │   ├── config.py                 # Central settings (env vars, ports, thresholds, AI config)
│   │   ├── main.py                   # FastAPI server, CORS, rate-limiting & static mount
│   │   ├── models/
│   │   │   ├── requests.py           # Pydantic input models (AnalyzeRequest, AppContext)
│   │   │   └── responses.py          # Pydantic response models (Finding, UrlFinding, Verdict)
│   │   └── engine/
│   │       ├── coordinator.py        # Master pipeline orchestrating validation, rules & AI
│   │       ├── validator.py          # Input length, content sufficiency & scheme checks
│   │       ├── normalizer.py         # NFKC Unicode normalization & zero-width character stripping
│   │       ├── url_parser.py         # Offline tldextract, homoglyph & IP detection
│   │       ├── scorer.py             # Diminishing returns & multi-vector synergy math
│   │       ├── ai_analyzer.py        # Hybrid LLaMA / Ollama / OpenAI semantic analysis layer
│   │       ├── reputation.py         # Optional VirusTotal / external threat intel interface
│   │       └── rules/
│   │           ├── base.py           # Rule dataclass & ThreatCategory enum
│   │           ├── registry.py       # Global singleton rule registry & lookups
│   │           ├── message_rules.py  # 13 message heuristics (OTP, digital arrest, utility scams)
│   │           ├── url_rules.py      # 9 URL heuristics (homoglyphs, subdomains, raw IPs)
│   │           └── app_rules.py      # 6 app heuristics (trojan permissions, purpose mismatch)
│   ├── tests/                        # 68 automated pytest unit & integration tests
│   └── requirements.txt              # Backend Python dependencies
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx                   # Main React view, active tab state & theme manager
│   │   ├── main.tsx                  # React DOM entry point
│   │   ├── index.css                 # Tailwind CSS styles & Neo-Brutalist variables
│   │   ├── types/api.ts              # TypeScript interfaces mirroring backend responses
│   │   ├── services/api.ts           # Fetch API service with abort controller timeouts
│   │   └── components/
│   │       ├── Header.tsx            # Header bar with theme toggle & service health indicator
│   │       ├── InputTabs.tsx         # Tab switcher (Message, URL, App Request, QR Code)
│   │       ├── MessageInput.tsx      # Text message input with char counter
│   │       ├── UrlInput.tsx          # Multi-URL batch input
│   │       ├── AppRequestInput.tsx   # Android app permission selector & purpose input
│   │       ├── QrCodeInput.tsx       # jsQR client-side camera & file drop scanner
│   │       ├── SampleSelector.tsx    # Curated preset attack scenarios for instant demo
│   │       ├── VerdictCard.tsx       # Large verdict display (Safe / Suspicious / Unable to Assess)
│   │       ├── RiskMeter.tsx         # 0-100 visual risk score gauge
│   │       ├── IndicatorsList.tsx    # Detailed list of triggered rules with evidence badges
│   │       ├── UrlBreakdown.tsx      # Individual URL inspection cards with defanged links
│   │       ├── ChecksSummary.tsx     # Transparent status of all engine checks
│   │       ├── SessionHistory.tsx    # Tab-session in-memory past scans (max 5)
│   │       ├── TechnicalDetails.tsx  # Raw JSON and Markdown export modal
│   │       └── LimitationsNotice.tsx # Mandatory safety disclaimer notice
│   ├── package.json                  # Frontend dependencies (React, Vite, Tailwind, jsQR)
│   └── vite.config.ts                # Vite dev server & proxy configuration
│
├── run.sh                            # One-click startup script (venv, tests, build, uvicorn)
├── README.md                         # Project documentation
├── SCORING.md                        # Formal mathematical scoring methodology
└── CYBERSHIELD_MASTER_GUIDE.md       # This comprehensive master handbook
```

---

## 9. Step-by-Step Installation & Running Instructions

### System Requirements
* **Operating System:** macOS, Linux, or Windows (WSL2 recommended for Windows)
* **Python:** 3.9, 3.10, 3.11, or 3.12
* **Node.js:** 18.x or 20.x
* **Memory:** 4 GB RAM minimum (8+ GB recommended if running local LLMs with Ollama)

---

### Method A: One-Click Startup (Recommended)
Inspectra includes an automated startup script `run.sh` that checks dependencies, creates the Python virtual environment, executes the automated test suite, builds frontend static assets, and launches the server:
```bash
cd /path/to/CP
chmod +x run.sh
./run.sh
```
Once started, open your browser at:
👉 **`http://127.0.0.1:8000`**

---

### Method B: Manual Step-by-Step Setup

#### 1. Backend Setup
```bash
# Navigate to the repository root
cd /path/to/CP

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Run automated tests to verify your setup
pytest backend/tests -v
```

#### 2. Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Build static production assets
npm run build

# Return to root directory
cd ..
```

#### 3. Start the Server
With the production frontend built, FastAPI serves both the API and the static web app on port 8000:
```bash
# From the repository root with .venv activated:
PYTHONPATH=backend uvicorn app.main:app --host 127.0.0.1 --port 8000
```

#### 4. Optional: Live Development Mode
If you are modifying frontend React components and want live Hot Module Replacement (HMR):
```bash
# Terminal 1 (Backend API):
source .venv/bin/activate
PYTHONPATH=backend uvicorn app.main:app --reload --port 8000

# Terminal 2 (Frontend Vite Server):
cd frontend
npm run dev
# Vite runs at http://localhost:5173 and automatically proxies /api to port 8000
```

---

## 10. Automated Security Test Suite

Inspectra contains **68 automated tests** covering edge cases, evasion attempts, regex boundaries, and security properties:

```bash
# Run the entire test suite
pytest backend/tests -v
```

### What the Test Suite Verifies:
1. **`test_messages.py`:** Tests credential harvesting, urgency language, digital-arrest threats, authority impersonation, customs parcel extortion, electricity disconnection scams, and negation awareness guards.
2. **`test_urls.py`:** Tests lookalike subdomains, homoglyphs/punycode, raw IP addresses, embedded `@` syntax, executable download extensions, and shortener detection.
3. **`test_app_requests.py`:** Tests toxic permission pairs (Accessibility + SMS), flashlight purpose mismatch, sideloading source detection, and device admin requests.
4. **`test_reputation_and_scoring.py`:** Tests signal family diminishing returns formulas, multi-URL anti-dilution logic, and score caps (0–100).
5. **`test_validation_security.py`:** Tests input length boundaries (10,000 characters), empty/insufficient content handling, unsupported URL schemes (`ftp://`, `ldap://`), and rate limiting.
6. **`test_llama_ai.py`:** Tests mock AI model outputs, string boolean handling (`"false"`), confidence-based scoring, timeout handling, and fail-safe recovery when the model returns 500 or times out.
7. **`test_audit_findings_10_to_14.py`:** Verifies key real-world edge cases:
   - *Finding 10:* Preserving uppercase domains (`HDFC-UPDATE.COM`) from being dropped by sentence-period filters.
   - *Finding 11:* Handling `android.permission.*` manifest prefixes and human-readable permission labels.
   - *Finding 12:* Ensuring suspicious heuristic evidence prevails over external check failures.
   - *Finding 13:* Ensuring string `"false"` in AI responses is not evaluated as suspicious.
   - *Finding 14:* Preventing false positives on legitimate benign chat and utility applications.

---

## 11. Privacy Guarantees, Limitations & Disclaimers

### Privacy & Data Handling Guarantees:
* **No Database:** Inspectra does not connect to PostgreSQL, SQLite, MongoDB, or Redis.
* **No Disk Persistence:** User submissions are parsed in volatile RAM and freed upon request completion.
* **Safe URL Handling:** URLs are evaluated using passive string algorithms and offline public suffix tables. Inspectra **never** fetches, crawls, or executes remote URLs or binary payloads.
* **Client-Side QR:** QR codes are scanned locally in the browser canvas using `jsQR`; no photos or camera streams are sent to the backend.

### Technical & Operational Limitations:
1. **No Dynamic Execution:** Inspectra does not decompile APKs or execute payloads inside a virtual sandbox. App assessments evaluate declared permissions and claimed context only.
2. **Sender Identity Unverifiability:** SMS headers and display names can be spoofed at the telecom level. Inspectra evaluates indicators present in the submitted text, but cannot authenticate cryptographic telecom origin without carrier signaling data.
3. **Heuristic Nature of Scores:** The 0–100 score is a density metric of detected deceptive patterns, not a statistically validated actuarial probability of fraud.

### Mandatory Disclaimer
Every assessment generated by Inspectra includes this disclaimer:
> *"This assessment is based on the submitted content and available checks. It does not guarantee safety or confirm malicious intent."*
