# Inspectra — Suspicious Content Analyzer

**Inspectra** is an explainable, privacy-first cybersecurity analysis web platform. It evaluates user-submitted text messages, URLs, and mobile application requests to assess whether the content appears safe or suspicious.

The system is built on a **transparent heuristic rules engine** paired with an optional **local LLaMA AI semantic analyzer**, providing deterministic, auditable risk scores (0–100), human-readable indicator findings, highlighted evidence snippets, and automatic URL defanging.

> [!TIP]
> **Looking for the complete developer handbook and model customization guide?**
> See [INSPECTRA_MASTER_GUIDE.md](file:///Users/chakri/Downloads/CP/INSPECTRA_MASTER_GUIDE.md) for full architectural explanations, step-by-step guides to swap AI models (Ollama, OpenAI, Groq, Claude, DeepSeek, LM Studio), mathematical formulas, and complete feature criteria.

---

## Table of Contents
1. [Core Design Principles & Privacy Guarantees](#core-design-principles--privacy-guarantees)
2. [Architecture Overview](#architecture-overview)
3. [Implemented Feature Catalog & Expected Outputs](#implemented-feature-catalog--expected-outputs)
   - [A. Message & Social Engineering Analysis](#a-message--social-engineering-analysis)
     - [1. Sensitive Credential & OTP Harvesting](#1-sensitive-credential--otp-harvesting)
     - [2. Artificial Urgency & Coercive Pressure](#2-artificial-urgency--coercive-pressure)
     - [3. Digital-Arrest Scam & Authority Impersonation](#3-digital-arrest-scam--authority-impersonation)
     - [4. Personal Mobile Number & Unofficial SMS Header Anomaly](#4-personal-mobile-number--unofficial-sms-header-anomaly)
     - [5. Courier & Customs Contraband Parcel Seizure Extortion](#5-courier--customs-contraband-parcel-seizure-extortion)
     - [6. Utility & Electricity Disconnection Threats](#6-utility--electricity-disconnection-threats)
     - [7. Educational Awareness & Defensive Negation Handling](#7-educational-awareness--defensive-negation-handling)
     - [8. Zero-Width Character & Unicode Obfuscation Stripping](#8-zero-width-character--unicode-obfuscation-stripping)
   - [B. URL & Web Link Analysis](#b-url--web-link-analysis)
     - [9. Misleading Brand Subdomains & Lookalike Routing](#9-misleading-brand-subdomains--lookalike-routing)
     - [10. Confusable Homoglyphs & Punycode (IDN) Attacks](#10-confusable-homoglyphs--punycode-idn-attacks)
     - [11. Raw IP Address Hostnames](#11-raw-ip-address-hostnames)
     - [12. Embedded Credentials with `@` Obfuscation](#12-embedded-credentials-with--obfuscation)
     - [13. Dangerous URI Schemes & Executable Downloads](#13-dangerous-uri-schemes--executable-downloads)
     - [14. URL Shortener Detection without False Alarms](#14-url-shortener-detection-without-false-alarms)
     - [15. Multi-URL Batch Scanning with Anti-Dilution](#15-multi-url-batch-scanning-with-anti-dilution)
     - [16. Automatic URL Defanging & Sanitized Copy](#16-automatic-url-defanging--sanitized-copy)
   - [C. Mobile App Request & Toxic Permission Analysis](#c-mobile-app-request--toxic-permission-analysis)
     - [17. Toxic Banking Trojan Permission Combinations](#17-toxic-banking-trojan-permission-combinations)
     - [18. Claimed App Purpose vs. Requested Permission Mismatch](#18-claimed-app-purpose-vs-requested-permission-mismatch)
     - [19. High-Risk Sideloading Source Flagging](#19-high-risk-sideloading-source-flagging)
   - [D. QR Code & Quishing Payload Scanner](#d-qr-code--quishing-payload-scanner)
     - [20. Client-Side QR Scanner & Payload Router](#20-client-side-qr-scanner--payload-router)
   - [E. User Interface, History & Ergonomics](#e-user-interface-history--ergonomics)
     - [21. Refined Dark Neo-Brutalist Interface](#21-refined-dark-neo-brutalist-interface)
     - [22. Session-Only In-Memory History (Tab Session)](#22-session-only-in-memory-history-tab-session)
     - [23. One-Click Sanitized Assessment Report Export](#23-one-click-sanitized-assessment-report-export)
     - [24. Pre-Loaded Curated Sample Presets](#24-pre-loaded-curated-sample-presets)
   - [F. Hybrid AI Defense Layer](#f-hybrid-ai-defense-layer)
     - [25. Local LLaMA AI Integration & Fail-Safe Fallback](#25-local-llama-ai-integration--fail-safe-fallback)
4. [Project Directory Structure](#project-directory-structure)
5. [Setup & Running Instructions](#setup--running-instructions)
6. [Automated Verification Suite (68 Tests)](#automated-verification-suite-68-tests)
7. [Assessment Limitations & Disclaimer](#assessment-limitations--disclaimer)

---

## Core Design Principles & Privacy Guarantees

- **Zero Persistence & Absolute Privacy**: Submissions are evaluated strictly in transient memory. No database is used, no logs are written to disk, and no user inputs are permanently stored.
- **Explainable Heuristics Over Black Boxes**: Every risk score is calculated from deterministic, auditable rules with human-readable explanations and verbatim evidence quotes.
- **Non-Clickable, Defanged URLs**: Malicious links submitted for analysis are rendered strictly as unclickable text and can be automatically defanged (`hxxps://`, `[.]`) to prevent accidental clicks or chat unfurls.
- **Context-Aware Negation**: Distinguishes defensive educational advice (e.g., *"Never share your OTP"*) from active attacks (*"Send your OTP immediately"*).
- **Anti-Dilution & Diminishing Returns**: Signal stacking within a rule family uses diminishing returns, while multi-link batches ensure a high-risk link is never averaged down by clean links.
- **Fail-Safe Integrity**: If an optional external check (such as LLaMA or reputation lookup) fails or times out, it is recorded as `failed` in the audit trail. Failed checks never convert a suspicious assessment into a clean verdict.

---

## Architecture Overview

```
                      +------------------------------------------+
                      |         User Input Form (React)          |
                      |  [Message]  [URL]  [App Request]  [QR]   |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |     FastAPI Backend (/api/analyze)       |
                      +------------------------------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
        +-----------------------+                     +-----------------------+
        |   Input Normalizer    |                     |   Context Classifier  |
        | - NFKC Normalization  |                     | - Negation Detector   |
        | - Zero-Width Stripping|                     | - Defensive Education |
        +-----------------------+                     +-----------------------+
                    |                                             |
                    +----------------------+----------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |       Heuristic Rule Evaluator           |
                      | - message_rules.py (phishing, coercion)  |
                      | - url_rules.py (punycode, subdomains)    |
                      | - app_rules.py (trojan permissions)      |
                      +------------------------------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
        +-----------------------+                     +-----------------------+
        |   Scoring Engine      |                     | Optional Local LLaMA  |
        | - Diminishing Returns |                     | - Ollama / llama3.1   |
        | - Verdict Thresholds  |                     | - Fail-Safe Resilient |
        +-----------------------+                     +-----------------------+
                    |                                             |
                    +----------------------+----------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |    Explainable Assessment Response       |
                      | - Verdict: Safe / Suspicious / Unable    |
                      | - Heuristic Risk Score (0 - 100)         |
                      | - Detected Indicators & Evidence Quotes  |
                      | - URL Breakdown & Defanging Controls     |
                      | - In-Memory Session History Buffer (x5)  |
                      +------------------------------------------+
```

---

## Implemented Feature Catalog & Expected Outputs

### A. Message & Social Engineering Analysis

#### 1. Sensitive Credential & OTP Harvesting
- **How It Works**: Evaluates message body for requests for one-time passwords (OTP), banking PINs, card CVVs, account passwords, or net-banking secret codes.
- **Example Input**:
  ```text
  URGENT: Your bank account will be suspended within 24 hours. Send your OTP immediately to cancel this action.
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `100 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Sensitive Credential or OTP Request` (Severity: *Critical*, Evidence: `"Send your OTP immediately to cancel this action."`)
    - `Artificial Urgency or Time Pressure` (Severity: *Medium*, Evidence: `"URGENT: Your bank account"`)
    - `Threat of Immediate Adverse Action` (Severity: *High*, Evidence: `"will be suspended within 24 hours"`)
    - `Coercive Credential Phishing Pattern` (Severity: *High*, Evidence: `"Combined indicators: Urgent or threatening demand coupled with direct credential/OTP request"`)

#### 2. Artificial Urgency & Coercive Pressure
- **How It Works**: Flags manufactured psychological coercion such as countdowns, threats of immediate service termination, or legal escalation designed to bypass critical thinking.
- **Example Input**:
  ```text
  Final notice: Your subscription will be cancelled in 15 minutes unless you verify your identity now.
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `55 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Artificial Urgency or Time Pressure` (Severity: *Medium*, Evidence: `"Final notice: Your subscription"`)
    - `Threat of Immediate Adverse Action` (Severity: *High*, Evidence: `"will be cancelled in 15 minutes"`)

#### 3. Digital-Arrest Scam & Authority Impersonation
- **How It Works**: Detects combinations of law enforcement claims (CBI, Cyber Crime Cell, Police Inspector), fake non-bailable arrest warrants, secrecy commands under the Official Secrets Act, continuous video call monitoring ("digital arrest"), and demands to transfer bail funds to government "escrow" accounts.
- **Example Input**:
  ```text
  This is Inspector Sharma from Central Bureau of Investigation CBI Cyber Crime Cell. A non-bailable arrest warrant has been registered against you for an illegal customs parcel. You are placed under digital arrest. Transfer the verification bail deposit immediately via bank transfer to the government escrow account. Keep this strictly confidential under Official Secrecy Act and do not disconnect this video call.
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `100 / 100`
  - **Category**: `Digital-arrest & authority impersonation`
  - **Triggered Indicators**:
    - `Artificial Urgency or Time Pressure` (Severity: *Medium*, Evidence: `"bail deposit immediately"`)
    - `Threat of Immediate Adverse Action` (Severity: *High*, Evidence: `"non-bailable arrest warrant has been registered"`)
    - `Claim of Official or Institutional Authority` (Severity: *High*, Evidence: `"Inspector Sharma from Central Bureau of Investigation CBI Cyber Crime Cell"`)
    - `Demand for Direct Money or Account Transfer` (Severity: *High*, Evidence: `"bail deposit immediately via bank transfer to the government escrow account"`)
    - `Pressure for Secrecy and Isolation` (Severity: *High*, Evidence: `"strictly confidential under Official Secrecy Act and do not disconnect this video call"`)
    - `Classic Digital-Arrest Scam Pattern` (Severity: *Critical*, Evidence: `"Combined indicators: Institutional authority claim + adverse threat + financial/secrecy coercion"`)

#### 4. Personal Mobile Number & Unofficial SMS Header Anomaly
- **How It Works**: Checks whether an alert claiming to be an official bank, credit card, or utility notice arrives from a personal 10-digit mobile number or standard consumer mobile prefix (`+91 ...`, `+1 (555)...`, `9876543210:`) rather than a registered enterprise alphanumeric sender ID (e.g. `VK-HDFCBK`). Benign peer-to-peer chats are excluded.
- **Example Input**:
  ```text
  +91 9876543210: Dear customer, your bank account has been blocked due to suspicious activity. Send your OTP immediately to restore service.
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `100 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Sensitive Credential or OTP Request` (Severity: *Critical*, Evidence: `"Send your OTP immediately"`)
    - `Artificial Urgency or Time Pressure` (Severity: *Medium*, Evidence: `"immediately to restore service"`)
    - `Alert Originated from Personal Mobile Number` (Severity: *High*, Evidence: `"+91 9876543210:"`)
    - `Coercive Credential Phishing Pattern` (Severity: *High*, Evidence: `"Combined indicators: Urgent or threatening demand coupled with direct credential/OTP request"`)

#### 5. Courier & Customs Contraband Parcel Seizure Extortion
- **How It Works**: Flags fraudulent parcel seizure lures alleging that a FedEx, DHL, or Blue Dart package in the recipient's name containing narcotics, illegal passports, or contraband has been detained at customs or an airport cargo terminal.
- **Example Input**:
  ```text
  Your FedEx courier parcel containing illegal contraband narcotics has been seized by customs clearance authorities at Mumbai airport. Call our customs verification cell immediately.
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `55 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Artificial Urgency or Time Pressure` (Severity: *Medium*, Evidence: `"immediately"`)
    - `Customs or Courier Contraband Parcel Seizure Claim` (Severity: *High*, Evidence: `"FedEx courier parcel containing illegal contraband narcotics has been seized"`)

#### 6. Utility & Electricity Disconnection Threats
- **How It Works**: Detects urgency-based utility scams claiming that electricity, water, or telecom services will be disconnected tonight at a specific hour (e.g. 9:30 PM) due to an unpaid bill, urging the victim to call an unauthorized mobile number.
- **Example Input**:
  ```text
  Dear consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid electricity bill. Please call our power officer immediately at 9876543210 to avoid disconnection.
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `90 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Artificial Urgency or Time Pressure` (Severity: *Medium*, Evidence: `"immediately"`)
    - `Claim of Official or Institutional Authority` (Severity: *High*, Evidence: `"power officer"`)
    - `Imminent Utility or Telecom Disconnection Threat` (Severity: *High*, Evidence: `"electricity power will be disconnected tonight at 9:30 PM"`)

#### 7. Educational Awareness & Defensive Negation Handling
- **How It Works**: Evaluates linguistic context to detect defensive negations (*"never share"*, *"do not disclose"*, *"awareness tip"*). This prevents security advice messages from triggering false alarms.
- **Example Input**:
  ```text
  Cybersecurity Awareness Tip: Never share your OTP, banking password, or debit card PIN with anyone. Official bank staff will never ask you to disclose verification codes.
  ```
- **Expected Output**:
  - **Verdict**: `Appears safe`
  - **Risk Score**: `0 / 100`
  - **Category**: `Benign content`
  - **Summary**: *"No meaningful suspicious indicators were detected across completed checks (Score: 0/100)."*
  - **Triggered Indicators**: None (Safely bypassed via educational negation detection)

#### 8. Zero-Width Character & Unicode Obfuscation Stripping
- **How It Works**: Strips hidden zero-width spaces (`\u200B`), non-breaking spaces, zero-width joiners (`\u200D`), and directional overrides before rule evaluation, defeating evasion tactics.
- **Example Input**:
  ```text
  O​T​P​ ​v​e​r​i​f​i​c​a​t​i​o​n​ ​r​e​q​u​i​r​e​d​:​ ​p​l​e​a​s​e​ ​s​e​n​d​ ​y​o​u​r​ ​p​a​s​s​w​o​r​d
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `45 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Sensitive Credential or OTP Request` (Severity: *Critical*, Evidence: `"please send your password"`)

---

### B. URL & Web Link Analysis

#### 9. Misleading Brand Subdomains & Lookalike Routing
- **How It Works**: Parses the fully qualified domain name (FQDN) using registrable domain extraction. If a trusted brand name (e.g. `paypal`, `microsoft`, `apple`, `google`, `netflix`) appears in a subdomain prefix of an unrelated foreign root domain, it is flagged.
- **Example Input**:
  ```text
  https://paypal.com.account-verification-portal.xyz/secure/login
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `60 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Deceptive Brand Impersonation in Subdomain` (Severity: *High*, Evidence: `"Subdomain 'paypal.com' impersonates brand 'paypal' on unrelated root domain 'account-verification-portal.xyz'"`)
    - `High-Risk or Abused Top-Level Domain (TLD)` (Severity: *Medium*, Evidence: `"Domain suffix '.xyz' is a high-risk TLD"`)
  - **URL Breakdown**: Registrable root extracted as `account-verification-portal.xyz`, highlighting the deceptive `paypal.com` subdomain lure.

#### 10. Confusable Homoglyphs & Punycode (IDN) Attacks
- **How It Works**: Detects internationalized domain names (IDNs) beginning with `xn--` or domains mixing Cyrillic/Greek lookalike characters with Latin characters to impersonate legitimate brand URLs.
- **Example Input**:
  ```text
  https://xn--appl-43d.com/support/login
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `40 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Lookalike Homoglyph or Punycode Characters` (Severity: *High*, Evidence: `"Hostname 'xn--appl-43d.com': Punycode internationalized domain resolves to: аappl.com"`)

#### 11. Raw IP Address Hostnames
- **How It Works**: Identifies URLs that use an IPv4 or IPv6 address directly instead of a registered domain name, a standard tactic used by disposable attack infrastructure to bypass domain-based blocklists.
- **Example Input**:
  ```text
  http://192.168.1.105:8080/update/banking-app.apk
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `75 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Direct IP Address Hostname` (Severity: *High*, Evidence: `"192.168.1.105"`)
    - `Direct App or Executable File Download Link` (Severity: *High*, Evidence: `".apk"`)

#### 12. Embedded Credentials with `@` Obfuscation
- **How It Works**: Flags URLs that contain an `@` symbol in the authority component (`https://legit-brand.com@attacker-server.com/`). Browsers treat everything before `@` as username credentials and route traffic to the server listed *after* `@`.
- **Example Input**:
  ```text
  https://google.com@evil-phishing-host.com/login
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `45 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Misleading Credentials or '@' Symbol in URL Authority` (Severity: *Critical*, Evidence: `"google.com@"`)

#### 13. Dangerous URI Schemes & Executable Downloads
- **How It Works**: Flags non-standard, dangerous protocols such as `javascript:`, `data:`, `file:`, or `blob:`, as well as direct links to compiled executable packages (`.apk`, `.exe`, `.scr`, `.bat`, `.cmd`, `.ps1`).
- **Example Input**:
  ```text
  https://storage-cloud-cdn.net/files/system_update_v4.apk
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `40 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `Direct App or Executable File Download Link` (Severity: *High*, Evidence: `".apk"`)

#### 14. URL Shortener Detection without False Alarms
- **How It Works**: Identifies link shortening services (e.g. `bit.ly`, `tinyurl.com`, `t.co`). If a shortener is present alone without other indicators, it issues an informational finding and keeps the verdict `Appears safe` ($< 25$) to avoid false alarms.
- **Example Input**:
  ```text
  https://bit.ly/3xSampleCleanLink
  ```
- **Expected Output**:
  - **Verdict**: `Appears safe`
  - **Risk Score**: `15 / 100`
  - **Category**: `Phishing & deceptive links`
  - **Triggered Indicators**:
    - `URL Shortener Masking Actual Destination` (Severity: *Low*, Evidence: `"Known shortener domain: 'bit.ly'"`)

#### 15. Multi-URL Batch Scanning with Anti-Dilution
- **How It Works**: Evaluates multiple submitted URLs simultaneously. The overall assessment uses the **highest risk URL** to determine the verdict rather than averaging the scores, preventing attackers from hiding a malicious link inside a list of clean links.
- **Example Input**:
  ```text
  Check these resources:
  1. https://docs.python.org/3/
  2. https://paypal.com.account-verification-portal.xyz/secure/login
  3. https://en.wikipedia.org/wiki/Main_Page
  ```
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `60 / 100` (Governed by URL #2, not averaged down by #1 and #3)
  - **URL Breakdown**: Displays individual rows for all 3 links with their respective scores.

#### 16. Automatic URL Defanging & Sanitized Copy
- **How It Works**: Protects users from accidental clicks by displaying URLs as non-clickable plain text and offering an instant **"Defang URLs"** toggle (`https://` $\to$ `hxxps://`, `.` $\to$ `[.]`).
- **Expected Output**:
  ```text
  Original: https://paypal.com.phish.xyz/login
  Defanged: hxxps://paypal[.]com[.]phish[.]xyz/login
  ```

---

### C. Mobile App Request & Toxic Permission Analysis

#### 17. Toxic Banking Trojan Permission Combinations
- **How It Works**: Detects dangerous permission combinations typically found in Android banking trojans, specifically `BIND_ACCESSIBILITY_SERVICE` combined with SMS intercept privileges (`READ_SMS`, `RECEIVE_SMS`) and overlay privileges (`SYSTEM_ALERT_WINDOW`).
- **Example Input**:
  - **Content**: `"Please install this Battery Saver app to improve your battery life."`
  - **Claimed App Purpose**: `Battery Optimizer`
  - **Installation Source**: `Telegram Channel APK Download`
  - **Requested Permissions**:
    - `BIND_ACCESSIBILITY_SERVICE`
    - `READ_SMS`
    - `RECEIVE_SMS`
    - `SYSTEM_ALERT_WINDOW`
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `100 / 100`
  - **Category**: `Suspicious app installation & permissions`
  - **Triggered Indicators**:
    - `Critical Banking Trojan Permission Combination` (Severity: *Critical*, Evidence: `"Requested privileges: Accessibility Service and SMS access"`)
    - `Suspicious Mismatch Between Claimed Purpose and Permissions` (Severity: *High*, Evidence: `"Claimed purpose 'battery optimizer' requests disproportionate permissions: Accessibility, SMS"`)
    - `Untrusted Installation Source with Sensitive Permissions` (Severity: *High*, Evidence: `"Installation from untrusted channel with sensitive requests: Accessibility, SMS"`)

#### 18. Claimed App Purpose vs. Requested Permission Mismatch
- **How It Works**: Evaluates whether requested permissions align with the application's stated functionality. Flags simple tools (calculators, flashlights, wallpapers) that request device administration or telephony access.
- **Example Input**:
  - **Content**: `"Scientific calculator tool with unit converter."`
  - **Claimed App Purpose**: `Calculator`
  - **Installation Source**: `Direct APK Download`
  - **Requested Permissions**:
    - `READ_SMS`
    - `BIND_DEVICE_ADMIN`
- **Expected Output**:
  - **Verdict**: `Suspicious`
  - **Risk Score**: `100 / 100`
  - **Category**: `Suspicious app installation & permissions`
  - **Triggered Indicators**:
    - `Suspicious Mismatch Between Claimed Purpose and Permissions` (Severity: *High*, Evidence: `"Claimed purpose 'calculator' requests disproportionate permissions: SMS, Device Admin"`)
    - `High-Privilege Device Administrator Request` (Severity: *High*, Evidence: `"Application requests Device Administrator privilege"`)
    - `Untrusted Installation Source with Sensitive Permissions` (Severity: *High*, Evidence: `"Installation from untrusted channel with sensitive requests: SMS, Device Admin"`)

#### 19. High-Risk Sideloading Source Flagging
- **How It Works**: Identifies untrusted installation sources outside official app stores, including direct APK downloads, Telegram channels, Discord servers, and file-sharing mirrors.
- **Example Input**:
  - **Installation Source**: `Telegram Channel Direct APK`
- **Expected Output**:
  - Flags `High-Risk Sideloading Source` as a contributing risk indicator.

---

### D. QR Code & Quishing Payload Scanner

#### 20. Client-Side QR Scanner & Payload Router
- **How It Works**: Features an in-browser QR code scanner using `jsQR`. Users can point their webcam or upload a static QR image file (`.png`, `.jpg`, `.webp`).
- **Processing Flow**:
  1. Image is processed directly in the browser via HTML5 Canvas (no image data is sent to the server).
  2. The decoded text/URL payload is extracted.
  3. The payload is automatically routed into the analysis engine as either a URL or Message.
- **Example Test**:
  - Upload a QR code containing `https://paypal.com.secure-update.xyz/login`.
- **Expected Output**:
  - **Decoded Output**: Payload extracted instantly.
  - **Dispatched Assessment**: Displays Verdict `Suspicious` (Risk 60) with defanged URL controls.

---

### E. User Interface, History & Ergonomics

#### 21. Refined Dark Neo-Brutalist Interface
- **Design System**: Strict 2px borders, high-contrast dark surfaces (`#0C0C0E` background, `#161619` cards), solid `#000` drop-shadow offsets (`shadow-[4px_4px_0px_#000]`), and deliberate typography.
- **Zero AI Marketing Filler**: Clean, functional microcopy. Free of fake live counters, fabricated detection statistics, or simulated terminal outputs.
- **Accessibility**: High-contrast labels, clear focus states, and qualified verdicts (`Appears safe`, `Suspicious`, `Unable to assess`).

#### 22. Session-Only In-Memory History (Tab Session)
- **How It Works**: Stores up to the last 5 analyses in React component memory.
- **Key Properties**:
  - **Zero Storage**: Uses no `localStorage`, `sessionStorage`, or cookies. Closing or reloading the tab purges the history completely.
  - **Interactive Chips**: Displays input type (`MSG`, `URL`, `APP`, `QR`), text snippet, verdict chip, and score.
  - **Fast Switching**: Clicking any chip restores its inputs and assessment view instantly.
  - Includes a one-click **"Clear history"** button.

#### 23. One-Click Sanitized Assessment Report Export
- **How It Works**: The **"Copy summary"** button formats the full analysis into a clean plain-text report with all URLs automatically defanged, preventing accidental link previews when shared across Slack, Teams, or WhatsApp.
- **Generated Report Format**:
  ```text
  ========================================
  CYBERSHIELD SECURITY ASSESSMENT REPORT
  ========================================
  Verdict: SUSPICIOUS
  Risk Score: 70 / 100
  Threat Category: Phishing & deceptive links
  Summary: The submitted content exhibits indicators consistent with phishing...

  Analyzed Links (Defanged):
    * hxxps://paypal[.]com[.]phish[.]xyz (Risk: 60/100)

  Detected Indicators:
    * [CRITICAL] Sensitive Credential or OTP Request
    * [HIGH] Unofficial Mobile Sender for Institutional Alert

  Limitation Notice:
  This assessment is heuristic and based on the submitted content and available checks.
  It does not guarantee safety or confirm malicious intent.
  ========================================
  ```

#### 24. Pre-Loaded Curated Sample Presets
- Provides 11 one-click test cases directly in the UI under **"Load sample"**:
  1. *Urgent phishing SMS* (Suspicious)
  2. *Personal mobile bank SMS* (Suspicious)
  3. *FedEx customs seizure* (Suspicious)
  4. *Power disconnection threat* (Suspicious)
  5. *Digital-arrest extortion* (Suspicious)
  6. *Benign work message* (Safe control)
  7. *Defensive security tip* (Safe control)
  8. *Deceptive brand subdomain* (Suspicious)
  9. *Legitimate documentation URL* (Safe control)
  10. *Banking trojan permissions* (Suspicious)
  11. *Calculator purpose mismatch* (Suspicious)

---

### F. Hybrid AI Defense Layer

#### 25. Local LLaMA AI Integration & Fail-Safe Fallback
- **How It Works**: Supports an optional secondary semantic analysis layer via a local **Ollama** instance (`llama3.1:8b`) or any OpenAI-compatible API.
- **Heuristic Core Takes Precedence**: The deterministic rules engine always runs first. LLaMA provides structured nuance on psychological coercion.
- **Fail-Safe Integrity**: If Ollama is offline or times out:
  - The audit report marks `checks.ai_semantic_analysis: "failed"`.
  - The deterministic rules engine delivers the final score and verdict without interruption.
  - **A failed AI check never downgrades risk or converts a suspicious finding into a clean verdict.**

---

## Project Directory Structure

```
.
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI application, CORS, rate limiting, static hosting
│   │   ├── config.py                  # Environment settings, thresholds, and Ollama configuration
│   │   ├── models/
│   │   │   ├── requests.py            # Pydantic request schemas (AnalyzeRequest, AppContext)
│   │   │   └── responses.py           # Response models (AnalyzeResponse, Finding, UrlFinding)
│   │   └── engine/
│   │       ├── validator.py           # Length limits, input sanitization, scheme checks
│   │       ├── normalizer.py          # NFKC normalization, zero-width character stripping
│   │       ├── context_classifier.py  # Defensive educational negation handler
│   │       ├── url_parser.py          # Offline FQDN extractor, punycode & IP parser
│   │       ├── scorer.py              # 0-100 heuristic scoring & diminishing returns
│   │       ├── reputation.py          # Optional external reputation interface
│   │       ├── ai_analyzer.py         # LLaMA semantic analyzer via Ollama/OpenAI API
│   │       ├── coordinator.py         # Orchestration pipeline
│   │       └── rules/
│   │           ├── base.py            # Rule definition, Severity, ThreatCategory enums
│   │           ├── registry.py        # Centralized rule registry
│   │           ├── message_rules.py   # Phishing, digital arrest, courier, utility, sender rules
│   │           ├── url_rules.py       # Lookalike domain, IP, executable download rules
│   │           └── app_rules.py       # Trojan permission combinations & purpose mismatch rules
│   └── tests/
│       ├── test_messages.py           # Benign, phishing, educational negation, digital arrest, courier, utility
│       ├── test_urls.py               # Documentation URLs, subdomains, homoglyphs, multi-URL batches
│       ├── test_app_requests.py       # Trojan permissions, purpose mismatches, safe apps
│       ├── test_llama_ai.py           # LLaMA disabled, active, and fail-safe resilience tests
│       ├── test_validation_security.py# Length boundaries, whitespace, script injection, scheme security
│       ├── test_reputation_and_scoring.py # Score consistency and provider failure tests
│       └── test_comprehensive_matrix.py   # Matrix covering all security criteria
├── frontend/
│   ├── src/
│   │   ├── types/api.ts               # TypeScript data types
│   │   ├── services/api.ts            # API client with health checking and error handling
│   │   ├── utils/
│   │   │   └── defang.ts              # URL defanging (hxxps://, [.]) utilities
│   │   ├── components/
│   │   │   ├── Header.tsx             # Header bar with real-time status and dark mode toggle
│   │   │   ├── InputTabs.tsx          # Tab switcher (Message, URL, App, QR)
│   │   │   ├── SampleSelector.tsx     # One-click test scenarios
│   │   │   ├── SessionHistory.tsx     # In-memory session history bar (last 5 checks)
│   │   │   ├── MessageInput.tsx       # Message text input with character counter
│   │   │   ├── UrlInput.tsx           # Multi-URL input with safety instructions
│   │   │   ├── AppRequestInput.tsx    # App request form with permission tag selector
│   │   │   ├── QrCodeInput.tsx        # Camera/upload client-side QR scanner
│   │   │   ├── VerdictCard.tsx        # Verdict banner, risk gauge, summary, report copy button
│   │   │   ├── RiskMeter.tsx          # Visual 0-100 risk score meter
│   │   │   ├── IndicatorsList.tsx     # Detected indicators list with severity badges & evidence
│   │   │   ├── UrlBreakdown.tsx       # URL structural table with defanging toggle & copy
│   │   │   ├── ChecksSummary.tsx      # Completed, skipped, and failed checks audit trail
│   │   │   ├── LimitationsNotice.tsx  # Mandatory assessment limitations notice
│   │   │   └── TechnicalDetails.tsx   # Collapsible engine diagnostics drawer
│   │   ├── App.tsx                    # Main application orchestration
│   │   └── index.css                  # Brutalist styles and Tailwind directives
│   ├── package.json
│   └── vite.config.ts
├── SCORING.md                         # Mathematical breakdown of heuristic scoring
└── README.md                          # Comprehensive project documentation
```

---

## Setup & Running Instructions

### Prerequisites
- Python 3.9+
- Node.js 18+ and npm
- (Optional) [Ollama](https://ollama.ai) with `llama3.1:8b` for local AI analysis

---

### Step 1: Backend Environment Setup

```bash
# 1. Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r backend/requirements.txt
```

---

### Step 2: Frontend Build

```bash
# Compile the React + TypeScript frontend into backend-served static assets
npm --prefix frontend install
npm --prefix frontend run build
```

---

### Step 3: Launch the Application

#### Production Mode (FastAPI serves both API and React frontend)
```bash
source .venv/bin/activate
PYTHONPATH=backend uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Open your browser at: **`http://localhost:8000`**

#### Development Mode (With Hot-Reloading)
- **Terminal 1 (Backend API):**
  ```bash
  source .venv/bin/activate
  PYTHONPATH=backend uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
  ```
- **Terminal 2 (Vite Dev Server):**
  ```bash
  npm --prefix frontend run dev
  ```
  Open your browser at: **`http://localhost:5173`**

---

### Step 4: (Optional) Local LLaMA AI Integration

To enable offline semantic analysis using your local Ollama installation:

1. Confirm your model is available in Ollama:
   ```bash
   ollama list
   # e.g., llama3.1:8b
   ```
2. Set the configuration in `backend/.env` (or environment variables):
   ```bash
   LLAMA_ENABLED=true
   LLAMA_PROVIDER=ollama
   LLAMA_BASE_URL=http://127.0.0.1:11434
   LLAMA_MODEL=llama3.1:8b
   ```
3. Restart the backend service. If Ollama is unavailable, Inspectra automatically falls back to deterministic heuristic evaluation with zero disruption.

---

## Automated Verification Suite (68 Tests)

The test suite validates detection accuracy, context awareness, boundary handling, and security resilience across all 68 automated test cases:

```bash
source .venv/bin/activate
PYTHONPATH=backend pytest backend/tests -v
```

### Key Test Categories Verified:
- **`test_messages.py`** (7 tests):
  - `test_benign_message`: Confirms benign messages score $< 25$ (`appears_safe`).
  - `test_suspicious_credential_request`: Validates OTP and credential theft detection.
  - `test_educational_text_mentioning_phishing`: Ensures educational advice is not falsely flagged.
  - `test_digital_arrest_authority_impersonation`: Validates composite digital arrest scoring ($100/100$).
  - `test_unofficial_sender_mobile_number_detection`: Verifies personal mobile sender anomaly logic.
  - `test_customs_courier_contraband_parcel_scam`: Confirms contraband courier parcel scam detection.
  - `test_utility_electricity_disconnection_threat`: Validates evening power cut threat detection.
- **`test_urls.py`** (8 tests):
  - `test_legitimate_url_with_long_path`: Confirms documentation URLs are not penalized.
  - `test_misleading_subdomain`: Flags brand spoofing across foreign subdomains.
  - `test_raw_ip_address_host`: Identifies direct IP hostnames.
  - `test_homoglyph_lookalike_domain`: Detects Punycode (`xn--`) and confusable homoglyphs.
  - `test_embedded_credentials_at_symbol`: Detects `@` character authority diversion.
  - `test_multiple_urls_no_averaging_away`: Guarantees a malicious URL in a batch is never averaged down.
  - `test_bare_ip_and_short_host_url_sufficiency`: Validates raw IPs and short hostnames are sufficient for URL analysis.
  - `test_schemeless_url_postfilter_email_and_sentence_period`: Verifies scheme-less filter skips emails and sentence boundary tokens.
- **`test_app_requests.py`** (4 tests):
  - `test_app_request_banking_trojan_permissions`: Detects Accessibility + SMS privilege clusters.
  - `test_app_request_purpose_mismatch`: Detects utility app purpose vs. permission mismatches.
  - `test_app_request_insufficient_context`: Gracefully handles minimal app contexts.
  - `test_benign_app_text_word_boundary_no_false_positives`: Prevents false positives on benign app descriptions.
- **`test_llama_ai.py`** (5 tests):
  - Validates active LLaMA detection, disabled state reporting, malformed output resilience, and Medium-severity scoring.
- **`test_validation_security.py`** (10 tests):
  - Verifies rejection of submissions over 10,000 characters, whitespace handling, HTML/script injection resilience, dangerous URL scheme rejection (422), rate limit static route exemption, and removal of unused SAFE_THRESHOLD.
- **`test_reputation_and_scoring.py`** (5 tests):
  - Confirms external provider failure reporting, diminishing returns formula, verdict threshold consistency, sticky multi-URL reputation failure, and insufficient input limitations.
- **`test_audit_findings_10_to_14.py`** (6 tests):
  - `test_finding_10_all_caps_domain_not_dropped`: Confirms all-caps domains (`HDFC-UPDATE.COM`) are not dropped by sentence period filters.
  - `test_finding_11_android_permission_prefix_and_human_labels`: Ensures manifest names (`android.permission.READ_SMS`) and human labels trigger detections.
  - `test_finding_12_suspicious_wins_over_unable_to_assess`: Confirms suspicious heuristic evidence takes precedence over failed external checks.
  - `test_finding_13_ai_string_false_is_not_suspicious`: Ensures string `"false"` from LLM does not trigger suspicious findings.
  - `test_finding_14_benign_chat_app_not_flagged`: Prevents benign chat apps from being flagged for bare "mega" or "text messages".
  - `test_429_response_carries_cors_headers`: Validates CORS headers are present on 429 rate limit responses.
- **`test_comprehensive_matrix.py`** (23 tests):
  - Comprehensive matrix covering full coverage across phishing SMS, digital arrest, QR quishing, dangerous URI schemes, batch URLs, and exact 10,000-character boundary conditions.

---

## Assessment Limitations & Disclaimer

> **Mandatory Notice**:
> *“This assessment is based on the submitted content and available checks. It does not guarantee safety or confirm malicious intent.”*

- **Heuristic Scope**: Risk scores reflect the presence and severity of observable heuristic patterns; they do not represent a statistical guarantee of fraud or legal evidence.
- **Zero Dynamic Execution**: Inspectra never executes binary files, downloads APKs, or connects to external server runtimes.
- **No Identity Verification**: The assessment does not cryptographically authenticate the true sender of an SMS or email beyond analyzing header text patterns.
- **Manifest-Level App Assessment**: Mobile app evaluations inspect declared permission strings and contextual descriptions; they do not decompile or execute APK DEX code.
