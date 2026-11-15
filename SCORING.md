# Inspectra — Heuristic Risk Scoring Methodology

## 1. Overview and Core Philosophy

Inspectra computes an explainable heuristic risk score between **0 and 100** based on detected security indicators.

> **Fundamental Principle**:
> The risk score reflects the density and severity of detected deceptive patterns, coercive signals, and privilege anomalies in the submitted content. It is **not** a statistically validated probability of fraud or criminal guilt, nor does a low score guarantee safety.

---

## 2. Risk Categories

Inspectra categorizes threats into three core domains:

1. **`phishing_and_deceptive_links`**
   - Fake login portals, deceptive subdomains, embedded `@` credential lures, homoglyph / punycode domains, disposable high-risk TLDs, and urgent credential/OTP harvesting.
2. **`digital_arrest_and_authority_impersonation`**
   - Impersonation of judicial, law enforcement, or regulatory entities (Police, CBI, Customs, ED, Courts, TRAI) coupled with arrest threats, demands for immediate fund transfer / bail deposits, and isolation/secrecy pressure.
3. **`suspicious_app_installation`**
   - Untrusted distribution channels (sideloading direct APKs), toxic permission combinations (Accessibility Service + SMS), and mismatches between claimed purpose (e.g., simple calculator or flashlight) and requested high-risk permissions.

---

## 3. Severity Weights & Base Contributions

Each rule is assigned a severity tier with a calibrated base score contribution:

| Severity Tier | Base Score Contribution | Description | Examples |
|---|---|---|---|
| **Critical** | 30 – 60 points | Immediate, high-consequence threat indicators | Dangerous URI schemes (60), Accessibility + SMS trojan pattern (50), direct OTP harvesting (45), embedded `@` credentials (45), device protection disable instructions (45), composite digital arrest pattern (30) |
| **High** | 25 – 40 points | Strong deceptive or coercive indicators | Deceptive brand subdomains (40), homoglyphs (40), direct executable downloads (40), app purpose mismatch (40), remote access software requests (40), authority impersonation (35), arrest threats (35), payment transfer demands (35), personal mobile sender (35), customs contraband claim (35), utility power cut threat (35), raw IP host (35), device admin (35), untrusted sideloading source (35), overlay combo (35), secrecy pressure (30), credential phishing synergy (25), AI semantic detection (25) |
| **Medium** | 15 – 25 points | Secondary pressure or suspicious structure | Obfuscated/double-URL encoding (25), artificial urgency phrases (20), disposable high-risk TLDs (20), AI semantic verification (15) |
| **Low** | 0 – 15 points | Weak, informational, or baseline indicators | Generic URL shorteners concealing destination (15), app context insufficient notice (0) |

---

## 4. Signal Families & Diminishing Returns (Anti-Double Counting)

To prevent inflating scores through repetitive keywords (e.g., repeating *"urgent right now immediately within 24 hours"*), rules belong to **Signal Families**:
- `credentials`
- `urgency`
- `threat`
- `authority`
- `payment`
- `secrecy`
- `remote_access`
- `security_tamper`
- `dangerous_permissions`
- `purpose_mismatch`
- `device_admin`
- `installation_source`
- `overlay_combo`
- `sender_identity`
- `customs_parcel`
- `utility_threat`
- `brand_spoof`
- `host_type`
- `homoglyph`
- `payload`
- `shortener`
- `tld`
- `encoding`
- `scheme_type`
- `url_obfuscation`
- `synergy_digital_arrest`
- `synergy_phishing`
- `ai_semantic`
- `context_status`

### Aggregation Formula within Families:
For any family $F$ with rule contributions $s_1 \ge s_2 \ge \dots \ge s_k$:
$$\text{FamilyScore}(F) = s_1 + \sum_{i=2}^{k} \lfloor 0.20 \times s_i \rfloor$$

The dominant indicator in each family contributes 100% of its weight, while secondary rules in the same family provide only 20% contribution.

---

## 5. Multi-Vector Synergy Modifiers

Attack patterns often combine seemingly disparate tactics. Inspectra detects multi-vector combinations and applies specialized synergy bonuses:

- **Digital-Arrest Synergy**:
  Triggered when `Authority Claim` + `Adverse Threat` + (`Payment Demand` OR `Secrecy Pressure`) are detected together.
  - Adds composite indicator: `digital_arrest_composite_pattern` (+30 points, Critical).
- **Credential Phishing Synergy**:
  Triggered when `Urgent Demand` OR `Adverse Threat` is paired directly with an active `Credential / OTP Request`.
  - Adds composite indicator: `credential_phishing_composite` (+25 points, High).

---

## 6. Multi-URL Scoring Logic

When multiple URLs are analyzed simultaneously:
- **No Averaging Down**: Inspectra never averages away a malicious link with benign links.
- **Score Calculation**:
  $$\text{UrlRiskScore} = \max(\text{URL}_1, \dots, \text{URL}_n) + \min(15, 5 \times (N_{\text{suspicious}} - 1))$$
- Every URL is parsed and displayed individually in the structural breakdown with its own risk score.

---

## 7. Verdict Determination

| Verdict | Condition | Interpretation |
|---|---|---|
| **`appears_safe`** | Risk score $< 25$ AND no High/Critical indicators AND all checks completed | No meaningful suspicious indicators detected across available checks. |
| **`suspicious`** | Risk score $\ge 25$ OR any High/Critical indicator detected | The submission exhibits suspicious indicators or known attack patterns. Heuristic evidence takes precedence over external check failures. |
| **`unable_to_assess`** | Input is insufficient ($< 4$ characters or empty) OR an essential external check failed on otherwise-clean content | Uncertainty state due to insufficient data or unavailable check. Never converted to a clean verdict; never suppresses detected suspicious evidence. |

### Precedence Rule: Suspicious Evidence Prevails
In accordance with fail-safe security principles, if heuristic analysis identifies suspicious evidence (score $\ge 25$ or High/Critical indicators), the verdict remains **`suspicious`** even if an external provider (such as VirusTotal or local LLaMA) times out or fails. External check failures only trigger **`unable_to_assess`** when the content would otherwise evaluate as safe, ensuring provider outages never mask malicious activity.

---

## 8. Limitations & Safeguards

1. **Context Awareness**: Defensive advice such as *"Never share your OTP"* is detected via negation/educational analysis and does not trigger phishing rules.
2. **Safe URL Preservation**: Legitimate long paths on trusted domains (e.g., documentation or tracking query params) are not penalized for length alone.
3. **No Dynamic Execution**: Inspectra never fetches, follows, executes, or decompiles untrusted code or remote targets.
4. **Mandatory Disclaimer**:
   > *“This assessment is based on the submitted content and available checks. It does not guarantee safety or confirm malicious intent.”*
