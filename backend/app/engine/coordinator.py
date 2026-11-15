import asyncio
from typing import List, Dict
from fastapi import HTTPException, status
from app.config import settings
from app.models.requests import AnalyzeRequest, InputType
from app.models.responses import (
    AnalyzeResponse,
    Verdict,
    Finding,
    UrlFinding,
    Severity,
)
from app.engine.validator import validate_input, is_content_insufficient
from app.engine.normalizer import normalize_text
from app.engine.url_parser import (
    extract_urls_from_text,
    parse_url_string,
    ParsedUrl,
)
from app.engine.rules.message_rules import analyze_message_content
from app.engine.rules.url_rules import analyze_parsed_url, build_url_finding_summary
from app.engine.rules.app_rules import analyze_app_request
from app.engine.scorer import (
    calculate_risk_score,
    determine_verdict,
    generate_analysis_summary,
)
from app.engine.reputation import reputation_service
from app.engine.ai_analyzer import llama_analyzer


async def process_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Main analysis pipeline:
    1. Input validation & sufficiency check
    2. Text normalization
    3. Context & rule evaluations across message, URL, and app domains
    4. Heuristic risk scoring with diminishing returns
    5. Verdict and summary generation
    6. Response packaging with transparent check status and mandatory limitations
    """
    raw_content = request.content
    input_type = request.input_type

    # 0. Input validation & scheme checks
    is_valid, validation_msg = validate_input(input_type, raw_content)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=validation_msg or "Invalid input.",
        )

    # Track check statuses
    checks: Dict[str, str] = {
        "text_analysis": "not_applicable",
        "url_structure": "not_applicable",
        "reputation": "not_configured",
        "ai_semantic_analysis": "not_configured",
    }
    if input_type == InputType.APP_REQUEST:
        checks["app_permission_analysis"] = "completed"

    limitations = [
        "This assessment is based on the submitted content and available checks. It does not guarantee safety or confirm malicious intent.",
        "This assessment does not verify the sender's identity or inspect remote server infrastructure.",
        "The risk score is heuristic, not a statistically validated probability of fraud.",
    ]
    if input_type == InputType.APP_REQUEST:
        limitations.append(
            "App assessment evaluates supplied text and permissions only, not compiled binary bytecode or runtime behavior."
        )

    # Check for empty or insufficient input
    if is_content_insufficient(raw_content, input_type):
        return AnalyzeResponse(
            verdict=Verdict.UNABLE_TO_ASSESS,
            risk_score=0,
            category="insufficient_input",
            summary="Submitted content contains insufficient meaningful information to assess security risk.",
            findings=[
                Finding(
                    rule_id="input_insufficient_length",
                    name="Insufficient Content",
                    severity=Severity.LOW,
                    evidence=raw_content[:50] if raw_content else "(empty)",
                    explanation="Inspectra requires at least a few words or a valid URL to identify indicators.",
                )
            ],
            urls=[],
            checks={
                "text_analysis": "skipped",
                "url_structure": "skipped",
                "reputation": "not_configured",
                "ai_semantic_analysis": "skipped",
            },
            limitations=limitations,
            engine_version=settings.ENGINE_VERSION,
        )

    normalized = normalize_text(raw_content)
    all_findings: List[Finding] = []
    url_findings_list: List[UrlFinding] = []

    # 1. URL Extraction & Parsing
    extracted_urls: List[str] = []
    if input_type == InputType.URL:
        # User explicitly provided URL(s)
        extracted_urls = extract_urls_from_text(normalized)
        if not extracted_urls:
            # Maybe a raw domain was provided without scheme
            extracted_urls = [normalized.strip()]
    else:
        # Extract any embedded links in message or app request
        extracted_urls = extract_urls_from_text(normalized)

    # Analyze URLs if present
    if extracted_urls:
        checks["url_structure"] = "completed"
        reputation_statuses: List[str] = []
        for url_str in extracted_urls[:10]:  # Limit to 10 URLs per submission
            parsed: ParsedUrl = parse_url_string(url_str)
            if parsed:
                findings_for_url, url_score = analyze_parsed_url(parsed)
                url_finding = build_url_finding_summary(parsed, findings_for_url, url_score)
                url_findings_list.append(url_finding)
                all_findings.extend(findings_for_url)

                # Optional reputation check
                rep_status, rep_findings = await reputation_service.check_url_reputation(parsed.raw_url)
                reputation_statuses.append(rep_status)
                if rep_findings:
                    all_findings.extend(rep_findings)

        if "failed" in reputation_statuses:
            checks["reputation"] = "failed"
        elif any(s == "completed" for s in reputation_statuses):
            checks["reputation"] = "completed"
        elif reputation_statuses:
            checks["reputation"] = reputation_statuses[0]
        else:
            checks["reputation"] = "not_configured"
    else:
        checks["url_structure"] = "not_applicable"

    # 2. Message Analysis (for message or app_request types)
    if input_type in [InputType.MESSAGE, InputType.APP_REQUEST]:
        checks["text_analysis"] = "completed"
        msg_findings, _ = analyze_message_content(normalized)
        all_findings.extend(msg_findings)

    # 3. App Request Analysis (for app_request type)
    if input_type == InputType.APP_REQUEST:
        app_findings, _ = analyze_app_request(normalized, request.context)
        all_findings.extend(app_findings)

    # 4. Optional LLaMA Semantic Threat Analysis Layer
    ai_status, ai_finding, _ = await llama_analyzer.analyze_content(
        normalized, input_type.value
    )
    checks["ai_semantic_analysis"] = ai_status
    if ai_finding:
        all_findings.append(ai_finding)

    # 5. Risk Scoring & Category Determination
    risk_score, dominant_category = calculate_risk_score(
        all_findings,
        url_findings_list,
        input_type.value
    )

    # Check if a critical external check failed (never convert failed check to clean)
    has_critical_failure = checks.get("reputation") == "failed"

    # 5. Verdict
    verdict = determine_verdict(
        risk_score,
        all_findings,
        has_insufficient_input=False,
        has_critical_check_failure=has_critical_failure,
    )

    # 6. Analysis Summary
    summary = generate_analysis_summary(
        verdict,
        risk_score,
        dominant_category,
        all_findings,
        len(url_findings_list),
    )

    return AnalyzeResponse(
        verdict=verdict,
        risk_score=risk_score,
        category=dominant_category,
        summary=summary,
        findings=all_findings,
        urls=url_findings_list,
        checks=checks,
        limitations=limitations,
        engine_version=settings.ENGINE_VERSION,
    )
