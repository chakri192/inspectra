import json
import logging
from typing import Dict, List, Optional, Tuple, Any
import httpx

from app.config import settings
from app.models.responses import Finding, Severity

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an explainable cybersecurity threat analyzer for Inspectra.
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
Do not provide advice, recovery steps, or conversational chat."""


class LlamaAnalyzer:
    """
    Hybrid Semantic Analysis Layer using LLaMA models.
    Supports:
    - Local Ollama (private, on-device execution at http://127.0.0.1:11434)
    - OpenAI-compatible hosted endpoints (Groq, Together, vLLM)
    Operates strictly within scope: explainability, structured JSON output, transient processing.
    """

    def __init__(self):
        self.enabled = settings.LLAMA_ENABLED
        self.provider = settings.LLAMA_PROVIDER
        self.base_url = settings.LLAMA_BASE_URL.rstrip("/")
        self.model = settings.LLAMA_MODEL
        self.api_key = settings.LLAMA_API_KEY
        self.timeout = settings.LLAMA_TIMEOUT_SECONDS

        # Test mocks for pytest
        self._mock_response: Optional[Dict[str, Any]] = None
        self._simulate_failure: bool = False

    def is_configured(self) -> bool:
        return self.enabled

    def set_mock_response(self, response_dict: Optional[Dict[str, Any]]):
        self._mock_response = response_dict

    def set_simulate_failure(self, simulate: bool):
        self._simulate_failure = simulate

    async def analyze_content(
        self,
        content: str,
        input_type: str
    ) -> Tuple[str, Optional[Finding], int]:
        """
        Executes semantic analysis using LLaMA.
        Returns:
            check_status: 'not_configured' | 'completed' | 'failed'
            finding: Optional Finding model if suspicious indicators are detected
            score_contribution: Heuristic score adjustment (0 to 35)
        """
        if self._simulate_failure:
            return "failed", None, 0

        if not self.is_configured() and self._mock_response is None:
            return "not_configured", None, 0

        # Handle mock response for tests
        if self._mock_response is not None:
            try:
                return self._parse_model_output(self._mock_response)
            except Exception as e:
                logger.warning("LLaMA semantic analysis mock parsing error: %s", type(e).__name__)
                return "failed", None, 0

        prompt = f"Analyze the following {input_type} content for cybersecurity threats:\n\n{content[:2000]}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if self.provider == "ollama":
                    # Ollama API
                    endpoint = f"{self.base_url}/api/generate"
                    payload = {
                        "model": self.model,
                        "system": SYSTEM_PROMPT,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                    resp = await client.post(endpoint, json=payload)
                    if resp.status_code != 200:
                        return "failed", None, 0

                    raw_text = resp.json().get("response", "{}")
                    parsed = json.loads(raw_text)
                    return self._parse_model_output(parsed)

                else:
                    # OpenAI-compatible API (Groq, Together, vLLM)
                    endpoint = f"{self.base_url}/v1/chat/completions"
                    headers = {
                        "Content-Type": "application/json",
                    }
                    if self.api_key:
                        headers["Authorization"] = f"Bearer {self.api_key}"

                    payload = {
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.1,
                        "response_format": {"type": "json_object"}
                    }
                    resp = await client.post(endpoint, json=payload, headers=headers)
                    if resp.status_code != 200:
                        return "failed", None, 0

                    data = resp.json()
                    raw_content = data["choices"][0]["message"]["content"]
                    parsed = json.loads(raw_content)
                    return self._parse_model_output(parsed)

        except Exception as e:
            logger.warning("LLaMA semantic analysis encountered error: %s (%s)", type(e).__name__, str(e))
            return "failed", None, 0

    def _parse_model_output(self, data: Any) -> Tuple[str, Optional[Finding], int]:
        if not isinstance(data, dict):
            logger.warning("LLaMA semantic analysis returned non-dict payload: %s", type(data).__name__)
            return "failed", None, 0

        raw_suspicious = data.get("is_suspicious", False)
        if isinstance(raw_suspicious, str):
            is_suspicious = raw_suspicious.strip().lower() in ("true", "1", "yes")
        else:
            is_suspicious = bool(raw_suspicious)

        raw_conf = data.get("confidence", 0)
        try:
            confidence = int(raw_conf)
        except (ValueError, TypeError):
            logger.warning("LLaMA semantic analysis invalid confidence value: %r", raw_conf)
            return "failed", None, 0

        raw_tactics = data.get("detected_tactics")
        if raw_tactics is not None and not isinstance(raw_tactics, list):
            logger.warning("LLaMA semantic analysis detected_tactics is not a list: %r", type(raw_tactics).__name__)
            return "failed", None, 0

        tactics: List[str] = []
        if isinstance(raw_tactics, list):
            for t in raw_tactics:
                if not isinstance(t, str):
                    logger.warning("LLaMA semantic analysis detected_tactics contains non-string: %r", t)
                    return "failed", None, 0
                tactics.append(t)

        explanation = str(data.get("explanation") or "AI semantic model identified social engineering indicators.")
        evidence = str(data.get("evidence_excerpt") or "Semantic pattern in submitted text")

        if is_suspicious and confidence >= 50:
            severity = Severity.HIGH if confidence >= 75 else Severity.MEDIUM
            tactics_str = f"Tactics: {', '.join(tactics[:3])}. " if tactics else ""
            finding = Finding(
                rule_id="llama_semantic_detection",
                name="AI Semantic Threat Verification (LLaMA)",
                severity=severity,
                evidence=evidence[:140],
                explanation=f"{tactics_str}{explanation}"
            )
            # Score contribution proportional to model confidence
            score_contrib = 25 if severity == Severity.HIGH else 15
            return "completed", finding, score_contrib

        return "completed", None, 0


llama_analyzer = LlamaAnalyzer()
