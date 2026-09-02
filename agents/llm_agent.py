import json
import os

from dotenv import load_dotenv
from google import genai


MODEL_NAME = "gemini-3.5-flash-lite"


SECURITY_ANALYST_PROMPT = """
You are an AI analyst assistant inside a phishing email investigation system.

Your job is to help a SOC analyst understand the results of a deterministic
phishing analysis pipeline.

IMPORTANT RULES:
1. The deterministic risk assessment is authoritative.
2. Do NOT change or override the provided verdict.
3. Do NOT invent indicators, authentication results, URLs, domains,
   attack techniques, or other evidence.
4. Base your explanation only on the evidence provided.
5. Clearly distinguish confirmed evidence from interpretation.
6. If evidence is missing, say so.
7. Keep the response concise and useful for a SOC analyst.

Produce the following sections:

VERDICT SUMMARY
- Explain the existing verdict and confidence.

STRONGEST INDICATORS
- List the most important pieces of evidence.

ANALYST REASONING
- Explain why the evidence supports the existing assessment.

AUTHENTICATION ANALYSIS
- Explain relevant SPF, DKIM, DMARC, Reply-To, Return-Path,
  or sender identity findings when available.

LIKELY ATTACK OBJECTIVE
- State the likely objective only when supported by the evidence.

SOC RECOMMENDATION
- Explain the recommended next step.
- Remember that final remediation requires human analyst approval.

MISSING EVIDENCE
- Mention important information that is unavailable or inconclusive.
"""


def _build_evidence(case):
    """Build a compact evidence package for the LLM.

    Raw email content is intentionally excluded. The LLM receives the
    structured findings produced by PhishMind instead.
    """

    case_data = case.to_dict()

    return {
        "email": {
            "subject": case_data.get("subject"),
            "date": case_data.get("date_header"),
            "message_id": case_data.get("message_id"),
            "sender": case_data.get("sender"),
            "authentication": case_data.get("authentication"),
        },
        "evidence": case_data.get("evidence"),
        "agent_findings": case_data.get("agent_findings"),
        "threat_assessment": case_data.get("threat_assessment"),
        "recommended_action": case_data.get("recommended_action"),
        "threat_intelligence": case_data.get("enrichment_results"),
    }


def analyze(case):
    """Generate an AI-assisted analyst explanation for an investigation case."""

    load_dotenv()

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured. "
            "Add it to the project .env file."
        )

    client = genai.Client(api_key=api_key)

    evidence = _build_evidence(case)

    prompt = (
        SECURITY_ANALYST_PROMPT
        + "\n\nINVESTIGATION EVIDENCE:\n"
        + json.dumps(evidence, indent=2, default=str)
    )

    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
    )

    if not response.text:
        raise RuntimeError("Gemini returned an empty response.")

    return response.text.strip()
