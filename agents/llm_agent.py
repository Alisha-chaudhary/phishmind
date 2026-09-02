def analyze_with_llm(case, findings, enrichment_results):

    evidence = {
        "email": case.email_metadata,
        "iocs": case.evidence,
        "findings": findings,
        "threat_intelligence": enrichment_results
    }

    response = llm.generate(
        system_prompt=SECURITY_ANALYST_PROMPT,
        input=evidence
    )

    return response
