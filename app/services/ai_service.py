import json
import logging
from typing import List, Optional, Tuple
from app.models.report import Finding, AIAnalysis
from app.config import settings
import litellm

logger = logging.getLogger(__name__)

SYSTEM_PROMPT_EN = """You are an expert cybersecurity auditor and senior security consultant. Your task is to analyze security scan findings and provide comprehensive, actionable insights.

You MUST respond ONLY with valid JSON in exactly this structure:
{
    "executive_summary": "Non-technical summary for stakeholders (2-3 paragraphs)",
    "technical_summary": "Technical analysis for developers (2-3 paragraphs)",
    "risk_narrative": "Overall risk assessment narrative",
    "priority_actions": ["Action 1", "Action 2", "Action 3"],
    "quick_wins": ["Quick fix 1", "Quick fix 2"],
    "long_term_recommendations": ["Long-term recommendation 1", "Long-term recommendation 2"],
    "enriched_findings": [
        {
            "finding_id": "ID of the finding",
            "recommendation": "Specific remediation steps",
            "code_fix": "Code example if applicable or null",
            "business_impact": "Business impact explanation"
        }
    ]
}

Be thorough, professional, and prioritize the most critical issues first."""

SYSTEM_PROMPT_FR = """Vous êtes un expert en audit de cybersécurité et consultant senior en sécurité. Votre tâche est d'analyser les résultats des scans de sécurité et de fournir des insights complets et exploitables.

Vous DEVEZ répondre UNIQUEMENT avec du JSON valide dans exactement cette structure:
{
    "executive_summary": "Résumé non technique pour les parties prenantes (2-3 paragraphes)",
    "technical_summary": "Analyse technique pour les développeurs (2-3 paragraphes)",
    "risk_narrative": "Évaluation narrative du risque global",
    "priority_actions": ["Action 1", "Action 2", "Action 3"],
    "quick_wins": ["Correction rapide 1", "Correction rapide 2"],
    "long_term_recommendations": ["Recommandation long terme 1", "Recommandation long terme 2"],
    "enriched_findings": [
        {
            "finding_id": "ID du finding",
            "recommendation": "Étapes de remédiation spécifiques",
            "code_fix": "Exemple de code si applicable ou null",
            "business_impact": "Explication de l'impact business"
        }
    ]
}

Soyez rigoureux, professionnel et priorisez les problèmes les plus critiques."""


def get_model_and_key(provider: str, user_api_key: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Returns the model name, api key, and API key mode based on provider and user choice.
    """
    if user_api_key:
        api_key = user_api_key
        api_key_mode = "own"
    else:
        api_key_mode = "platform"
        if provider == "claude":
            api_key = settings.CLAUDE_API_KEY
        elif provider == "gemini":
            api_key = settings.GEMINI_API_KEY
        elif provider == "groq":
            api_key = settings.GROQ_API_KEY
        elif provider == "openai":
            api_key = settings.OPENAI_API_KEY
        else:
            api_key = ""

    if provider == "claude":
        model = f"anthropic/{settings.CLAUDE_MODEL}"
    elif provider == "gemini":
        model = f"gemini/{settings.GEMINI_MODEL}"
    elif provider == "groq":
        model = f"groq/{settings.GROQ_MODEL}"
    elif provider == "openai":
        model = f"openai/{settings.OPENAI_MODEL}"
    else:
        model = f"anthropic/{settings.CLAUDE_MODEL}"
        
    return model, api_key, api_key_mode


async def analyze_findings(
    findings: List[Finding],
    audit_type: str,
    target: str,
    language: str = "en",
    ai_provider: str = "claude",
    user_api_key: Optional[str] = None
) -> Optional[AIAnalysis]:
    """
    Analyze security findings using the selected AI provider.
    """
    try:
        model, api_key, api_key_mode = get_model_and_key(ai_provider, user_api_key)
        
        if not api_key:
            logger.warning(f"No API key available for {ai_provider} analysis")
            return None
            
        system_prompt = SYSTEM_PROMPT_FR if language == "fr" else SYSTEM_PROMPT_EN
        
        findings_text = json.dumps([{
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "description": f.description,
            "affected_component": f.affected_component,
            "cvss_score": f.cvss_score
        } for f in findings], indent=2)
        
        user_prompt = f"""Analyze the following security scan results for a {audit_type} audit of: {target}

FINDINGS:
{findings_text}

Provide your analysis in JSON format as specified."""
        
        # Use litellm for unified multi-provider completions
        response = await litellm.acompletion(
            model=model,
            api_key=api_key,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={ "type": "json_object" } if ai_provider in ["openai", "groq", "gemini"] else None
        )
        
        response_text = response.choices[0].message.content
        
        # Parse JSON response
        try:
            response_text = response_text.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            
            analysis_data = json.loads(response_text.strip())
            
            ai_analysis = AIAnalysis(
                model_used=model,
                api_key_mode=api_key_mode,
                risk_narrative=analysis_data.get("risk_narrative", ""),
                priority_actions=analysis_data.get("priority_actions", []),
                quick_wins=analysis_data.get("quick_wins", []),
                long_term_recommendations=analysis_data.get("long_term_recommendations", [])
            )
            
            enriched = {e.get("finding_id"): e for e in analysis_data.get("enriched_findings", [])}
            for finding in findings:
                if finding.id in enriched:
                    finding.recommendation = enriched[finding.id].get("recommendation")
                    finding.code_fix = enriched[finding.id].get("code_fix")
            
            return ai_analysis
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse {ai_provider} response as JSON: {e}")
            return AIAnalysis(
                model_used=model,
                api_key_mode=api_key_mode,
                risk_narrative="Analysis completed but structured output parsing failed.",
                priority_actions=["Review all critical findings", "Address high-severity issues"],
                quick_wins=["Enable security headers", "Update dependencies"],
                long_term_recommendations=["Implement security testing in CI/CD"]
            )
            
    except Exception as e:
        logger.error(f"AI analysis failed with {ai_provider}: {e}")
        return None


async def test_api_key(provider: str, api_key: str) -> tuple[bool, str]:
    """Test if an API key is valid by making a simple request."""
    try:
        model, _, _ = get_model_and_key(provider, api_key)
        response = await litellm.acompletion(
            model=model,
            api_key=api_key,
            messages=[{"role": "user", "content": "Say 'OK' and nothing else."}],
            max_tokens=10
        )
        res_text = response.choices[0].message.content
        if res_text and len(res_text) > 0:
            return True, "API key is valid"
        return False, "Empty response from API"
        
    except Exception as e:
        return False, f"API error: {str(e)}"
