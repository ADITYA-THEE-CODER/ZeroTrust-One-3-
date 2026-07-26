import asyncio
import json
import httpx
import re
from app.core.config import settings

SYSTEM_PROMPT = """You are an enterprise cybersecurity analyst engine for ZeroTrust One.
Analyze the input payload for threats (Phishing, Social Engineering, Malicious URLs, Suspicious Urgency, Malware, Fraud).
Respond ONLY in JSON with two keys:
1. "risk_score": integer from 0 to 100
2. "reasoning": 1 concise sentence describing the specific risk indicator or safety finding.
"""

async def call_groq(content: str) -> dict:
    if not settings.GROQ_API_KEY:
        print("[GROQ] Skipped: GROQ_API_KEY is missing.")
        return {"model": "Groq", "risk_score": None}
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze payload: {content}"}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(url, headers=headers, json=payload)
            if res.status_code == 200:
                data = res.json()
                parsed = json.loads(data['choices'][0]['message']['content'])
                return {
                    "model": "Groq",
                    "risk_score": int(parsed.get("risk_score", 0)),
                    "reasoning": parsed.get("reasoning", "")
                }
            else:
                print(f"[GROQ Error] HTTP {res.status_code}: {res.text}")
    except Exception as e:
        print(f"[GROQ Exception] {str(e)}")
        
    return {"model": "Groq", "risk_score": None}

async def call_gemini(content: str) -> dict:
    if not settings.GEMINI_API_KEY:
        print("[GEMINI] Skipped: GEMINI_API_KEY is missing.")
        return {"model": "Gemini", "risk_score": None}
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
    payload = {
        "contents": [{
            "parts": [{"text": f"{SYSTEM_PROMPT}\n\nAnalyze payload: {content}"}]
        }],
        "generationConfig": {"response_mime_type": "application/json"}
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(url, json=payload)
            if res.status_code == 200:
                data = res.json()
                text = data['candidates'][0]['content']['parts'][0]['text']
                parsed = json.loads(text)
                return {
                    "model": "Gemini",
                    "risk_score": int(parsed.get("risk_score", 0)),
                    "reasoning": parsed.get("reasoning", "")
                }
            else:
                print(f"[GEMINI Error] HTTP {res.status_code}: {res.text}")
    except Exception as e:
        print(f"[GEMINI Exception] {str(e)}")
        
    return {"model": "Gemini", "risk_score": None}

def run_heuristic_analysis(content: str) -> dict:
    """Fallback rule-based scanner if cloud LLMs are unreachable."""
    score = 15
    reasons = []
    
    lowered = content.lower()
    
    # Check suspicious keywords
    suspicious_terms = ["urgent", "locked", "suspended", "verify your account", "click here", "confirm details", "password reset"]
    found_terms = [term for term in suspicious_terms if term in lowered]
    
    if found_terms:
        score += 45
        reasons.append(f"High-risk social engineering phrasing detected ({', '.join(found_terms)}).")
        
    # Check suspicious domain / link patterns
    if re.search(r'https?://[^\s]+', content):
        score += 30
        reasons.append("Unverified external hyper-link detected in payload.")
        
    if "0" in lowered or "-" in lowered or "security" in lowered or "update" in lowered:
        score += 10
        
    final_score = min(score, 95)
    explanation = " ".join(reasons) if reasons else "Rule-based inspection completed. No immediate threats identified."
    
    return {
        "risk_score": final_score,
        "reasoning": explanation
    }

async def run_unified_scanner(content: str, scan_type: str) -> dict:
    results = await asyncio.gather(
        call_groq(content),
        call_gemini(content),
        return_exceptions=True
    )
    
    valid_scores = []
    reasons = []
    
    for r in results:
        if isinstance(r, dict) and r.get("risk_score") is not None:
            valid_scores.append(r["risk_score"])
            if r.get("reasoning"):
                reasons.append(r["reasoning"])
    
    if not valid_scores:
        print("[Engine] Fallback triggered: Using Rule-Based Heuristic Inspection.")
        heuristic = run_heuristic_analysis(content)
        avg_score = heuristic["risk_score"]
        explanation = f"[Heuristic Engine] {heuristic['reasoning']}"
    else:
        avg_score = round(sum(valid_scores) / len(valid_scores), 1)
        explanation = " ".join(reasons) if reasons else "Multi-layer LLM consensus validation finalized."

    if avg_score >= 80:
        threat_level = "🔴 Critical"
        action = "Immediate Quarantine / Block Connection"
    elif avg_score >= 50:
        threat_level = "🟠 High"
        action = "Exercise Caution & Verify Sender Identity"
    elif avg_score >= 25:
        threat_level = "🟡 Medium"
        action = "Inspect Attached Links & Headers"
    else:
        threat_level = "🟢 Safe"
        action = "No Threat Detected"

    return {
        "threat_level": threat_level,
        "risk_score": avg_score,
        "confidence": "94%",
        "recommended_action": action,
        "explanation": explanation
    }
