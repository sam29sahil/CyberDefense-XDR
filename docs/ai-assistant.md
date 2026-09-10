# AI Security Assistant

## Overview
The AI Security Assistant acts as a tier-3 SOC analysis copilot. It interprets XDR telemetry (assets, alerts, IDS events, vulnerabilities, IOCs) mapped to user queries and provides deterministic or LLM-driven advisory insight.

## Architecture & Providers
The assistant abstracts model access behind an `AIProvider` base class.

### Providers
1. **OpenAICompatibleProvider**: Connects to OpenAI-compatible chat completion endpoints (defaulting to Gemini via Google's `v1beta/openai/chat/completions` facade). Automatically routes payloads and supports parameters like model and max tokens.
2. **LocalDeterministicProvider**: A zero-network fallback intelligence engine. Uses SOC reasoning heuristics and keyword/telemetry presence matching to issue analysis if external APIs fail or are unconfigured.

### Fallback Mechanism
If the `OpenAICompatibleProvider` experiences connection drops, API key exhaustion, or non-200 HTTP responses, it gracefully falls back to the `LocalDeterministicProvider` to ensure analysts still receive intelligence, logging the failure transparently without crashing.

## Context Gathering
Context is pulled live from XDR databases (`gather_security_context`):
- Regular expressions extract IPs, CVEs, and Alert IDs from the `user_prompt`.
- Relevant records (Assets, Alerts, IDSEvents filtering SID 2200074, Vulns, IOCs) are serialized.
- Bounds are set to the first 3 IPs, CVEs, and Alerts to avoid context explosion.
- A fallback injects the top 3 active critical/high system alerts if no specific entity is found.

## Security Controls
- **Advisory-Only (`ADVISORY_SYSTEM_PROMPT`)**: The AI operates strictly as an advisor. State-changing actions require SOAR execution/approval.
- **Secret Scrubbing (`SECRET_PATTERNS`)**: Regex-based scrubbing removes passwords, API keys, AWS tokens, private keys, and postgres URLs from prompts and log messages.
- **Input Sanitization**: The input is truncated to `MAX_INPUT_LENGTH` (4000) before processing.
- **Prompt Injection Defense (`wrap_untrusted_data`)**: Untrusted data (e.g. database logs and extracted fields) is wrapped in XML-like tags (e.g. `<security_telemetry>`) combined with system instructions to treat the block strictly as data, neutralizing instruction smuggling.
- **IDOR Protection**: The chat history API validates conversation ownership before granting read/delete access. Admins can view other users' logs.

## Models

### AIConversation
Tracks a chat session instance.
- `conversation_id`: Unique identifier
- `title`: Extracted title
- `user_id`: Owner user ID
- `entity_type` / `entity_id`: Optional target associations.

### AIMessage
Tracks individual turns in a conversation.
- `role`: user, assistant
- `content`: Raw text
- `evidence_json`, `analysis_json`, `recommendations_json`: Structured outputs extracted from AI completions.
- `risk_level`: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.
- `tokens_used`: Usage counter.

## Configuration Variables
Environment/Flask Config keys:
- `AI_PROVIDER`: "gemini", "openai", "local", "mock", etc.
- `AI_API_KEY`: API authentication token.
- `AI_API_BASE`: Target endpoint URL.
- `AI_MODEL`: Model ID (e.g., "gemini-2.5-flash", "gpt-4o-mini").
- `AI_TIMEOUT`: Request timeout in seconds.
- `AI_MAX_TOKENS`: Output token limit.

## Limitations / Notes
- The AI module operates purely as an advisory system and cannot directly modify backend infrastructure. All changes must go through the SOAR approval pipeline.
- Do NOT suggest any changes to this module as per strict project requirements.
