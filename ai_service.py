"""Local Ollama integration for Sentinel AI analyst features (Assignment 5.2).

This module is the **AI service layer** in the Aetherius Sentinel architecture
(Assignment 5.2): it sits between the Streamlit UI / sentinel_actions orchestration
and a **local** Ollama HTTP server. No cloud LLM API keys are embedded in code;
connectivity and model choice are entirely environment-driven so deployments can
swap hosts, models, or disable AI without code changes.

Architecture overview (5.2)
---------------------------
1. **Context assembly** — ``assemble_context`` / ``assemble_general_context`` pull
   incident, device, event, playbook, chat, and temporal state from SQLite via ``db``.
2. **Prompt construction** — Persona + scope rules + formatted context blocks are
   composed into system/user message pairs; incident chat may require structured JSON.
3. **Ollama transport** — ``_chat`` POSTs to ``/api/chat``; ``check_ai_status`` GETs
   ``/api/tags`` for health checks.
4. **Response validation** — ``_extract_json`` tolerates markdown fences; playbook
   keys are normalized and filtered against ``action_catalog.ACTIONS`` (never trusting
   raw model output).
5. **Structured results** — Dataclasses (``AnalysisResult``, ``ChatReplyResult``, etc.)
   return typed payloads to the UI; playbooks are AI-generated only with explicit
   errors when Ollama is unavailable.

Environment variables
---------------------
``OLLAMA_BASE_URL`` (default ``http://localhost:11434``)
    Root URL of the Ollama daemon; trailing slashes are stripped.

``OLLAMA_MODEL`` (default ``llama3.1:8b``)
    Model tag passed to every ``/api/chat`` request; must be pulled locally.

``AI_ENABLED`` (default ``true``)
    When false, ``_chat`` returns None immediately and status reports ``disabled``.

``AI_REQUEST_TIMEOUT`` (default ``120`` seconds)
    Per-request HTTP timeout for chat completions (analysis can be slow).

Optional: ``python-dotenv`` loads a ``.env`` file at import time if installed.

Failure philosophy
------------------
Playbooks and analyst narratives are **not** silently templated when AI fails;
callers receive ``success=False`` / error strings so the UI can surface actionable
Ollama setup guidance (``format_ai_error_message``, ``check_ai_status``).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import requests

# Load .env before reading OLLAMA_* / AI_* constants (optional dependency).
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

import db
from action_catalog import (
    ACTIONS,
    ACTION_CATEGORIES,
    get_action,
    normalize_action_key,
    playbook_recommendation_text,
    scenario_key_for_title,
)

# --- Ollama configuration (env-driven; never hardcode API keys) ---
# Ollama runs locally and does not use OpenAI-style secret keys in this integration.
# Operators configure host/model via environment or .env instead of editing source.
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() in ("1", "true", "yes")
AI_REQUEST_TIMEOUT = int(os.getenv("AI_REQUEST_TIMEOUT", "120"))

# Stable sort order for validated playbook keys: investigation < containment < ...
_CATEGORY_ORDER = {cat: index for index, cat in enumerate(ACTION_CATEGORIES)}

# Resolution shortcuts that bypass the recommended next step; verified by verify_resolution_action.
RESOLUTION_SHORTCUT_KEYS = frozenset({
    "trust_device",
    "mark_false_positive",
    "skip_to_documentation",
})


@dataclass
class AnalysisResult:
    """Structured output from post-investigation AI analysis.

    Returned by ``analyze_incident`` after automated investigation completes.
    The UI renders ``analysis`` and persists ``playbook_action_keys`` when
    ``success`` is True and ``used_ai`` is True.
    """

    # Homeowner-facing narrative summary (markdown allowed in analysis text).
    analysis: str
    # Ordered, validated keys from action_catalog — never raw model strings.
    playbook_action_keys: list[str]
    # True when model recommends law-enforcement / authority contact (serious crimes).
    authority_recommended: bool = False
    # Short advisory bullets separate from the main playbook (e.g. password reset).
    general_recommendations: list[str] = field(default_factory=list)
    # Human-readable playbook line built from keys via playbook_recommendation_text.
    playbook_text: str = ""
    # True when Ollama produced the result (False on DB/validation failures too).
    used_ai: bool = False
    # False when incident missing, Ollama down, JSON invalid, or no valid keys.
    success: bool = True
    # Technical detail for logs/UI when success is False.
    error_detail: str | None = None


@dataclass
class ChatReplyResult:
    """Structured output from free-form chat — may include a playbook revision offer.

    ``answer_chat`` returns this for both general dashboard Q&A and per-incident
    investigation threads. Plan-update fields are only populated for incident scope
    when the model proposes reordering *remaining* playbook steps.
    """

    # User-visible assistant message (never raw JSON).
    reply: str
    # True when model wants user consent to rewrite remaining playbook order.
    suggest_plan_update: bool = False
    # One-line explanation shown in the plan-update confirmation prompt.
    plan_update_summary: str = ""
    # Validated remaining keys the model proposes (post filter_remaining_playbook_keys).
    proposed_playbook_keys: list[str] = field(default_factory=list)
    # Full markdown question for the UI confirmation dialog.
    plan_update_question: str = ""


@dataclass
class UpdateAnalysisResult:
    """Structured output from re-analysis after an incident update alert.

    Produced when the user opens a monitoring/status update (not a new incident).
    May suggest a playbook revision if remaining steps differ materially from DB state.
    """

    # Primary user-facing summary of what changed after re-investigation.
    summary: str
    # Keys to persist when suggest_plan_update is True; else current remaining steps.
    playbook_action_keys: list[str] = field(default_factory=list)
    # True only when plan_update_summary is non-empty and keys differ from current.
    suggest_plan_update: bool = False
    # Rationale for accepting a playbook rewrite.
    plan_update_summary: str = ""
    # Short CTA narrative pointing to the next sticky-bar action.
    next_step_narrative: str = ""
    used_ai: bool = False
    success: bool = True
    error_detail: str | None = None


@dataclass
class VerificationResult:
    """AI caution before a non-recommended resolution shortcut.

    Used when the user attempts trust / false-alarm / skip-to-docs outside the
    recommended playbook order. Falls back to evidence bullets if Ollama is down.
    """

    # Warning paragraph(s) shown before confirm.
    warning: str
    # Checkbox items the user must acknowledge.
    checklist: list[str] = field(default_factory=list)
    # Label for the confirm button in the verification modal.
    confirm_label: str = "Confirm"
    # When True, UI should emphasize cancel over proceed.
    recommend_cancel: bool = False
    success: bool = True
    error_detail: str | None = None


# Shared persona for analysis, updates, and verification — emphasizes DB grounding.
_INCIDENT_MANAGER_PERSONA = (
    "You are Sentinel, the user's home incident manager. "
    "You have ongoing awareness of their devices, past incidents on those devices, "
    "and how they have responded before. Reference this history when it informs the "
    "current decision. Do not invent devices or incidents not in the context. "
)

# Chat routing: general = dashboard-wide; incident = single investigation thread.
ChatScope = Literal["general", "incident"]

# Tone fragments — combined with scope rules in build_chat_system_prompt.
_STANDARD_GUIDE_TONE = (
    "You are Sentinel, a calm home-network guide. "
    "Use simple everyday language—no jargon, acronyms, or SOC terms unless the user uses them first. "
    "Walk the user through problems one step at a time. Be reassuring and practical. "
)

_EXPERT_SOC_TONE = (
    "You are Sentinel, a SOC analyst. "
    "Use precise technical language: IOCs, containment, eradication, phases, telemetry. "
    "Be concise and evidence-driven. "
)

# General chat: plain language only — no JSON envelope for the model.
_CONVERSATIONAL_OUTPUT_RULES = (
    "Respond in clear, conversational natural language only. "
    "Write complete sentences as if speaking directly to the user. "
    "Do NOT use JSON, code fences, raw data structures, or field-name dumps. "
    "Never output keys like reply, incident_summary, or playbook_action_keys. "
)

# Incident chat: app parses JSON; user only sees the reply field as prose.
_INCIDENT_STRUCTURED_OUTPUT_RULES = (
    "The user must only see natural language—never JSON or structured data. "
    "Put your full conversational answer in the reply field using complete sentences. "
    "Respond with a single JSON object only (parsed by the app, not shown to the user). "
    "JSON keys: reply, suggest_plan_update, plan_update_summary, playbook_action_keys. "
    "Set suggest_plan_update true only when reordering remaining playbook steps would materially help; "
    "then include plan_update_summary and playbook_action_keys from remaining catalog keys only. "
)


def get_chat_tone(*, expert_mode: bool) -> str:
    """Return the base tone instruction for chat and playbook narrative prompts.

    Purpose:
        Select Standard (homeowner) vs Expert (SOC) voice for all user-facing AI text.

    Inputs:
        expert_mode: True when the UI is in expert/SOC mode.

    Outputs:
        One of ``_EXPERT_SOC_TONE`` or ``_STANDARD_GUIDE_TONE`` string constants.

    Prompt strategy:
        Prepended to system prompts before scope and output-format rules.

    Failure modes:
        None — always returns a non-empty string.
    """
    return _EXPERT_SOC_TONE if expert_mode else _STANDARD_GUIDE_TONE


def _general_scope_rules(*, expert_mode: bool) -> str:
    """Build scope guardrails for dashboard-wide (non-incident) chat.

    Purpose:
        Restrict the model to dashboard context and refuse playbook-driving behavior.

    Inputs:
        expert_mode: Reserved for future tone-specific scope tweaks (currently unused).

    Outputs:
        Multi-sentence scope instruction appended to the system prompt.

    Prompt strategy:
        Explicit allow-list (dashboard/network facts) and deny-list (off-topic, actions).

    Failure modes:
        Model may still hallucinate; mitigated by grounding user message in
        ``assemble_general_context`` output only.
    """
    _ = expert_mode
    return (
        "Scope: general dashboard Q&A. Answer ONLY from the provided dashboard and network context. "
        "Do not invent incidents, devices, or telemetry not in the context. "
        "The user may ask about any incident, device, open alert, or overall system status. "
        "Refuse clearly off-domain topics (weather, jokes, recipes, sports, stocks, etc.). "
        "Do not drive playbook execution or suggest plan updates. "
        "If the user asks to execute a response action on an incident, tell them to open "
        "that incident's investigation chat from the incident detail page. "
    )


def _incident_scope_rules(incident: dict | None, *, expert_mode: bool) -> str:
    """Build scope guardrails for single-incident investigation chat.

    Purpose:
        Bind the assistant to one incident_id/title and playbook/temporal constraints.

    Inputs:
        incident: Row dict with at least title and incident_id (may be partial).
        expert_mode: Controls technical vs plain-language action label instruction.

    Outputs:
        Scope paragraph including incident label and sticky-bar / monitoring rules.

    Prompt strategy:
        Embeds incident title/id so the model cannot drift to other cases; references
        blocked actions and monitoring gates from formatted context blocks.

    Failure modes:
        Missing incident fields fall back to generic placeholders; context assembly
        still supplies authoritative playbook/temporal blocks.
    """
    title = (incident or {}).get("title", "this incident")
    incident_id = (incident or {}).get("incident_id", "unknown")
    # Expert users may see internal action labels; standard users get plain_label only.
    label_rule = (
        "Use technical action labels when appropriate. "
        if expert_mode
        else "Use plain-language action labels—no internal keys or jargon. "
    )
    return (
        f"Scope: single-incident investigation for '{title}' (incident_id={incident_id}). "
        "Answer ONLY about this incident. Refuse questions about other incidents, unrelated devices, "
        "or general chit-chat—tell the user to use general chat for cross-incident questions. "
        "Ground answers in provided evidence; do not invent attack details. "
        f"{label_rule}"
        "Point users to the sticky action bar for Trust, False alarm, Skip to docs, and the next recommended step. "
        "If monitoring is active, do not recommend trust, closure, or documentation—explain the wait. "
        "Never recommend actions listed under Blocked actions in the context. "
        "When the user asks about status or next step, summarize from completed and remaining steps in context "
        "and point them to the action bar for the next action. "
        "If a different step order would materially help, you may suggest a plan update via the structured fields. "
    )


def build_chat_system_prompt(
    *,
    chat_scope: ChatScope,
    expert_mode: bool,
    incident: dict | None = None,
) -> str:
    """Compose system prompt from tone + scope rules for free-form chat.

    Purpose:
        Central factory for chat system messages — enforces scope and output shape.

    Inputs:
        chat_scope: ``"general"`` (dashboard) or ``"incident"`` (single investigation).
        expert_mode: Selects SOC vs homeowner tone via ``get_chat_tone``.
        incident: Required for incident scope rules (title/id embedding).

    Outputs:
        Single system string: tone + scope rules + output format rules.

    Prompt strategy:
        General scope → conversational-only rules (no JSON).
        Incident scope → structured JSON rules for plan-update metadata.

    Validation:
        Caller must pass matching ``chat_scope`` and context in the user message.

    Failure modes:
        Wrong scope may confuse the model; UI must set scope from incident_id presence.
    """
    tone = get_chat_tone(expert_mode=expert_mode)
    # Scope split: general chat never asks for JSON; incident chat requires structured fields.
    if chat_scope == "general":
        return tone + " " + _general_scope_rules(expert_mode=expert_mode) + _CONVERSATIONAL_OUTPUT_RULES
    return (
        tone
        + " "
        + _incident_scope_rules(incident, expert_mode=expert_mode)
        + _INCIDENT_STRUCTURED_OUTPUT_RULES
    )


def assemble_general_context() -> dict[str, Any]:
    """Bundle dashboard-level facts for general (non-incident) chat prompts.

    Purpose:
        Ground general chat in live DB aggregates without loading a full incident graph.

    Inputs:
        None — reads dashboard tables via ``db``.

    Outputs:
        Dict with counts, up to 12 devices, up to 10 open incidents (safe defaults on error).

    Prompt strategy:
        Serialized by ``_format_general_context_block`` into the user message.

    Validation:
        Each DB subsection is try/except isolated so partial context still ships.

    Failure modes:
        On DB errors, returns zeros/empty lists rather than raising.
    """
    context: dict[str, Any] = {
        "device_count": 0,
        "critical_count": 0,
        "incidents_this_month": 0,
        "devices": [],
        "open_incidents": [],
    }
    # Aggregate counters — best-effort; chat can still answer with partial data.
    try:
        context["device_count"] = db.get_device_count()
        context["critical_count"] = db.get_critical_incident_count()
        context["incidents_this_month"] = db.get_incidents_this_month_count()
    except Exception:
        pass

    try:
        hardware_df = db.get_connected_hardware()
        if not hardware_df.empty:
            for _, row in hardware_df.head(12).iterrows():
                context["devices"].append(
                    {
                        "name": row.get("Device", ""),
                        "type": row.get("Type", ""),
                        "ip": row.get("IP Address", ""),
                        "mac": row.get("MAC Address", ""),
                        "owner": row.get("Owner", ""),
                    }
                )
    except Exception:
        pass

    try:
        incidents_df = db.get_incidents_filtered(status="Open")
        if not incidents_df.empty:
            for _, row in incidents_df.head(10).iterrows():
                context["open_incidents"].append(
                    {
                        "incident_id": int(row.get("ID", 0)),
                        "title": row.get("Title", ""),
                        "severity": row.get("Severity", ""),
                        "status": row.get("Status", ""),
                        "device": row.get("Device", ""),
                        "ip": row.get("IP", ""),
                        "events": row.get("Events", 0),
                        "created": row.get("Created", ""),
                    }
                )
    except Exception:
        pass

    return context


def _format_general_context_block(context: dict[str, Any], *, expert_mode: bool = False) -> str:
    """Render dashboard context as compact text for general chat prompts.

    Purpose:
        Convert ``assemble_general_context`` dict into human-readable prompt lines.

    Inputs:
        context: Output of ``assemble_general_context``.
        expert_mode: Reserved (format is the same for both modes today).

    Outputs:
        Newline-joined block starting with "Dashboard summary:".

    Failure modes:
        Missing keys use .get defaults — never raises.
    """
    _ = expert_mode
    lines = [
        "Dashboard summary:",
        f"  Devices on network: {context.get('device_count', 0)}",
        f"  Critical incidents: {context.get('critical_count', 0)}",
        f"  Incidents this month: {context.get('incidents_this_month', 0)}",
    ]

    devices = context.get("devices", [])
    if devices:
        lines.append("\nConnected hardware:")
        for device in devices:
            lines.append(
                f"  - {device.get('name', 'Unknown')} ({device.get('type', '')}) "
                f"IP {device.get('ip', 'N/A')} — owner {device.get('owner', 'N/A')}"
            )

    incidents = context.get("open_incidents", [])
    if incidents:
        lines.append("\nOpen incidents (Active / Investigating):")
        for inc in incidents:
            lines.append(
                f"  - ID {inc.get('incident_id')}: {inc.get('title', '')} | "
                f"{inc.get('severity', '')} | {inc.get('status', '')} | "
                f"device {inc.get('device', '')} | events {inc.get('events', 0)}"
            )
    else:
        lines.append("\nOpen incidents: none")

    return "\n".join(lines)


def check_ai_status() -> dict[str, Any]:
    """Return diagnostic status for Ollama connectivity and model availability.

    Purpose:
        Pre-flight probe used by UI badges and before expensive analysis calls.

    Inputs:
        None — uses module-level ``OLLAMA_*`` and ``AI_ENABLED`` constants.

    Outputs:
        Dict with keys: ok, reason, detail, base_url, model.
        reason ∈ {disabled, ready, model_missing, timeout, unreachable, unknown}.

    Validation steps:
        1. Return early if AI_ENABLED is false.
        2. GET ``{OLLAMA_BASE_URL}/api/tags`` with 5s timeout.
        3. Match OLLAMA_MODEL exactly or by base name prefix (tag variants).

    Failure modes:
        Timeout, connection refused, or missing model → ok=False with setup hints.
    """
    base = {
        "ok": False,
        "reason": "unknown",
        "detail": "",
        "base_url": OLLAMA_BASE_URL,
        "model": OLLAMA_MODEL,
    }
    if not AI_ENABLED:
        return {
            **base,
            "reason": "disabled",
            "detail": (
                "AI is disabled (AI_ENABLED=false). Set AI_ENABLED=true in your environment "
                "to enable AI-generated playbooks and chat."
            ),
        }
    try:
        # Lightweight health check — no chat completion, no API key header required.
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        response.raise_for_status()
        models = response.json().get("models", [])
        names = {m.get("name", "") for m in models}
        model_base = OLLAMA_MODEL.split(":")[0]
        # Accept "llama3.1:8b" or any tag sharing the same base name.
        model_ok = OLLAMA_MODEL in names or any(n.startswith(f"{model_base}:") for n in names)
        if not model_ok:
            return {
                **base,
                "reason": "model_missing",
                "detail": (
                    f"Ollama is running at {OLLAMA_BASE_URL} but model '{OLLAMA_MODEL}' is not installed. "
                    f"Run: ollama pull {OLLAMA_MODEL}"
                ),
            }
        return {**base, "ok": True, "reason": "ready", "detail": "Ollama is reachable and the model is available."}
    except requests.Timeout:
        return {
            **base,
            "reason": "timeout",
            "detail": (
                f"Timed out connecting to Ollama at {OLLAMA_BASE_URL}. "
                "Start Ollama and confirm the URL in OLLAMA_BASE_URL."
            ),
        }
    except requests.RequestException as exc:
        return {
            **base,
            "reason": "unreachable",
            "detail": (
                f"Cannot reach Ollama at {OLLAMA_BASE_URL}: {exc}. "
                "Start Ollama locally or update OLLAMA_BASE_URL."
            ),
        }


def is_available() -> bool:
    """Return True when Ollama is reachable and the configured model is present.

    Purpose:
        Fast boolean gate for chat/narrative helpers that should return None on failure.

    Outputs:
        True only when ``check_ai_status()["ok"]`` is truthy.

    Failure modes:
        Any check_ai_status failure → False (callers use templates or error messages).
    """
    return bool(check_ai_status().get("ok"))


def format_ai_error_message(context: str = "AI analysis") -> str:
    """Human-readable error from check_ai_status for UI display.

    Purpose:
        Markdown-friendly single line for Streamlit when AI is unavailable.

    Inputs:
        context: Short label prefix (e.g. "Chat", "AI analysis").

    Outputs:
        Empty string if AI is ready; otherwise ``**{context} failed** — reason: detail``.

    Failure modes:
        Never raises; always derived from latest ``check_ai_status`` snapshot.
    """
    status = check_ai_status()
    if status.get("ok"):
        return ""
    return f"**{context} failed** — {status.get('reason', 'error')}: {status.get('detail', '')}"


def _truncate_raw(text: str, limit: int = 280) -> str:
    """Truncate model raw output for error messages and logs.

    Purpose:
        Include a safe excerpt of malformed JSON in ``error_detail`` without huge blobs.

    Inputs:
        text: Raw assistant string; limit: max characters (default 280).

    Outputs:
        Single-line snippet with ellipsis if truncated.
    """
    cleaned = (text or "").strip().replace("\n", " ")
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def _chat(messages: list[dict[str, str]], *, temperature: float = 0.3) -> str | None:
    """Send a chat completion request to Ollama; return assistant content or None.

    Purpose:
        Single HTTP transport for all LLM calls in this module (Assignment 5.2).

    Inputs:
        messages: OpenAI-style role/content list (system + user typical).
        temperature: Passed in Ollama ``options`` — lower for analysis, higher for chat.

    Outputs:
        Stripped assistant message content, or None on disable/network/parse failure.

    Ollama HTTP pattern:
        POST ``{OLLAMA_BASE_URL}/api/chat`` with JSON body:
        model, messages, stream=False, options.temperature.
        No Authorization header — local Ollama trusts the host; secrets live in env
        only for *which* host/model to use, not API keys baked into source.

    Validation:
        ``raise_for_status`` on HTTP errors; extracts message.content from JSON body.

    Failure modes:
        AI_ENABLED false → immediate None.
        Timeout (AI_REQUEST_TIMEOUT), connection errors, non-JSON body → None (swallowed).
    """
    if not AI_ENABLED:
        return None
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature},
            },
            timeout=AI_REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("message", {}).get("content", "").strip()
    except (requests.RequestException, ValueError, KeyError):
        return None


def _extract_json(text: str) -> dict | None:
    """Parse JSON from model output, tolerating markdown fences.

    Purpose:
        Structured analysis/chat/update responses must be dicts; models often wrap JSON in fences.

    Inputs:
        text: Raw assistant output string.

    Outputs:
        Parsed dict or None if no valid JSON object found.

    Parsing strategy:
        1. Strip whitespace; peel ```json ... ``` fence if present.
        2. ``json.loads`` on full stripped text.
        3. Fallback: substring from first ``{`` to last ``}`` (common partial-fence case).

    Failure modes:
        Prose-only, arrays-only, or broken JSON → None (caller surfaces analysis error).
    """
    if not text:
        return None
    stripped = text.strip()
    # Models frequently wrap JSON in markdown despite instructions — strip fence first.
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", stripped)
    if fence:
        stripped = fence.group(1).strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(stripped[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _prose_after_json(text: str) -> str:
    """Return any assistant prose written after a JSON object in the model output.

    Purpose:
        Some models append a human paragraph after the JSON blob; merge into user reply.

    Inputs:
        text: Raw assistant output.

    Outputs:
        Trailing prose after fence or closing ``}``, or empty string.
    """
    if not text:
        return ""
    stripped = text.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", stripped)
    if fence:
        return stripped[fence.end() :].strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        return stripped[end + 1 :].strip()
    return ""


def _conversational_reply(raw: str) -> str:
    """Return user-visible chat text — never raw JSON blobs.

    Purpose:
        General chat and JSON-fallback paths must never show structured data in the UI.

    Inputs:
        raw: Unprocessed assistant string from ``_chat``.

    Outputs:
        Plain-language reply; PLACEHOLDER_AI_REPLY if empty/unparseable JSON-only.

    Validation:
        If output looks like JSON, extract ``reply`` field via ``_extract_json``.

    Failure modes:
        JSON without reply key → polite re-ask message; empty → placeholder.
    """
    from sentinel_actions import PLACEHOLDER_AI_REPLY

    text = (raw or "").strip()
    if not text:
        return PLACEHOLDER_AI_REPLY

    fence = re.search(r"^```(?:json)?\s*([\s\S]*?)\s*```$", text, re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()

    if text.startswith("{") or text.startswith("["):
        # Model ignored conversational rules — salvage reply field if present.
        parsed = _extract_json(text)
        if parsed and parsed.get("reply"):
            return str(parsed["reply"]).strip()
        if parsed:
            return (
                "I can answer that in plain language—please ask again and I'll give you a short summary "
                "without technical formatting."
            )

    return text


def _merge_chat_reply(parsed_reply: str, raw: str) -> str:
    """Combine JSON reply field with any prose the model wrote outside the JSON object.

    Purpose:
        Incident chat may return JSON plus trailing explanation — show both to the user.

    Inputs:
        parsed_reply: Value of the ``reply`` key from parsed JSON.
        raw: Full raw assistant string for prose-after-JSON detection.

    Outputs:
        Merged string preferring parsed reply + trailing prose; heuristics for truncated JSON.

    Failure modes:
        Falls back to raw plain text when reply looks like an incomplete JSON prefix.
    """
    reply = (parsed_reply or "").strip()
    trailing = _prose_after_json(raw)
    if trailing:
        if reply:
            return f"{reply}\n\n{trailing}".strip()
        return trailing
    # Heuristic: model started JSON in reply field but put full answer in raw body.
    if reply.rstrip().endswith(":") and len(reply) < 120:
        plain = (raw or "").strip()
        if plain and len(plain) > len(reply) + 20:
            return plain
    return reply


def _action_catalog_for_prompt() -> list[dict[str, str]]:
    """Export user-selectable action keys for LLM grounding (exclude auto investigation).

    Purpose:
        Give the model an allow-list of playbook_action_keys it may emit.

    Outputs:
        List of {key, category, label, hint} — investigation category omitted.

    Validation:
        Only keys present here (via ACTIONS) can pass ``_validate_playbook_keys``.

    Failure modes:
        Empty catalog would make all playbooks fail validation downstream.
    """
    catalog = []
    for key, meta in ACTIONS.items():
        # Automated investigation steps are not user playbook steps — exclude from LLM catalog.
        if meta["category"] == "investigation":
            continue
        catalog.append(
            {
                "key": key,
                "category": meta["category"],
                "label": meta.get("plain_label", meta["label"]),
                "hint": meta.get("plain_hint", meta["hint"]),
            }
        )
    return catalog


def _scenario_narrative_block(incident: dict) -> str:
    """Include static scenario description when incident key is known.

    Purpose:
        Anchor the model to seeded scenario copy (description, indicator) from incident_scenarios.

    Inputs:
        incident: Dict with optional ``key`` or derivable ``title``.

    Outputs:
        Multi-line scenario block or minimal "Scenario key: unknown" fallback.
    """
    from incident_scenarios import INCIDENTS

    key = incident.get("key") or scenario_key_for_title(incident.get("title", ""))
    scenario = INCIDENTS.get(key, {})
    if not scenario:
        return f"Scenario key: {key or 'unknown'}"
    lines = [
        f"Scenario type: {key}",
        f"Scenario description: {scenario.get('description', '')}",
        f"Primary indicator: {scenario.get('indicator', incident.get('primary_indicator', 'N/A'))}",
    ]
    return "\n".join(lines)


def assemble_context(incident_id: int, *, update_row: dict | None = None) -> dict[str, Any]:
    """Bundle DB facts for AI prompts.

    Purpose:
        Single incident context package for analysis, chat, updates, and verification.

    Inputs:
        incident_id: Primary key in incidents table.
        update_row: Optional opened update alert row for ``analyze_incident_update``.

    Outputs:
        Large dict (incident, events, actions, indicators, playbook, chat, etc.) or {} if missing.

    Context assembly strategy:
        Pull normalized rows from ``db`` helpers; cap chat at 40 messages; prefer canonical
        session thread when ``get_incident_chat_session_id`` returns an id.

    Validation:
        Playbook JSON parsed defensively; scenario key derived from title if absent.

    Failure modes:
        Unknown incident_id → empty dict (callers must handle).
    """
    incident_row = db.get_incident_by_id(incident_id)
    if not incident_row:
        return {}

    ctx_df = db.get_ai_incident_context(incident_id)
    events_df = db.get_incident_events(incident_id)
    actions = db.get_incident_actions_list(incident_id)
    indicators = db.get_incident_indicators(incident_id)
    recommendations = db.get_recommendations_for_incident(incident_id)
    completed = db.get_incident_action_keys_completed(incident_id)
    playbook_rec = db.get_active_playbook_recommendation(incident_id)
    updates = db.get_updates_for_incident(incident_id)
    chat_messages = db.get_all_messages_for_incident(incident_id, limit=40)
    canonical_session_id = db.get_incident_chat_session_id(incident_id)
    if canonical_session_id:
        chat_messages = db.get_messages_for_session(canonical_session_id)
        if len(chat_messages) > 40:
            chat_messages = chat_messages[-40:]

    incident = dict(incident_row)
    incident["key"] = scenario_key_for_title(incident.get("title", ""))
    if not ctx_df.empty:
        row = ctx_df.iloc[0]
        incident["event_logs"] = row.get("event_logs", "")

    playbook_keys: list[str] = []
    if playbook_rec and playbook_rec.get("playbook_actions_json"):
        try:
            playbook_keys = json.loads(playbook_rec["playbook_actions_json"])
        except json.JSONDecodeError:
            playbook_keys = []

    return {
        "incident": incident,
        "events": events_df.to_dict(orient="records") if not events_df.empty else [],
        "actions_taken": actions,
        "indicators": indicators,
        "recommendations": recommendations,
        "completed_action_keys": completed,
        "action_catalog": _action_catalog_for_prompt(),
        "system_context": assemble_system_context(
            incident_row.get("device_id"),
            incident_id,
        ),
        "playbook_recommendation": playbook_rec,
        "playbook_action_keys": playbook_keys,
        "incident_updates": updates,
        "chat_messages": chat_messages,
        "update_row": update_row,
        "scenario_narrative": _scenario_narrative_block(incident),
    }


def assemble_system_context(device_id: int | None, incident_id: int | None) -> dict[str, Any]:
    """Derive home-network memory from existing DB rows for AI grounding.

    Purpose:
        Supply device profile + prior incident history so the model can reference past outcomes.

    Inputs:
        device_id: FK from incident row; None skips memory block.
        incident_id: Used to attach current incident's update rows.

    Outputs:
        Dict with device, prior_incidents, trust/escalate counts, or {} if no device.

    Failure modes:
        Missing device row → empty dict (prompt still works without network memory).
    """
    if not device_id:
        return {}

    device = db.get_device_row(int(device_id))
    if not device:
        return {}

    prior_incidents = db.get_incidents_for_device(int(device_id), limit=8)
    updates = db.get_updates_for_incident(incident_id) if incident_id else []

    trust_count = 0
    escalate_count = 0
    # Lightweight outcome stats so the model can reference prior trust vs mitigation patterns.
    for prior in prior_incidents:
        if prior.get("status") == "Trusted":
            trust_count += 1
        elif prior.get("status") in ("Mitigated", "False Positive"):
            escalate_count += 1

    return {
        "device": device,
        "prior_incidents": prior_incidents,
        "incident_updates": updates,
        "trust_resolutions": trust_count,
        "mitigated_or_fp_resolutions": escalate_count,
    }


def format_playbook_state_block(
    incident_id: int,
    *,
    expert_mode: bool = False,
) -> str:
    """Render current playbook order, completed/remaining steps, and next step.

    Purpose:
        Authoritative playbook snapshot for prompts — complements model suggestions.

    Inputs:
        incident_id: Loads active playbook recommendation from DB.
        expert_mode: Use technical labels vs plain_label for display lines.

    Outputs:
        Multi-line "Playbook state:" block or message when no active playbook.

    Validation:
        playbook_actions_json parsed with JSONDecodeError guard.

    Failure modes:
        Invalid JSON in DB → treated as empty playbook list.
    """
    rec = db.get_active_playbook_recommendation(incident_id)
    keys: list[str] = []
    if rec and rec.get("playbook_actions_json"):
        try:
            keys = json.loads(rec["playbook_actions_json"])
        except json.JSONDecodeError:
            keys = []

    if not keys:
        return "\nPlaybook state: no active playbook in database."

    completed = db.get_incident_action_keys_completed(incident_id)
    remaining = [key for key in keys if key not in completed]
    all_labels: list[str] = []
    completed_labels: list[str] = []
    remaining_labels: list[str] = []
    for key in keys:
        action = get_action(key)
        label = action.get("plain_label", action["label"]) if action else key
        if expert_mode and action:
            label = action["label"]
        all_labels.append(label)
        if key in completed:
            completed_labels.append(label)
        else:
            remaining_labels.append(label)

    lines = [
        "\nPlaybook state:",
        f"  Full order: {', '.join(all_labels)}",
        f"  Completed: {', '.join(completed_labels) if completed_labels else 'none'}",
        f"  Remaining: {', '.join(remaining_labels) if remaining_labels else 'none'}",
    ]
    if remaining:
        next_action = get_action(remaining[0])
        next_label = (
            next_action["label"]
            if expert_mode and next_action
            else next_action.get("plain_label", next_action["label"])
            if next_action
            else remaining[0]
        )
        lines.append(f"  Next recommended step: {next_label}")
    if rec:
        lines.append(f"  Playbook summary: {rec.get('recommendation_text', '')}")
    return "\n".join(lines)


def _format_system_context_block(system: dict[str, Any]) -> str:
    """Render device memory dict from ``assemble_system_context`` for prompt injection.

    Purpose:
        Convert prior-incident history into readable lines under "Your network context:".

    Inputs:
        system: Output of ``assemble_system_context`` (may be empty).

    Outputs:
        Newline-joined block or empty string when no device memory exists.
    """
    if not system:
        return ""
    lines = ["\nYour network context:"]
    device = system.get("device", {})
    lines.append(
        f"  Device profile: {device.get('device_name', 'Unknown')} "
        f"({device.get('device_type', 'Other')}), owner {device.get('owner_name', 'N/A')}, "
        f"IP {device.get('internal_ip', 'N/A')}"
    )
    prior = system.get("prior_incidents", [])
    if prior:
        lines.append("  Prior incidents on this device:")
        for row in prior[:5]:
            lines.append(
                f"    - {row.get('title', '')} ({row.get('severity', '')}, "
                f"{row.get('status', '')}, {row.get('created_at', '')})"
            )
    trust = system.get("trust_resolutions", 0)
    esc = system.get("mitigated_or_fp_resolutions", 0)
    if trust or esc:
        lines.append(
            f"  Past outcomes on this device: {trust} trusted, {esc} mitigated/false-positive"
        )
    return "\n".join(lines)


def _format_temporal_block(incident: dict, incident_id: int | None) -> str:
    """Render monitoring gates, blocked actions, and next allowed step for prompts.

    Purpose:
        Encode demo temporal_state rules so the model respects monitoring and blocked keys.

    Inputs:
        incident: Incident row dict; incident_id for temporal helpers.

    Outputs:
        "Temporal state:" section appended in ``_format_context_block``.

    Failure modes:
        get_next_executable_recommended_step errors are swallowed — block still returns partial info.
    """
    from incident_scenarios import get_next_executable_recommended_step
    from temporal_state import (
        format_monitoring_remaining,
        get_blocked_actions,
        get_monitoring_narrative_hours,
        is_monitoring_active,
    )

    incident_dict = dict(incident)
    if incident_id and not incident_dict.get("incident_id"):
        incident_dict["incident_id"] = incident_id

    lines = ["\nTemporal state:"]
    active = is_monitoring_active(incident_dict)
    lines.append(f"  Monitoring active: {'yes' if active else 'no'}")
    if active:
        hours = get_monitoring_narrative_hours(incident_id)
        lines.append(f"  Narrative watch window: {hours}h")
        lines.append(f"  Demo unlock in: {format_monitoring_remaining(incident_dict)}")
        if incident.get("monitor_until"):
            lines.append(f"  Monitor until (gate): {incident['monitor_until']}")

    blocked = get_blocked_actions(incident_dict, incident_id=incident_id)
    if blocked:
        lines.append("  Blocked actions:")
        for key, reason in blocked.items():
            action = get_action(key)
            label = action.get("plain_label", key) if action else key
            lines.append(f"    - {label}: {reason}")

    if incident_id:
        try:
            full_incident = dict(incident)
            full_incident.setdefault("incident_id", incident_id)
            next_key = get_next_executable_recommended_step(full_incident)
            if next_key:
                action = get_action(next_key)
                label = action.get("plain_label", next_key) if action else next_key
                lines.append(f"  Next allowed action: {label}")
            else:
                lines.append("  Next allowed action: none")
        except Exception:
            pass
    return "\n".join(lines)


def _format_context_block(context: dict[str, Any], *, expert_mode: bool = False) -> str:
    """Render context dict as readable text for prompts.

    Purpose:
        Serialize the full incident evidence package for analysis/chat/update prompts.

    Inputs:
        context: Output of ``assemble_context`` (must include ``incident``).
        expert_mode: Label style for playbook section and action display.

    Outputs:
        Large newline-joined string: scenario, events, IOCs, catalog, chat, playbook, temporal.

    Prompt strategy:
        Includes explicit catalog line "use only these keys in playbook_action_keys" so the
        model keys align with ``_validate_playbook_keys``.

    Failure modes:
        Missing optional sections are simply omitted — never raises.
    """
    incident = context.get("incident", {})
    incident_id = incident.get("incident_id")
    lines = [
        context.get("scenario_narrative", ""),
        f"Title: {incident.get('title', 'Unknown')}",
        f"Severity: {incident.get('severity', 'Unknown')}",
        f"Status: {incident.get('status', 'Unknown')}",
        f"Acknowledged: {incident.get('acknowledged_at') or 'no'}",
        f"Authority recommended: {incident.get('authority_recommended', 0)}",
        f"Device: {incident.get('device_name', 'Unknown')}",
        f"IP: {incident.get('internal_ip', 'N/A')}",
        f"MAC: {incident.get('mac_address', 'N/A')}",
        f"Created: {incident.get('created_at', 'N/A')}",
    ]
    if incident.get("event_logs"):
        lines.append(f"Event summaries: {incident['event_logs']}")

    update_row = context.get("update_row")
    if update_row:
        lines.append("\nOpened incident update:")
        lines.append(f"  Type: {update_row.get('update_type', '')}")
        lines.append(f"  Title: {update_row.get('title', '')}")
        lines.append(f"  Summary: {update_row.get('summary_text', '')}")
        if update_row.get("payload_json"):
            lines.append(f"  Payload: {update_row.get('payload_json')}")

    updates = context.get("incident_updates", [])
    if updates:
        lines.append("\nAll incident updates:")
        for row in updates:
            lines.append(
                f"  - [{row.get('update_type', '')}] {row.get('title', '')}: "
                f"{row.get('summary_text', '')} (ack={row.get('acknowledged_at') or 'pending'})"
            )

    events = context.get("events", [])
    if events:
        lines.append("\nSecurity events:")
        for event in events[:50]:
            lines.append(
                f"  - {event.get('Time', '')} | {event.get('Summary', '')} "
                f"({event.get('Protocol', '')} {event.get('Source IP', '')} -> {event.get('Destination IP', '')})"
            )

    actions = context.get("actions_taken", [])
    if actions:
        inv = [a for a in actions if a.get("action_category") == "investigation"]
        resp = [a for a in actions if a.get("action_category") != "investigation"]
        if inv:
            lines.append("\nInvestigation actions:")
            for action in inv:
                auto = " (automated)" if action.get("is_automated") else ""
                lines.append(
                    f"  - {action.get('action_key', '')}{auto}: {action.get('result_summary', '')}"
                )
        if resp:
            lines.append("\nResponse actions taken:")
            for action in resp:
                lines.append(
                    f"  - [{action.get('action_category', '')}] {action.get('action_key', '')}: "
                    f"{action.get('result_summary', '')}"
                )

    indicators = context.get("indicators", [])
    if indicators:
        lines.append("\nIndicators of compromise:")
        for ioc in indicators:
            lines.append(
                f"  - {ioc.get('indicator_type', '')}: {ioc.get('indicator_value', '')} "
                f"(confidence {ioc.get('confidence_score', 'N/A')})"
            )

    completed = context.get("completed_action_keys", [])
    if completed:
        lines.append(f"\nCompleted response action keys: {', '.join(sorted(completed))}")

    recs = context.get("recommendations", [])
    if recs:
        lines.append("\nRecommendations on file:")
        for rec in recs:
            lines.append(f"  - [{rec.get('recommendation_type', '')}] {rec.get('recommendation_text', '')}")

    catalog = context.get("action_catalog", [])
    if catalog:
        # Critical grounding: model must only emit keys listed here (validated post-hoc).
        lines.append("\nAvailable response actions (use only these keys in playbook_action_keys):")
        for item in catalog:
            lines.append(f"  - {item['key']} ({item['category']}): {item['label']} — {item['hint']}")

    chat_messages = context.get("chat_messages", [])
    if chat_messages:
        lines.append("\nPrior chat on this incident:")
        for msg in chat_messages[-20:]:
            lines.append(f"  {msg.get('role', 'user')}: {(msg.get('content') or '')[:300]}")

    if incident_id:
        lines.append(format_playbook_state_block(incident_id, expert_mode=expert_mode))

    lines.append(_format_temporal_block(incident, incident_id))
    lines.append(_format_system_context_block(context.get("system_context", {})))

    return "\n".join(lines)


def _validate_playbook_keys(raw_keys: list[Any]) -> list[str]:
    """Filter and sort action keys by IR category order.

    Purpose:
        Never trust raw LLM playbook_action_keys — normalize, dedupe, allow-list, sort.

    Inputs:
        raw_keys: Arbitrary list from parsed JSON (strings or coercible values).

    Outputs:
        Ordered unique keys present in ACTIONS, excluding investigation category.

    Validation steps:
        1. ``normalize_action_key`` each entry.
        2. Drop unknown keys, duplicates, and investigation-category actions.
        3. Sort by ACTION_CATEGORIES order, preserving relative order within category.

    Failure modes:
        Empty input or all invalid keys → [] (callers treat as analysis failure).
    """
    seen: set[str] = set()
    valid: list[str] = []
    for raw in raw_keys:
        key = normalize_action_key(str(raw).strip())
        if key in ACTIONS and key not in seen and ACTIONS[key]["category"] != "investigation":
            seen.add(key)
            valid.append(key)

    order = list(valid)
    valid.sort(key=lambda k: (_CATEGORY_ORDER.get(ACTIONS[k]["category"], 99), order.index(k)))
    return valid


def filter_remaining_playbook_keys(proposed: list[str], incident_id: int) -> list[str]:
    """Validate and drop completed or investigation keys from a proposal.

    Purpose:
        Plan-update proposals must only contain steps still available to the user.

    Inputs:
        proposed: Raw model playbook_action_keys list.
        incident_id: Used to load completed keys from DB.

    Outputs:
        Subset of validated keys not yet completed on this incident.

    Failure modes:
        All proposed keys already done → [] (suppresses plan-update UI).
    """
    validated = _validate_playbook_keys(proposed)
    completed = db.get_incident_action_keys_completed(incident_id)
    return [key for key in validated if key not in completed]


def merge_playbook_update(
    current_keys: list[str],
    completed_keys: set[str],
    proposed_keys: list[str],
) -> list[str]:
    """Merge AI-proposed keys with completed steps already taken.

    Purpose:
        When user accepts a plan update, preserve completed prefix and replace tail.

    Inputs:
        current_keys: Existing playbook order from DB.
        completed_keys: Set of action keys already executed.
        proposed_keys: New tail from model (validated internally).

    Outputs:
        head(completed from current) + validated proposed tail, or current_keys if noop.

    Validation:
        Proposed keys run through ``_validate_playbook_keys``; skips completed/duplicate.

    Failure modes:
        Empty validated proposal → returns copy of current_keys unchanged.
    """
    validated = _validate_playbook_keys(proposed_keys)
    if not validated:
        return list(current_keys)

    head = [key for key in current_keys if key in completed_keys]
    seen = set(head)
    tail: list[str] = []
    # Append validated proposed keys that are not already completed or duplicated in head.
    for key in validated:
        if key in completed_keys or key in seen:
            continue
        seen.add(key)
        tail.append(key)

    merged = head + tail
    return merged if merged else list(current_keys)


def _analysis_error(incident: dict, detail: str) -> AnalysisResult:
    """Build a failed AnalysisResult with homeowner-facing explanation.

    Purpose:
        Uniform error envelope when Ollama/JSON/validation fails after investigation.

    Inputs:
        incident: Used for title/device interpolation in analysis markdown.
        detail: Technical reason appended for the user.

    Outputs:
        AnalysisResult with success=False, used_ai=False, empty playbook keys.
    """
    device = incident.get("device_name") or incident.get("source", "the device")
    return AnalysisResult(
        analysis=(
            f"Automated investigation finished for **{incident.get('title', 'this incident')}** "
            f"on **{device}**, but Sentinel could not generate an AI response plan.\n\n{detail}"
        ),
        playbook_action_keys=[],
        success=False,
        error_detail=detail,
        used_ai=False,
    )


def analyze_incident(incident_id: int, incident: dict | None = None) -> AnalysisResult:
    """Run post-investigation AI analysis and return validated playbook recommendation.

    Purpose:
        Core Assignment 5.2 flow — convert DB evidence into an ordered response playbook.

    Inputs:
        incident_id: Target incident after automated investigation completes.
        incident: Optional pre-built row; loaded from DB if omitted.

    Outputs:
        AnalysisResult with validated keys, authority flag, and playbook_text on success.

    Prompt strategy:
        System: incident manager persona + JSON schema + evidence-matching rules.
        User: full ``_format_context_block`` dump.
        Temperature 0.2 for deterministic key ordering.

    Validation steps:
        1. check_ai_status before HTTP call.
        2. _extract_json on response.
        3. _validate_playbook_keys — fail if empty.
        4. Default analysis text if model omits analysis field.

    Failure modes:
        Missing incident, AI down, timeout, invalid JSON, no valid keys → _analysis_error.
    """
    incident_row = db.get_incident_by_id(incident_id)
    if not incident_row:
        return AnalysisResult(
            analysis="Incident not found.",
            playbook_action_keys=[],
            success=False,
            error_detail="Incident not found in database.",
        )

    if incident is None:
        incident = dict(incident_row)
        incident["key"] = scenario_key_for_title(incident.get("title", ""))

    status = check_ai_status()
    if not status.get("ok"):
        return _analysis_error(incident, status.get("detail", "AI unavailable."))

    context = assemble_context(incident_id)
    context_block = _format_context_block(context)

    # Prompt construction: persona + strict JSON contract + scenario-evidence guardrails.
    system = (
        _INCIDENT_MANAGER_PERSONA
        + "Analyze ONLY the provided database evidence. "
        "Response actions are simulated in this prototype — do not claim real firewall changes. "
        "Choose playbook_action_keys that match the scenario evidence — do not recommend exfiltration "
        "steps (like sever_connection) for internal lateral scanning unless outbound transfer evidence exists. "
        "Respond with a single JSON object (no markdown outside JSON) with keys: "
        "analysis (plain-language summary for a homeowner), "
        "playbook_action_keys (ordered list of action keys from the catalog, excluding investigation keys), "
        "authority_recommended (boolean — true for serious crimes like exfiltration or ransomware), "
        "general_recommendations (array of short advisory strings)."
    )
    user = f"Analyze this incident after automated investigation:\n\n{context_block}"

    raw = _chat(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.2,
    )
    if not raw:
        return _analysis_error(
            incident,
            f"No response from Ollama within {AI_REQUEST_TIMEOUT}s. {format_ai_error_message()}",
        )

    parsed = _extract_json(raw)
    if not parsed:
        return _analysis_error(
            incident,
            f"AI returned invalid JSON. Raw excerpt: {_truncate_raw(raw)}",
        )

    keys = _validate_playbook_keys(parsed.get("playbook_action_keys", []))
    if not keys:
        return _analysis_error(
            incident,
            "AI returned no valid playbook_action_keys from the action catalog.",
        )

    analysis_text = str(parsed.get("analysis", "")).strip()
    if not analysis_text:
        analysis_text = (
            f"Investigation complete for **{incident.get('title', 'this incident')}** "
            f"on **{incident.get('device_name', 'the device')}**."
        )
    authority = bool(parsed.get("authority_recommended", False))
    general = [str(g).strip() for g in parsed.get("general_recommendations", []) if str(g).strip()]

    return AnalysisResult(
        analysis=analysis_text,
        playbook_action_keys=keys,
        authority_recommended=authority,
        general_recommendations=general,
        playbook_text=playbook_recommendation_text(incident, keys),
        used_ai=True,
        success=True,
    )


def _recent_chat_history(
    incident_id: int | None,
    in_memory_history: list[dict],
    *,
    limit: int = 10,
) -> list[dict]:
    """Merge canonical DB thread with in-memory chat for prompt context.

    Purpose:
        Include Streamlit session messages not yet persisted plus DB canonical session.

    Inputs:
        incident_id: None for general chat (in-memory only).
        in_memory_history: Current UI thread tail.
        limit: Max messages to include in prompt.

    Outputs:
        Deduplicated merged list, last ``limit`` messages.

    Failure modes:
        Missing session falls back to get_all_messages_for_incident.
    """
    if not incident_id:
        return in_memory_history[-limit:]

    canonical_session_id = db.get_incident_chat_session_id(incident_id)
    db_history = (
        db.get_messages_for_session(canonical_session_id)
        if canonical_session_id
        else db.get_all_messages_for_incident(incident_id, limit=limit)
    )
    if not in_memory_history:
        return db_history[-limit:]

    merged = list(db_history)
    for message in in_memory_history:
        if not merged:
            merged.append(message)
            continue
        last = merged[-1]
        if last.get("role") == message.get("role") and last.get("content") == message.get("content"):
            continue
        merged.append(message)

    return merged[-limit:]


def answer_chat(
    user_message: str,
    incident_id: int | None,
    history: list[dict],
    *,
    chat_scope: ChatScope | None = None,
    expert_mode: bool = False,
    playbook_phase: str = "closed",
    awaiting_get_started: bool = False,
    incident: dict | None = None,
) -> ChatReplyResult:
    """Answer a free-form chat question; optionally propose a playbook revision.

    Purpose:
        Unified chat entry for general dashboard Q&A and per-incident investigation.

    Inputs:
        user_message: Latest user utterance.
        incident_id: Set for incident scope; None for general.
        history: In-memory chat tail from the UI session.
        chat_scope: Explicit "general" | "incident"; inferred from incident_id if None.
        expert_mode: Tone and label style.
        playbook_phase: Current UI phase string injected into incident context.
        awaiting_get_started: Whether user has not yet started playbook.
        incident: Optional incident row for scope rules.

    Outputs:
        ChatReplyResult — plan-update fields set only for incident scope + valid proposal.

    Prompt strategy:
        System from ``build_chat_system_prompt`` (scope + output format split).
        User: context block + playbook state + recent chat + question.

    Validation:
        Incident scope: parse JSON, validate keys, filter_remaining_playbook_keys.
        General scope: _conversational_reply only (no JSON parsing for plan updates).

    Failure modes:
        Empty message → placeholder; AI down → format_ai_error_message or action-bar hint.
    """
    from sentinel_actions import PLACEHOLDER_AI_REPLY

    fallback = ChatReplyResult(reply=PLACEHOLDER_AI_REPLY)

    if not user_message.strip():
        return fallback

    # Chat scope rules: incident_id implies single-incident grounding unless overridden.
    if chat_scope is None:
        chat_scope = "incident" if incident_id else "general"

    if not is_available():
        fallback_msg = (
            "I cannot reach the local AI service right now. "
            "Use the action bar below to continue the playbook."
            if chat_scope == "incident"
            else "I cannot reach the local AI service right now. Try again in a moment."
        )
        return ChatReplyResult(reply=format_ai_error_message("Chat") or fallback_msg)

    context_block = ""
    playbook_line = ""
    context_label = "Dashboard context"

    # Context assembly branches on scope — incident loads full assemble_context graph.
    if chat_scope == "incident" and incident_id:
        context = assemble_context(incident_id)
        if incident is None:
            incident = context.get("incident")
        context_block = _format_context_block(context, expert_mode=expert_mode)
        context_block += f"\n\nCurrent playbook phase: {playbook_phase}"
        playbook_line = format_playbook_state_block(incident_id, expert_mode=expert_mode)
        context_label = "Incident context"
    else:
        general_context = assemble_general_context()
        context_block = _format_general_context_block(general_context, expert_mode=expert_mode)

    history_lines = []
    recent_history = _recent_chat_history(incident_id if chat_scope == "incident" else None, history, limit=10)
    for msg in recent_history:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if content:
            history_lines.append(f"{role}: {content}")

    system = build_chat_system_prompt(
        chat_scope=chat_scope,
        expert_mode=expert_mode,
        incident=incident,
    )

    # User message stacks: evidence → playbook → session flags → history → question.
    user_parts = [
        f"{context_label}:\n{context_block or 'No context available.'}",
    ]
    if chat_scope == "incident":
        user_parts.append(playbook_line)
        user_parts.append(f"Awaiting get started: {awaiting_get_started}")
    user_parts.append("Recent chat:\n" + ("\n".join(history_lines) if history_lines else "(none)"))
    user_parts.append(f"User question: {user_message.strip()}")
    user = "\n\n".join(part for part in user_parts if part)

    raw = _chat(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.3,
    )

    # General chat: prose-only path — never expose JSON plan-update fields.
    if chat_scope == "general":
        return ChatReplyResult(reply=_conversational_reply(raw or ""))

    # Incident chat: parse structured JSON for optional playbook revision offer.
    parsed = _extract_json(raw or "")
    if parsed:
        reply = _merge_chat_reply(str(parsed.get("reply", "")).strip(), raw or "")
        reply = reply.strip() or _conversational_reply(raw or "")
    else:
        reply = _conversational_reply(raw or "")

    suggest = bool(parsed.get("suggest_plan_update", False)) if parsed else False
    summary = str(parsed.get("plan_update_summary", "")).strip() if parsed else ""
    proposed = _validate_playbook_keys(parsed.get("playbook_action_keys", [])) if parsed else []
    if incident_id and proposed:
        proposed = filter_remaining_playbook_keys(proposed, incident_id)

    # All three required to surface plan-update confirmation in the UI.
    if not suggest or not proposed or not summary:
        return ChatReplyResult(reply=reply)

    question = f"**Should I update your response plan?** {summary}"
    return ChatReplyResult(
        reply=reply,
        suggest_plan_update=True,
        plan_update_summary=summary,
        proposed_playbook_keys=proposed,
        plan_update_question=question,
    )


def generate_step_guidance(
    incident_id: int,
    incident: dict,
    next_key: str | None,
    *,
    playbook_phase: str = "closed",
    expert_mode: bool = False,
) -> str | None:
    """Generate AI narrative for the next playbook step; None triggers template fallback.

    Purpose:
        Optional prose above the sticky action bar for the next recommended step.

    Inputs:
        incident_id, incident row, next_key from playbook engine.
        playbook_phase, expert_mode for tone/labels.

    Outputs:
        1-2 paragraph string from Ollama, or None to use static template.

    Failure modes:
        Monitoring active, AI down, missing next_key/action → None (caller uses fallback).
    """
    from temporal_state import is_monitoring_active

    if playbook_phase == "monitoring" or is_monitoring_active(incident):
        return None
    if not is_available() or not next_key:
        return None

    context = assemble_context(incident_id)
    action = get_action(next_key)
    if not action:
        return None

    label = action["label"] if expert_mode else action.get("plain_label", action["label"])
    hint = action["hint"] if expert_mode else action.get("plain_hint", action["hint"])
    system = (
        get_chat_tone(expert_mode=expert_mode)
        + "Write 1-2 short paragraphs explaining the NEXT recommended step. "
        "End by inviting them to use the action bar below. "
        "Do not invent facts beyond the context."
    )
    user = (
        f"{_format_context_block(context, expert_mode=expert_mode)}\n\n"
        f"Current phase: {playbook_phase}\n"
        f"Next action: {label} — {hint}\n"
        "Explain why this step matters and what it will do (simulated)."
    )
    return _chat(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.15,
    )


def generate_session_summary(incident_id: int, incident_title: str) -> str | None:
    """AI summary of prior chat sessions for an incident.

    Purpose:
        Bullet recap of analyst/user actions for session history UI.

    Inputs:
        incident_id: Loads full context including prior chat section.
        incident_title: Human label in user prompt.

    Outputs:
        Model prose or None if AI unavailable.

    Failure modes:
        is_available() false → None; _chat failure → None.
    """
    if not is_available():
        return None

    context = assemble_context(incident_id)
    system = (
        "Summarize prior analyst chat sessions for this incident in bullet points. "
        "Focus on what the user did and what response steps were taken."
    )
    user = (
        f"Incident: {incident_title}\n\n"
        f"{_format_context_block(context)}\n\n"
        "Use the prior chat section in context."
    )
    return _chat([{"role": "system", "content": system}, {"role": "user", "content": user}])


def generate_resume_briefing(
    incident_id: int,
    incident: dict,
    *,
    playbook_phase: str = "closed",
    next_key: str | None = None,
    playbook_complete: bool = False,
    expert_mode: bool = False,
) -> str | None:
    """AI 'where we left off' briefing for returning users.

    Purpose:
        Resume narrative when user reopens an in-progress incident.

    Inputs:
        incident_id, incident dict, playbook_phase, next_key, playbook_complete, expert_mode.

    Outputs:
        Short briefing string or None if AI unavailable.

    Prompt strategy:
        Tone from get_chat_tone; user block includes format_playbook_state via context.

    Failure modes:
        is_available() false → None.
    """
    if not is_available():
        return None

    context = assemble_context(incident_id)
    next_label = ""
    if next_key:
        action = get_action(next_key)
        if action:
            next_label = action["label"] if expert_mode else action.get("plain_label", action["label"])

    tone = get_chat_tone(expert_mode=expert_mode)
    system = (
        tone
        + "Tell the user where they left off. "
        "Recap status, completed steps, and the single next recommended action from context only."
    )
    user = (
        f"{_format_context_block(context, expert_mode=expert_mode)}\n\n"
        f"Phase: {playbook_phase}\n"
        f"Playbook complete: {playbook_complete}\n"
        f"Next step: {next_key or 'none'} ({next_label})"
    )
    return _chat([{"role": "system", "content": system}, {"role": "user", "content": user}])


def generate_incident_report(incident_id: int) -> str | None:
    """Generate a full markdown incident report for the documentation phase.

    Purpose:
        Formal IR report from DB facts only (documentation playbook step).

    Inputs:
        incident_id: Full assemble_context source.

    Outputs:
        Markdown report string or None if AI unavailable.

    Prompt strategy:
        Fixed section list in system prompt; temperature 0.2 for factual tone.

    Failure modes:
        is_available() false or _chat None → None.
    """
    if not is_available():
        return None

    context = assemble_context(incident_id)
    system = (
        "Write a formal incident response report in Markdown with sections: "
        "Executive Summary, Timeline, Indicators, Actions Taken, Recommendations, Current Status. "
        "Use only facts from the provided context."
    )
    user = f"Generate the incident report:\n\n{_format_context_block(context)}"
    return _chat(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.2,
    )


def _update_error(update_row: dict | None, detail: str) -> UpdateAnalysisResult:
    """Build failed UpdateAnalysisResult preserving update summary when possible.

    Purpose:
        Uniform error path for analyze_incident_update.

    Inputs:
        update_row: Opened update alert (may be None).
        detail: Technical failure reason.

    Outputs:
        UpdateAnalysisResult with success=False, used_ai=False.
    """
    summary = (
        update_row.get("summary_text", "Incident update received.")
        if update_row
        else "Incident update received."
    )
    return UpdateAnalysisResult(
        summary=summary,
        success=False,
        error_detail=detail,
        used_ai=False,
    )


def _remaining_playbook_keys(incident_id: int) -> list[str]:
    """Return scenario-recommended keys not yet completed on this incident.

    Purpose:
        Baseline remaining steps for comparing AI plan-update proposals.

    Outputs:
        Filtered list from get_recommended_action_keys minus completed DB keys.
    """
    from incident_scenarios import get_recommended_action_keys

    keys = get_recommended_action_keys(incident_id)
    completed = db.get_incident_action_keys_completed(incident_id)
    return [key for key in keys if key not in completed]


def analyze_incident_update(incident_id: int, update_row: dict) -> UpdateAnalysisResult:
    """Re-analyze an incident after a monitoring or status update alert.

    Purpose:
        Summarize what changed after re-investigation; optionally propose playbook tail rewrite.

    Inputs:
        incident_id: Parent incident.
        update_row: The update alert the user opened (type, title, summary_text).

    Outputs:
        UpdateAnalysisResult with summary, narrative, and conditional plan-update flags.

    Prompt strategy:
        System emphasizes UPDATE (not new threat), incomplete keys only, simulated actions.
        User: update metadata + full context block including update_row highlight.

    Validation:
        JSON parse → filter_remaining_playbook_keys → suppress suggest if keys == current_remaining.

    Failure modes:
        Missing update/incident, AI down, timeout, invalid JSON → _update_error.
    """
    from incident_scenarios import (
        build_active_incident_from_db,
        format_chat_action_prompt,
        get_next_executable_recommended_step,
    )

    if not update_row:
        return _update_error(None, "Update record not found.")

    row = db.get_incident_by_id(incident_id)
    if not row:
        return _update_error(update_row, "Incident not found in database.")

    incident = build_active_incident_from_db(row)
    update_summary = update_row.get("summary_text", "")

    status = check_ai_status()
    if not status.get("ok"):
        return _update_error(update_row, status.get("detail", "AI unavailable."))

    context = assemble_context(incident_id, update_row=update_row)
    context_block = _format_context_block(context)
    update_type = update_row.get("update_type", "unknown")
    update_title = update_row.get("title", "")

    system = (
        _INCIDENT_MANAGER_PERSONA
        + "The user opened an incident UPDATE alert (not a new threat). "
        "Automated re-investigation just ran. Summarize what changed and recommend next steps. "
        "playbook_action_keys must list ONLY incomplete response steps not in completed_action_keys. "
        "Do not repeat completed steps. Default suggest_plan_update to false unless remaining steps "
        "materially differ from the current DB playbook. "
        "Response actions are simulated. "
        "Respond with JSON keys: summary, playbook_action_keys, suggest_plan_update, "
        "plan_update_summary, next_step_narrative."
    )
    user = (
        f"Update type: {update_type}\n"
        f"Update title: {update_title}\n"
        f"Update summary: {update_summary}\n\n"
        f"{context_block}"
    )

    raw = _chat(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.2,
    )
    if not raw:
        return _update_error(
            update_row,
            f"No response from Ollama within {AI_REQUEST_TIMEOUT}s.",
        )

    parsed = _extract_json(raw)
    if not parsed:
        return _update_error(
            update_row,
            f"AI returned invalid JSON. Raw excerpt: {_truncate_raw(raw)}",
        )

    keys = filter_remaining_playbook_keys(
        parsed.get("playbook_action_keys", []),
        incident_id,
    )
    current_remaining = _remaining_playbook_keys(incident_id)

    summary = str(parsed.get("summary", "")).strip() or update_summary
    plan_summary = str(parsed.get("plan_update_summary", "")).strip()
    suggest = bool(parsed.get("suggest_plan_update", False)) and bool(plan_summary)
    # Suppress noop plan updates when model keys match scenario remaining steps exactly.
    if suggest and keys == current_remaining:
        suggest = False
        plan_summary = ""

    narrative = str(parsed.get("next_step_narrative", "")).strip()
    if not narrative:
        next_key = get_next_executable_recommended_step(incident)
        narrative = format_chat_action_prompt(incident) if next_key else summary

    return UpdateAnalysisResult(
        summary=summary,
        playbook_action_keys=keys if suggest else current_remaining,
        suggest_plan_update=suggest,
        plan_update_summary=plan_summary,
        next_step_narrative=narrative,
        used_ai=True,
        success=True,
    )


def verify_resolution_action(incident_id: int, action_key: str) -> VerificationResult:
    """AI caution before executing a non-recommended trust/false-alarm/skip action.

    Purpose:
        Friction step for RESOLUTION_SHORTCUT_KEYS when they are not the recommended next step.

    Inputs:
        incident_id: Full context source.
        action_key: Proposed shortcut (normalized against action catalog).

    Outputs:
        VerificationResult with warning, checklist, confirm_label, recommend_cancel.

    Prompt strategy:
        JSON output with evidence-specific warning; shorter if low-risk anomaly.

    Validation:
        Unknown action → immediate failure; parse failure → generic caution + recommend_cancel.

    Failure modes:
        AI down → evidence bullet fallback with format_ai_error_message appended.
    """
    action_key = normalize_action_key(action_key)
    action = get_action(action_key)
    if not action:
        return VerificationResult(
            warning="Unknown action.",
            success=False,
            error_detail=f"Unknown action key: {action_key}",
        )

    label = action.get("plain_label", action["label"])
    context = assemble_context(incident_id)
    context_block = _format_context_block(context)

    if not is_available():
        # Offline verification: static evidence bullets — no fabricated AI warnings.
        lines = [
            f"**Before you {label.lower()}**, review the evidence:",
            "",
        ]
        for ioc in context.get("indicators", [])[:3]:
            lines.append(f"- {ioc.get('indicator_type', '')}: {ioc.get('indicator_value', '')}")
        for act in context.get("actions_taken", [])[-5:]:
            if act.get("action_category") != "investigation":
                lines.append(f"- Already done: {act.get('action_key', '')}")
        lines.append("")
        lines.append(format_ai_error_message("Verification"))
        return VerificationResult(
            warning="\n".join(lines),
            checklist=["I have reviewed the evidence above."],
            confirm_label=f"Confirm {label}",
            recommend_cancel=True,
            success=False,
            error_detail=check_ai_status().get("detail"),
        )

    system = (
        _INCIDENT_MANAGER_PERSONA
        + "The user is about to take a resolution shortcut that is NOT the current recommended next step. "
        "Warn them if the evidence conflicts with this choice. Be specific about scenario behavior. "
        "Respond with JSON: warning (2-3 sentences), checklist (array of 3-5 short confirm bullets), "
        "confirm_label (short button text), recommend_cancel (boolean)."
    )
    user = (
        f"Proposed action: {label} ({action_key})\n\n"
        f"{context_block}\n\n"
        "Explain risks if this is premature. If low-risk anomaly and monitoring is clear, be shorter."
    )

    raw = _chat(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.2,
    )
    parsed = _extract_json(raw or "")
    if not parsed:
        # Parse failure still allows proceed-with-caution UX via generic warning.
        return VerificationResult(
            warning=(
                f"You are about to **{label}**. The evidence on file may not support closing this incident yet. "
                "Review indicators and completed steps before confirming."
            ),
            checklist=[
                "I understand this may not match the recommended playbook order.",
                "I have reviewed the device and incident evidence.",
            ],
            confirm_label=f"Confirm {label}",
            recommend_cancel=True,
            success=False,
            error_detail=f"Could not parse verification response: {_truncate_raw(raw or '')}",
        )

    warning = str(parsed.get("warning", "")).strip() or f"Please confirm you want to {label}."
    checklist = [str(c).strip() for c in parsed.get("checklist", []) if str(c).strip()]
    if not checklist:
        checklist = ["I have reviewed the evidence and accept the risk."]
    confirm_label = str(parsed.get("confirm_label", "")).strip() or f"Confirm {label}"
    recommend_cancel = bool(parsed.get("recommend_cancel", False))

    return VerificationResult(
        warning=warning,
        checklist=checklist,
        confirm_label=confirm_label,
        recommend_cancel=recommend_cancel,
        success=True,
    )
