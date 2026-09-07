"""Type 8: detect trojans, backdoors, bots, and remote-access trojans."""
from __future__ import annotations

import re
from collections.abc import Mapping

from services.security.models import SecurityRuleHit


_FAMILY_RE = re.compile(
    r"\b(?:asyncrat|njrat|quasar(?:rat)?|remcos(?: rat)?|darkcomet|nanocore|netwire|"
    r"gh0st rat|ghost rat|xworm|venom rat|warzone rat|orcus rat|adwind|jrat|"
    r"blackshades|poison ivy|plugx|shadowpad|turla backdoor|metasploit meterpreter|"
    r"cobalt strike beacon|sliver implant|mylo botnet|mirai botnet)\b",
    re.I,
)
_REMOTE_CONTROL_RE = re.compile(
    r"\b(?:remote access trojan|remote administration trojan|covert remote access|"
    r"unauthorized remote access|remote command execution|execute remote commands?|"
    r"attacker-controlled remote shell|reverse shell|bind shell|command shell backdoor|"
    r"persistent backdoor|hidden backdoor|webshell backdoor)\b",
    re.I,
)
_C2_RE = re.compile(
    r"\b(?:command[- ]and[- ]control|c2|c&c)\b.{0,140}\b(?:beacon|server|channel|commands?|tasking|callback|connect)\b"
    r"|\b(?:beacon|callback)\b.{0,140}\b(?:command[- ]and[- ]control|c2|c&c|attacker server)\b",
    re.I | re.S,
)
_BOTNET_RE = re.compile(
    r"\b(?:enroll|add|join|register|infect)\b.{0,120}\b(?:botnet|bot network|zombie network)\b"
    r"|\b(?:botnet|bot network|zombie host)\b.{0,160}\b(?:ddos|distributed denial|spam task|proxy task|commands?|tasking)\b",
    re.I | re.S,
)
_SURVEILLANCE_RE = re.compile(
    r"\b(?:remotely|covertly|silently)\b.{0,180}\b(?:control the desktop|capture (?:the )?screen|"
    r"activate (?:the )?(?:webcam|microphone)|record audio|upload files?|download files?|"
    r"execute commands?|manage processes?)\b",
    re.I | re.S,
)
_PERSISTENCE_RE = re.compile(
    r"\b(?:establish|install|create|maintain)\b.{0,100}\b(?:persistence|backdoor|remote shell)\b"
    r"|\b(?:registry run key|scheduled task|startup persistence|service persistence)\b.{0,140}"
    r"\b(?:backdoor|remote access|c2|beacon)\b",
    re.I | re.S,
)
_DELIVERY_RE = re.compile(
    r"\b(?:install|run|execute|launch|open|download|enable|load|deploy|payload|attachment|update)\b"
    r"|https?://",
    re.I,
)
_ACTIVE_DELIVERY_RE = re.compile(
    r"\b(?:install|run|execute|launch|open|download|enable|load|deploy)\b.{0,120}"
    r"(?:https?://|\b(?:payload|attachment|installer|implant|agent|script|archive)\b)"
    r"|(?:https?://|\b(?:payload|attachment|installer|implant|agent|script|archive)\b).{0,120}"
    r"\b(?:install|run|execute|launch|open|download|enable|load|deploy)\b",
    re.I | re.S,
)
_ANALYSIS_RE = re.compile(
    r"\b(?:remote access trojan|rat malware|malicious remote access|trojan backdoor|"
    r"botnet malware|malicious bot|command[- ]and[- ]control implant|backdoor malware)\b",
    re.I,
)
_CLEAN_CONTEXT_RE = re.compile(
    r"\b(?:clean|benign|safe|approved|authorized|training|awareness|research|report|"
    r"analysis|simulation|administration guide|support session|not malicious|no payload)\b",
    re.I,
)
_TEXT_ATTACHMENT_EXTENSIONS = (
    ".txt", ".log", ".json", ".xml", ".ps1", ".bat", ".cmd", ".js", ".vbs",
    ".hta", ".html", ".py", ".sh", ".conf", ".cfg",
)
_MAX_SAMPLE = 512 * 1024


def _sample(attachment: Mapping) -> str:
    filename = str(attachment.get("filename") or "").casefold()
    content_type = str(attachment.get("content_type") or "").split(";", 1)[0].casefold().strip()
    if not filename.endswith(_TEXT_ATTACHMENT_EXTENSIONS) and content_type not in {
        "text/plain", "text/html", "application/json", "application/javascript"
    }:
        return ""
    data = attachment.get("data")
    if isinstance(data, str):
        return data[:_MAX_SAMPLE]
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data[:_MAX_SAMPLE]).decode("utf-8", errors="ignore")
    return ""


def _metadata_reason(email_data: Mapping, attachments) -> str:
    sources = [email_data] + [item for item in (attachments or []) if isinstance(item, Mapping)]
    for source in sources:
        for key in (
            "is_trojan", "trojan_detected", "backdoor_detected", "bot_detected",
            "botnet_detected", "rat_detected", "remote_access_trojan_detected",
        ):
            value = source.get(key)
            if value is True or (isinstance(value, (int, float)) and value == 1):
                return key.replace("_", " ")
        for key in ("malware_family", "behavior_verdict", "rat_analysis", "c2_analysis", "analysis"):
            value = str(source.get(key) or "").strip()
            if not value or _CLEAN_CONTEXT_RE.search(value):
                continue
            if _ANALYSIS_RE.search(value) or _FAMILY_RE.search(value) or _REMOTE_CONTROL_RE.search(value):
                return f"scanner trojan/backdoor evidence: {value[:120]}"
    return ""


def _behavior_reason(value: str, *, require_delivery: bool) -> str:
    text = str(value or "")
    awareness = bool(_CLEAN_CONTEXT_RE.search(text))
    delivery = bool(_DELIVERY_RE.search(text))
    if awareness and require_delivery and not _ACTIVE_DELIVERY_RE.search(text):
        return ""
    allowed = delivery or not awareness or not require_delivery
    if _FAMILY_RE.search(text) and allowed:
        return "known RAT, backdoor, implant, or botnet family is named"
    if _REMOTE_CONTROL_RE.search(text) and allowed:
        return "covert backdoor, reverse-shell, or remote-command behavior"
    if _C2_RE.search(text) and allowed:
        return "command-and-control beacon or tasking behavior"
    if _BOTNET_RE.search(text) and allowed:
        return "botnet enrollment or malicious bot tasking"
    if _SURVEILLANCE_RE.search(text) and allowed:
        return "covert remote surveillance or host-control behavior"
    if _PERSISTENCE_RE.search(text) and allowed:
        return "persistent backdoor or remote-shell behavior"
    return ""


def evaluate_trojan_backdoor_bot_rat_rules(*, email_data: Mapping, text: str, attachments) -> list[SecurityRuleHit]:
    reason = _metadata_reason(email_data, attachments) or _behavior_reason(str(text or ""), require_delivery=True)
    if not reason:
        for attachment in attachments or []:
            if not isinstance(attachment, Mapping):
                continue
            sample = _sample(attachment)
            if not sample:
                continue
            sample_reason = _behavior_reason(sample, require_delivery=False)
            if sample_reason:
                filename = str(attachment.get("filename") or "attachment")
                reason = f"{sample_reason} in attachment: {filename}"
                break
    if not reason:
        return []
    return [SecurityRuleHit(
        rule_id="type8-trojan-backdoor-bot-rat",
        points=100,
        reason=f"Trojan, backdoor, bot, or RAT detected ({reason})",
        categories=("Malware",),
        strong_flag="trojan-backdoor-bot-rat",
    )]
