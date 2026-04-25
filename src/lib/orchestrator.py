from typing import Any, Dict
from lib.ghostmcp_runner import GhostMCPToolRunner
from lib.llm_client import Client as LLMClient
import json
import os
import re
import shutil
import time
from datetime import datetime
from jsonschema import validate, ValidationError


# -----------------------------
# Planner schema
# -----------------------------
PLAN_SCHEMA = {
    "type": "object",
    "required": ["thought", "action", "expected_result"],
    "properties": {
        "thought": {"type": "string"},
        "expected_result": {"type": "string"},
        "action": {
            "type": "object",
            "required": ["tool", "args"],
            "properties": {
                "tool": {"type": "string"},
                "args": {"type": "object"},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}


import ipaddress
from lib.reporting_engine import generate_markdown_report


class Orchestrator:
    _REQUIRED_TOOL_ARGS: Dict[str, list[str]] = {}

    def __init__(self):
        # GhostMCP runs in-process (imported as a module via submodule + editable install)
        self.mcp = GhostMCPToolRunner()
        self.llm = LLMClient()
        self.allowed_cidrs = self._load_scope()

    def _load_scope(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        # Load from env or file in future; default to RFC1918 + loopback for safety
        scope_str = os.getenv(
            "ARES_ALLOWED_CIDRS",
            "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        )
        return [ipaddress.ip_network(c.strip()) for t in scope_str.split(",") if (c := t.strip())]

    def _validate_scope(self, targets: list[str]) -> list[str]:
        allowed_cidrs = getattr(self, "allowed_cidrs", None)
        if allowed_cidrs is None:
            allowed_cidrs = self._load_scope()
            self.allowed_cidrs = allowed_cidrs

        valid = []
        for target in targets:
            try:
                # Handle single IP or hostname (best effort)
                # Note: Hostname resolution happens later in tools, but we check CIDRs here
                ip = ipaddress.ip_address(target)
                if any(ip in cidr for cidr in allowed_cidrs):
                    valid.append(target)
            except ValueError:
                # Likely a hostname; pass through if policy allows (default yes for now)
                valid.append(target)
        return valid

    def _get_dynamic_tool_args(self, tool_name: str) -> list[str]:
        """Dynamically extract required arguments from GhostMCP tool signatures."""
        tool_info = self.mcp.tools.get(tool_name)
        if not tool_info:
            return self._REQUIRED_TOOL_ARGS.get(tool_name, [])
        
        # Parse signature string: (host: str, ports: list[int] | None = None, ...)
        sig = tool_info.get("signature", "")
        # Extract arguments without default values
        params = re.findall(r"([a-z_]+):\s*[^=,)]+(?=[,)]|$)", sig)
        return params
    _MODE_BLOCKED_TOOLS: Dict[str, set[str]] = {
        "enum": {"msf_search"},
    }

    # -----------------------------
    # Execution helpers
    # -----------------------------
    def _apply_execution_options(self, config: Dict[str, Any], tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(args or {})
        if config.get("enable_ipv6") and tool in {"ping_sweep", "nmap_basic", "nmap_full"}:
            merged.setdefault("ipv6", True)
        return merged

    def _split_targets(self, raw_targets: Any) -> list[str]:
        if not raw_targets or not isinstance(raw_targets, str):
            return []
        normalized = raw_targets.replace("\n", ";").replace("\r", ";")
        return [t.strip() for t in normalized.split(";") if t.strip()]

    def _preflight_binaries(self) -> Dict[str, bool]:
        binaries = [
            "nmap",
            "dig",
            "httpx",
            "ffuf",
            "subfinder",
            "nuclei",
            "msfconsole",
            "nc",
            "curl",
        ]
        return {name: bool(shutil.which(name)) for name in binaries}

    def _normalize_action_signature(self, tool: str, args: Dict[str, Any]) -> str:
        try:
            return json.dumps({"tool": tool, "args": args or {}}, sort_keys=True)
        except Exception:
            return f"{tool}:{repr(args)}"

    def _find_last_step(self, conversation: list[dict], tool: str, args: Dict[str, Any]) -> dict | None:
        sig = self._normalize_action_signature(tool, args)
        for step in reversed(conversation):
            if step.get("tool") != tool:
                continue
            step_sig = self._normalize_action_signature(tool, step.get("args") or {})
            if step_sig == sig:
                return step
        return None

    def _has_successful_step(self, conversation: list[dict], tool: str, args: Dict[str, Any]) -> bool:
        step = self._find_last_step(conversation, tool, args)
        if not step:
            return False
        result = step.get("result")
        if not isinstance(result, dict):
            return False
        if result.get("error") or result.get("exception"):
            return False
        rc = result.get("returncode")
        return rc == 0 or rc is None  # some tools may not return returncode

    # -----------------------------
    # Nmap parsing + fingerprinting
    # -----------------------------
    _NMAP_OPEN_TCP_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.IGNORECASE | re.MULTILINE)

    def _extract_open_tcp_ports(self, conversation: list[dict]) -> dict:
        """
        Returns:
          {
            "127.0.0.1": [{"port": 3306, "service": "mysql"}, ...]
          }
        """
        by_target: dict[str, list[dict[str, Any]]] = {}

        for step in conversation:
            if step.get("tool") not in {"nmap_basic", "nmap_full"}:
                continue

            args = step.get("args", {}) or {}
            target = args.get("target") or "unknown"
            result = step.get("result", {}) or {}
            stdout = result.get("stdout", "") or ""

            matches = self._NMAP_OPEN_TCP_RE.findall(stdout)
            if not matches:
                continue

            items = []
            for port_str, svc in matches:
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                items.append({"port": port, "service": svc})

            if items:
                by_target.setdefault(target, []).extend(items)

        # de-dupe
        for t in list(by_target.keys()):
            seen = set()
            uniq = []
            for item in by_target[t]:
                key = (item["port"], item["service"])
                if key in seen:
                    continue
                seen.add(key)
                uniq.append(item)
            by_target[t] = uniq

        return by_target

    def _ports_fingerprint(self, open_ports: dict) -> str:
        """
        Stable fingerprint of discovered open ports/services.
        """
        try:
            normalized: dict[str, list[str]] = {}
            for target, items in (open_ports or {}).items():
                pairs = [f"{i['port']}:{i.get('service','')}" for i in items]
                normalized[target] = sorted(pairs)
            return json.dumps(normalized, sort_keys=True)
        except Exception:
            return repr(open_ports)

    def _last_ports_fingerprint(self, conversation: list[dict]) -> str | None:
        """
        Fingerprint from the most recent nmap_basic/nmap_full step.
        """
        for step in reversed(conversation):
            if step.get("tool") not in {"nmap_basic", "nmap_full"}:
                continue
            tmp_conv = [step]
            open_ports = self._extract_open_tcp_ports(tmp_conv)
            if open_ports:
                return self._ports_fingerprint(open_ports)
            return self._ports_fingerprint({})
        return None

    # -----------------------------
    # Coverage heuristics
    # -----------------------------
    def _has_attempted_any(self, conversation: list[dict], tools: set[str]) -> bool:
        for step in conversation:
            if step.get("tool") in tools:
                # ignore guard steps
                if step.get("tool") == "planner_guard":
                    continue
                # treat execution attempt as coverage even if it errors (it’s still an attempt)
                return True
        return False

    def _coverage_summary(self, conversation: list[dict]) -> dict:
        """
        Tracks whether we've attempted reasonable followups.
        This is used to allow termination after diminishing returns.
        """
        open_ports = self._extract_open_tcp_ports(conversation)
        fp = self._ports_fingerprint(open_ports)

        has_nmap_full = self._has_attempted_any(conversation, {"nmap_full"})
        has_nmap_scripts = self._has_attempted_any(conversation, {"nmap_scripts"})
        has_banner = self._has_attempted_any(conversation, {"banner_grab"})
        has_mysql = self._has_attempted_any(conversation, {"mysql_enum"})
        has_http = self._has_attempted_any(conversation, {"http_probe"})
        has_tor = self._has_attempted_any(conversation, {"tor_check"})

        # compute “needs”
        needs_mysql = False
        needs_tor = False
        needs_banner = False

        for _t, items in (open_ports or {}).items():
            for it in items:
                port = it.get("port")
                svc = (it.get("service") or "").lower()
                if port == 3306 or "mysql" in svc:
                    needs_mysql = True
                if port in (9040, 9050) or "tor" in svc:
                    needs_tor = True
                if port in (1234,) or svc in ("unknown", "hotline", "netconf-ch-tls"):
                    needs_banner = True

        # Minimum “reasonable enum” set: run nmap_full once, plus at least one followup family.
        followup_ok = has_nmap_scripts or has_banner or has_http or (needs_mysql and has_mysql) or (needs_tor and has_tor)

        return {
            "open_ports": open_ports,
            "ports_fingerprint": fp,
            "has_nmap_full": has_nmap_full,
            "has_nmap_scripts": has_nmap_scripts,
            "has_banner_grab": has_banner,
            "has_mysql_enum": has_mysql,
            "has_http_probe": has_http,
            "has_tor_check": has_tor,
            "needs_mysql_enum": needs_mysql,
            "needs_tor_check": needs_tor,
            "needs_banner_grab": needs_banner,
            "followup_ok": followup_ok,
        }

    # -----------------------------
    # Duplicate / loop guards
    # -----------------------------
    def _count_recent_repeats(self, conversation: list[dict], tool: str, window: int = 6) -> int:
        cnt = 0
        for step in reversed(conversation[-window:]):
            if step.get("tool") == tool:
                cnt += 1
        return cnt

    def _should_block_duplicate_action(self, conversation: list[dict], tool: str, args: Dict[str, Any]) -> tuple[bool, str]:
        """
        Returns (block, reason).
        """
        # Block exact repeats for expensive tools when they already succeeded.
        if tool in {"nmap_basic", "ping_sweep", "nuclei_scan", "dir_bruteforce", "subdomain_enum"}:
            if self._has_successful_step(conversation, tool, args):
                return True, "duplicate_successful_action"

        # Special: nmap_full should not be rerun if it does not change the port fingerprint.
        if tool == "nmap_full":
            # If we've already successfully run nmap_full with same args, block.
            if self._has_successful_step(conversation, tool, args):
                # If last nmap_full produced same fingerprint as current discovered ports, it’s pointless.
                # We compute fingerprint from all nmap results seen so far.
                current_fp = self._ports_fingerprint(self._extract_open_tcp_ports(conversation))
                last_step = self._find_last_step(conversation, "nmap_full", args)
                if last_step and isinstance(last_step.get("result"), dict):
                    stdout = (last_step["result"].get("stdout") or "")
                    matches = self._NMAP_OPEN_TCP_RE.findall(stdout)
                    temp_open = {}
                    if matches:
                        items = []
                        for port_str, svc in matches:
                            try:
                                items.append({"port": int(port_str), "service": svc})
                            except ValueError:
                                continue
                        temp_open[last_step.get("args", {}).get("target", "unknown")] = items
                    last_fp = self._ports_fingerprint(temp_open)
                    if last_fp == current_fp:
                        return True, "nmap_full_no_change_repeat"

            # Also block runaway repeats even if previous run errored (LLM thrashing).
            if self._count_recent_repeats(conversation, "nmap_full", window=6) >= 2:
                return True, "nmap_full_repeat_guard"

        # Prevent repeated banner_grab on same port
        if tool == "banner_grab":
            if self._has_successful_step(conversation, tool, args):
                return True, "banner_grab_repeat"

        # Prevent repeated nmap_scripts with same ports/target if it already succeeded
        if tool == "nmap_scripts":
            if self._has_successful_step(conversation, tool, args):
                return True, "nmap_scripts_repeat"

        # Prevent repeated mysql_enum to death
        if tool == "mysql_enum":
            if self._has_successful_step(conversation, tool, args):
                return True, "mysql_enum_repeat"

        # Prevent repeated tor_check
        if tool == "tor_check":
            if self._has_successful_step(conversation, tool, args):
                return True, "tor_check_repeat"

        return False, ""

    # -----------------------------
    # Tool arg autofill + validation
    # -----------------------------
    def _autofill_tool_args(self, tool: str, args: Dict[str, Any], targets: list[str], conversation: list[dict]) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Best-effort fill-in for missing required args so the scan doesn't just fail with "X required".
        Returns (args, autofill_info).
        """
        merged = dict(args or {})
        autofill_info: Dict[str, Any] = {}

        required = self._get_dynamic_tool_args(tool)
        if not required:
            return merged, autofill_info

        if "target" in required and not merged.get("target") and targets:
            merged["target"] = targets[0]
            autofill_info["target"] = targets[0]

        if "targets" in required and not merged.get("targets") and targets:
            merged["targets"] = targets
            autofill_info["targets"] = targets

        # Autofill ports for nmap_scripts from observed open ports
        if tool == "nmap_scripts":
            if not merged.get("ports"):
                open_ports = self._extract_open_tcp_ports(conversation)
                t = merged.get("target") or (targets[0] if targets else None)
                ports_list = []
                if t and t in open_ports:
                    ports_list = [str(it["port"]) for it in open_ports[t] if isinstance(it.get("port"), int)]
                if ports_list:
                    merged["ports"] = ",".join(sorted(set(ports_list), key=lambda x: int(x)))
                    autofill_info["ports"] = merged["ports"]

        # Autofill banner_grab port: pick an "unknown-ish" port if not provided
        if tool == "banner_grab":
            if merged.get("port") is None:
                open_ports = self._extract_open_tcp_ports(conversation)
                t = merged.get("target") or (targets[0] if targets else None)
                if t and t in open_ports:
                    # Prefer unknown/hotline/netconf/odd ports first
                    preferred = []
                    fallback = []
                    for it in open_ports[t]:
                        p = it.get("port")
                        svc = (it.get("service") or "").lower()
                        if not isinstance(p, int):
                            continue
                        if svc in ("unknown", "hotline", "netconf-ch-tls"):
                            preferred.append(p)
                        else:
                            fallback.append(p)
                    chosen = preferred[0] if preferred else (fallback[0] if fallback else None)
                    if chosen is not None:
                        merged["port"] = chosen
                        autofill_info["port"] = chosen

        # Autofill mysql_enum port if missing and mysql is open
        if tool == "mysql_enum":
            if merged.get("port") is None:
                open_ports = self._extract_open_tcp_ports(conversation)
                t = merged.get("target") or (targets[0] if targets else None)
                if t and t in open_ports:
                    for it in open_ports[t]:
                        p = it.get("port")
                        svc = (it.get("service") or "").lower()
                        if p == 3306 or "mysql" in svc:
                            merged["port"] = 3306
                            autofill_info["port"] = 3306
                            break

        # Autofill tor_check: if tor-socks open, use 9050; else if tor-trans, 9040
        if tool == "tor_check":
            if merged.get("target") is None and targets:
                merged["target"] = targets[0]
                autofill_info["target"] = merged["target"]
            if merged.get("port") is None:
                open_ports = self._extract_open_tcp_ports(conversation)
                t = merged.get("target") or (targets[0] if targets else None)
                if t and t in open_ports:
                    ports = {it.get("port") for it in open_ports[t] if isinstance(it.get("port"), int)}
                    if 9050 in ports:
                        merged["port"] = 9050
                        autofill_info["port"] = 9050
                    elif 9040 in ports:
                        merged["port"] = 9040
                        autofill_info["port"] = 9040

        return merged, autofill_info

    def _missing_required_args(self, tool: str, args: Dict[str, Any]) -> list[str]:
        required = self._get_dynamic_tool_args(tool)
        missing: list[str] = []
        for key in required:
            val = (args or {}).get(key)
            if val is None:
                missing.append(key)
            elif isinstance(val, str) and not val.strip():
                missing.append(key)
            elif isinstance(val, list) and len(val) == 0:
                missing.append(key)
        return missing

    # -----------------------------
    # Prompt builder
    # -----------------------------
    def _build_prompt(self, config: Dict[str, Any], history: list[dict]) -> str:
        history_block = ""
        for i, step in enumerate(history, 1):
            history_block += f"""
Step {i}:
Tool: {step['tool']}
Args: {step['args']}
Result:
{json.dumps(step['result'], indent=2)}
"""

        available_tools = list(self.mcp.tools.keys())

        coverage = self._coverage_summary(history)
        open_ports_block = json.dumps(coverage["open_ports"], indent=2) if coverage["open_ports"] else "None"

        # Give the model a strong steer away from repeating nmap_full
        return f"""
You are a penetration testing orchestrator. Your job is to choose the next enumeration action.

Targets:
{config.get('targets')}

Execution options:
- resolve_dns: {config.get('resolve_dns')}
- enable_ipv6: {config.get('enable_ipv6')}

Mode:
{config.get('mode')}

Available tools:
{available_tools}

Observed open TCP ports so far (parsed from nmap stdout):
{open_ports_block}

Coverage status:
- ports_fingerprint: {coverage["ports_fingerprint"]}
- has_nmap_full: {coverage["has_nmap_full"]}
- has_nmap_scripts: {coverage["has_nmap_scripts"]}
- has_banner_grab: {coverage["has_banner_grab"]}
- has_mysql_enum: {coverage["has_mysql_enum"]}
- has_http_probe: {coverage["has_http_probe"]}
- has_tor_check: {coverage["has_tor_check"]}
- needs_mysql_enum: {coverage["needs_mysql_enum"]}
- needs_tor_check: {coverage["needs_tor_check"]}
- needs_banner_grab: {coverage["needs_banner_grab"]}

Previous steps:
{history_block if history else "None"}

Return ONLY a single JSON object with no extra text or markdown.

Format:
{{
  "thought": "short internal reasoning",
  "action": {{
    "tool": "nmap_full",
    "args": {{}}
  }},
  "expected_result": "what this action will produce"
}}

Rules:
- All fields are REQUIRED.
- Do NOT add extra fields.
- tool MUST be one of the available tools OR "terminate".

Progress rules (STRICT):
- Do NOT repeat the same expensive scan if it already succeeded and port discovery did not change.
  - Specifically: do NOT call nmap_full again if you already ran it on the same target.
- If open ports exist, you MUST choose a follow-up action that increases information:
  - Prefer nmap_scripts for service/version + safe scripts.
  - Prefer banner_grab for unknown/nonstandard services (e.g. hotline/unknown/netconf-ch-tls/high ports).
  - Prefer mysql_enum when MySQL is open.
  - Prefer tor_check when tor ports are open.
  - Use http_probe only if you suspect HTTP services.

Termination rules:
- You may terminate AFTER diminishing returns if you have:
  - run nmap_full at least once, AND
  - attempted at least one meaningful follow-up (nmap_scripts OR banner_grab OR mysql_enum OR tor_check OR http_probe), AND
  - there is no clear next tool that would add new information.

Terminate format:
{{
  "thought": "why stopping is justified",
  "action": {{
    "tool": "terminate",
    "args": {{}}
  }},
  "expected_result": "Scan complete"
}}
""".strip()

    def parse_plan(self, raw: str) -> Dict[str, Any]:
        if not raw or not isinstance(raw, str):
            raise ValueError("LLM returned empty response")

        raw = raw.strip()

        start = raw.find("{")
        end = raw.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise ValueError("No JSON object found in LLM output")

        raw = raw[start:end + 1]

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"LLM returned invalid JSON: {e}")

        # Handle JSON-string-wrapped JSON (LM Studio behavior)
        if isinstance(parsed, str):
            try:
                parsed = json.loads(parsed)
            except json.JSONDecodeError as e:
                raise ValueError(f"LLM returned double-encoded JSON: {e}")

        try:
            validate(instance=parsed, schema=PLAN_SCHEMA)
        except ValidationError as e:
            raise ValueError(f"Plan schema validation failed: {e.message}")

        return parsed

    # -----------------------------
    # Main run loop
    # -----------------------------
    def run_scan(self, config: Dict[str, Any], emit, should_cancel=None):
        emit("[*] Starting scan")
        emit(f"[*] Targets: {config.get('targets')}")
        emit(f"[*] Mode: {config.get('mode')}")
        emit(f"[*] IPv6 enabled: {bool(config.get('enable_ipv6'))}")
        emit(f"[*] Available MCP tools: {list(self.mcp.tools.keys())}")

        binary_status = self._preflight_binaries()
        missing_bins = [name for name, ok in binary_status.items() if not ok]
        if missing_bins:
            emit(f"[!] Missing system binaries: {missing_bins}")
            emit("[!] Tool calls that rely on these will fail (install them or update PATH).")

        conversation: list[dict] = []

        targets = self._split_targets(config.get("targets"))
        targets = self._validate_scope(targets)
        if not targets:
            emit({"status": "error", "message": "No targets within allowed scope."})
            return
        if not targets:
            emit("[!] No targets provided")
            emit("[*] Scan complete")
            return

        emit("[*] Running initial nmap scan (basic) on targets...")
        for target in targets:
            if should_cancel and should_cancel():
                emit("[*] Cancel requested; stopping scan.")
                emit("[*] Scan complete")
                return

            emit(f"[*] Initial nmap_basic: {target}")
            args: Dict[str, Any] = self._apply_execution_options(config, "nmap_basic", {"target": target})
            try:
                result = self.mcp.call("nmap_basic", args)
            except Exception as e:
                emit(f"[!] Initial nmap_basic failed for {target}: {e}")
                result = {"error": str(e)}

            conversation.append({
                "tool": "nmap_basic",
                "args": args,
                "result": result,
            })

        emit("[*] Handing off to LLM for planning...\n")

        MAX_PLAN_ATTEMPTS = 3
        MAX_ACTION_STEPS = 40
        step_count = 0

        # Track port-fingerprint stability for diminishing returns
        stable_fp_count = 0
        last_fp = self._ports_fingerprint(self._extract_open_tcp_ports(conversation))

        while True:
            if should_cancel and should_cancel():
                emit("[*] Cancel requested; stopping scan.")
                break

            prompt = self._build_prompt(config, conversation)
            raw = self.llm.generate_text(prompt, max_tokens=650)
            emit("[LLM] Response received")

            if should_cancel and should_cancel():
                emit("[*] Cancel requested; stopping scan.")
                break

            if raw is None:
                emit("[!] LLM returned no response")
                break

            plan = None
            for attempt in range(1, MAX_PLAN_ATTEMPTS + 1):
                if should_cancel and should_cancel():
                    emit("[*] Cancel requested; stopping scan.")
                    return
                try:
                    plan = self.parse_plan(raw)
                    break
                except Exception as e:
                    emit(f"[!] Invalid plan (attempt {attempt}): {e}")
                    if attempt >= MAX_PLAN_ATTEMPTS:
                        emit("[!] Failed to obtain valid structured output")
                        return
                    raw = self.llm.generate_text(
                        "Your last response was invalid. Fix it and return ONLY a valid JSON object that matches the schema.\n\n"
                        f"Your previous response:\n{raw}",
                        max_tokens=650,
                    )
                    if raw is None:
                        emit("[!] LLM returned no response")
                        return

            if plan is None:
                emit("[!] Failed to obtain valid structured output")
                return

            action = plan["action"]
            tool = action.get("tool")
            args = action.get("args", {})

            step_count += 1
            if step_count > MAX_ACTION_STEPS:
                emit(f"[!] Max action steps reached ({MAX_ACTION_STEPS}); stopping to avoid infinite loop.")
                break

            # Explicit termination (now allowed under diminishing returns)
            if tool == "terminate":
                emit("[*] Termination requested by planner")
                break

            if tool not in self.mcp.tools:
                emit(f"[!] Invalid tool requested: {tool}")
                conversation.append({
                    "tool": "planner_guard",
                    "args": {"reason": "invalid_tool", "tool": tool},
                    "result": {"available_tools": list(self.mcp.tools.keys())},
                })
                continue

            # Enforce mode safety.
            mode = config.get("mode", "enum")
            blocked = self._MODE_BLOCKED_TOOLS.get(mode, set())
            if tool in blocked:
                emit(f"[!] Tool '{tool}' not allowed in mode '{mode}'")
                conversation.append({
                    "tool": "planner_guard",
                    "args": {"reason": "mode_violation", "tool": tool, "mode": mode},
                    "result": {
                        "blocked_tools": sorted(blocked),
                        "mode": mode,
                    },
                })
                continue

            emit(f"[*] Executing tool: {tool}")
            args = self._apply_execution_options(config, tool, args)
            args, autofilled = self._autofill_tool_args(tool, args, targets, conversation)
            emit(f"[*] Args: {args}")

            # Block duplicates intelligently
            block, reason = self._should_block_duplicate_action(conversation, tool, args)
            if block:
                emit(f"[!] Blocking action: {reason} -> {tool} {args}")
                conversation.append({
                    "tool": "planner_guard",
                    "args": {"reason": reason, "tool": tool, "args": args},
                    "result": {
                        "note": "Pick a different next step that increases information (nmap_scripts/banner_grab/mysql_enum/tor_check/http_probe).",
                        "open_ports": self._extract_open_tcp_ports(conversation),
                        "coverage": self._coverage_summary(conversation),
                    },
                })

                # If we're stable and have already tried followups, allow termination via diminishing returns
                coverage = self._coverage_summary(conversation)
                current_fp = coverage["ports_fingerprint"]
                if current_fp == last_fp:
                    stable_fp_count += 1
                else:
                    stable_fp_count = 0
                    last_fp = current_fp

                if stable_fp_count >= 3 and coverage["has_nmap_full"] and coverage["followup_ok"]:
                    emit("[*] Diminishing returns detected (stable port fingerprint + followups attempted). Allowing planner to terminate.")
                    conversation.append({
                        "tool": "planner_guard",
                        "args": {"reason": "diminishing_returns"},
                        "result": {
                            "note": "You may now terminate. Open ports exist but enumeration has plateaued given available tools/binaries.",
                            "coverage": coverage,
                        },
                    })
                continue

            missing = self._missing_required_args(tool, args)
            if missing:
                emit(f"[!] Missing required args for tool '{tool}': {missing}")
                conversation.append({
                    "tool": "planner_guard",
                    "args": {"reason": "missing_required_args", "tool": tool, "missing": missing},
                    "result": {
                        "required_args": self._REQUIRED_TOOL_ARGS.get(tool, []),
                        "note": "Planner must include required args in action.args.",
                    },
                })
                continue

            if autofilled:
                emit(f"[*] Auto-filled args for tool '{tool}': {autofilled}")
                conversation.append({
                    "tool": "planner_guard",
                    "args": {"reason": "autofilled_args", "tool": tool},
                    "result": {"autofilled": autofilled},
                })

            try:
                result = self.mcp.call(tool, args)
            except Exception as e:
                emit(f"[!] Tool execution failed: {e}")
                conversation.append({
                    "tool": "tool_error",
                    "args": {"tool": tool, "args": args},
                    "result": {"error": str(e)},
                })
                continue

            emit("[*] Tool result:")
            emit(json.dumps(result, indent=2))

            conversation.append({
                "tool": tool,
                "args": args,
                "result": result,
            })

            # Update stability tracking after each tool
            coverage = self._coverage_summary(conversation)
            current_fp = coverage["ports_fingerprint"]
            if current_fp == last_fp:
                stable_fp_count += 1
            else:
                stable_fp_count = 0
                last_fp = current_fp

        emit("[*] Scan complete")

        # Generate final report
        try:
            record = {
                "timestamp": datetime.now().isoformat(),
                "config": config,
                "steps": conversation
            }
            record_path = f"reports/run-{int(time.time())}.json"
            os.makedirs("reports", exist_ok=True)
            with open(record_path, "w") as f:
                json.dump(record, f, indent=2)
            
            report_path = record_path.replace(".json", ".md")
            generate_markdown_report(record_path, report_path)
            emit(f"[*] Report generated: {report_path}")
        except Exception as e:
            emit(f"[!] Reporting failed: {e}")
