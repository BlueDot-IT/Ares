from __future__ import annotations

from dataclasses import dataclass

from ares.policy.risk import RISK_ORDER


@dataclass(frozen=True)
class OperatorRole:
    id: str
    name: str
    purpose: str
    allowed_phases: tuple[str, ...]
    allowed_toolsets: tuple[str, ...]
    max_risk: str
    allowed_tools: tuple[str, ...] = ()

    def allows_tool(self, tool_name: str | None) -> bool:
        return tool_name is None or not self.allowed_tools or tool_name in self.allowed_tools

    def allows_risk(self, risk: str) -> bool:
        return RISK_ORDER[risk] <= RISK_ORDER[self.max_risk]


OPERATORS: dict[str, OperatorRole] = {
    "coordinator": OperatorRole(
        id="coordinator",
        name="Coordinator",
        purpose="Plan mission tasks and decide when to stop.",
        allowed_phases=("plan", "report"),
        allowed_toolsets=("redteam_report",),
        max_risk="safe",
    ),
    "recon": OperatorRole(
        id="recon",
        name="Recon",
        purpose="Collect scoped target facts without exploitation.",
        allowed_phases=("recon",),
        allowed_toolsets=("redteam_recon", "ghostmcp"),
        max_risk="active",
        allowed_tools=(
            "amass_passive", "dns_lookup", "reverse_dns", "whois",
            "security_txt", "http_probe", "tls_certificate",
            "tcp_port_scan", "nmap_basic", "whatweb",
        ),
    ),
    "scanner": OperatorRole(
        id="scanner",
        name="Scanner",
        purpose="Run safe static, dependency, and secret scans.",
        allowed_phases=("scan",),
        allowed_toolsets=("redteam_static", "redteam_secrets", "redteam_deps"),
        max_risk="scan",
    ),
    "validator": OperatorRole(
        id="validator",
        name="Validator",
        purpose="Try to validate or weaken findings using evidence only.",
        allowed_phases=("validate",),
        allowed_toolsets=("redteam_static", "redteam_secrets", "redteam_deps"),
        max_risk="scan",
    ),
    "exploiter": OperatorRole(
        id="exploiter",
        name="Exploit Validator",
        purpose="Validate confirmed vulnerabilities with the minimum authorized proof of impact.",
        allowed_phases=("weaponize", "deliver", "exploit", "validate"),
        allowed_toolsets=("ghostmcp",),
        max_risk="exploit",
        allowed_tools=(
            "exploitdb_raw", "msf_search", "msfconsole_raw",
            "searchsploit", "searchsploit_raw", "sqlmap", "sqlmap_raw",
            "commix_raw",
        ),
    ),
    "infiltrator": OperatorRole(
        id="infiltrator",
        name="Lateral-Movement Validator",
        purpose="Assess privilege and lateral-movement paths inside an explicitly authorized scope.",
        allowed_phases=("post-exploitation",),
        allowed_toolsets=("ghostmcp",),
        max_risk="post-exploitation",
        allowed_tools=(
            "bloodhound_python_raw", "crackmapexec", "crackmapexec_raw",
            "evil_winrm_raw", "impacket_psexec_raw", "impacket_wmiexec_raw",
            "kerbrute_raw", "netexec_raw", "rpcclient", "rpcclient_raw",
            "smbclient", "smbclient_raw", "smbmap", "smbmap_raw",
        ),
    ),
    "exfiltrator": OperatorRole(
        id="exfiltrator",
        name="Data-Exposure Validator",
        purpose="Prove bounded data exposure without bulk collection or removal.",
        allowed_phases=("actions",),
        allowed_toolsets=("ghostmcp",),
        max_risk="post-exploitation",
        allowed_tools=(
            "mysql_enum", "smbclient", "smbclient_raw", "smbmap",
            "smbmap_raw", "sqlmap", "sqlmap_raw",
        ),
    ),
    "ghost": OperatorRole(
        id="ghost",
        name="Persistence-Control Validator",
        purpose="Assess persistence controls without installing implants or hiding activity.",
        allowed_phases=("persistence", "post-exploitation"),
        allowed_toolsets=("ghostmcp",),
        max_risk="post-exploitation",
        allowed_tools=(
            "bloodhound_python_raw", "crackmapexec", "crackmapexec_raw",
            "evil_winrm_raw", "impacket_psexec_raw", "impacket_wmiexec_raw",
            "netexec_raw", "rpcclient", "rpcclient_raw",
        ),
    ),
    "analyst": OperatorRole(
        id="analyst",
        name="Analyst",
        purpose="Summarize evidence, risk, limitations, and fixes.",
        allowed_phases=("analyze", "report"),
        allowed_toolsets=("redteam_report",),
        max_risk="safe",
    ),
}


def get_operator(role_id: str) -> OperatorRole:
    try:
        return OPERATORS[role_id]
    except KeyError as exc:
        raise ValueError(f"unknown operator role: {role_id}") from exc
