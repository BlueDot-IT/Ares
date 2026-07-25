RISK_ORDER = {
    "safe": 0,
    "scan": 1,
    "passive": 1,
    "active": 2,
    "intrusive": 3,
    "exploit": 4,
    "post-exploitation": 5,
}


def risk_allows(max_risk: str, tool_risk: str) -> bool:
    if max_risk not in RISK_ORDER:
        raise ValueError(f"unknown max risk level: {max_risk}")
    if tool_risk not in RISK_ORDER:
        raise ValueError(f"unknown tool risk level: {tool_risk}")
    return RISK_ORDER[tool_risk] <= RISK_ORDER[max_risk]
