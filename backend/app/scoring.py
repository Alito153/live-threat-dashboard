from typing import Any, Dict, Optional


def compute_risk(ioc_type: str, abuse: Optional[Dict[str, Any]], otx: Optional[Dict[str, Any]], vt: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    risk_points = 0
    signals: list[str] = []

    if ioc_type == "ip" and abuse and isinstance(abuse.get("abuseConfidenceScore"), int):
        s = abuse["abuseConfidenceScore"]
        if s >= 90:
            risk_points += 3; signals.append(f"AbuseIPDB score {s}")
        elif s >= 50:
            risk_points += 2; signals.append(f"AbuseIPDB score {s}")
        elif s >= 10:
            risk_points += 1; signals.append(f"AbuseIPDB score {s}")

    if vt and isinstance(vt.get("malicious"), int):
        m = vt["malicious"]
        if m >= 10:
            risk_points += 3; signals.append(f"VT malicious={m}")
        elif m >= 3:
            risk_points += 2; signals.append(f"VT malicious={m}")
        elif m >= 1:
            risk_points += 1; signals.append(f"VT malicious={m}")

    if otx and isinstance(otx.get("pulse_count"), int):
        pc = otx["pulse_count"]
        if pc >= 10:
            risk_points += 2; signals.append(f"OTX pulses={pc}")
        elif pc >= 1:
            risk_points += 1; signals.append(f"OTX pulses={pc}")

    level = "low"
    if risk_points >= 5:
        level = "high"
    elif risk_points >= 2:
        level = "medium"

    return {"risk_level": level, "risk_points": risk_points, "signals": signals}