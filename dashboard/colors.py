# one place for severity colors so the dashboard, pdf and csv all agree

from reportlab.lib import colors

SEVERITY_COLORS_HEX = {"high": "#e74c3c", "medium": "#e67e22", "low": "#2ecc71"}
SEVERITY_COLORS_RL = {
    "high": colors.HexColor("#e74c3c"),
    "medium": colors.HexColor("#e67e22"),
    "low": colors.HexColor("#2ecc71"),
}


def severity_emoji(sev: str) -> str:
    return {"high": "🔴", "medium": "🟠", "low": "🟢"}.get(sev, "⚪")
