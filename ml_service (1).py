import re
from difflib import SequenceMatcher

def _similarity(a, b):
    return SequenceMatcher(None, (a or "").strip().lower(), (b or "").strip().lower()).ratio()

def predict(student: dict, others: list[dict]) -> dict:
    aapar = student.get("aapar_id") or ""
    phone = student.get("phone") or ""
    email = (student.get("email") or "").strip().lower()
    same_id = sum(1 for x in others if aapar and x.get("aapar_id") == aapar)
    same_phone = sum(1 for x in others if phone and x.get("phone") == phone)
    same_email = sum(1 for x in others if email and (x.get("email") or "").strip().lower() == email)
    name_similarity = max((_similarity(x.get("name"), student.get("name"))
        for x in others if (x.get("institution") or "").strip().lower() ==
        (student.get("institution") or "").strip().lower()), default=0.0)
    valid_phone = bool(re.fullmatch(r"[6-9][0-9]{9}", phone))
    valid_email = bool(re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+", email))
    score, reasons = 0.0, []
    if same_id: score += .50; reasons.append(f"AAPAR ID already used by {same_id} record(s)")
    if same_phone: score += .25; reasons.append(f"Phone shared with {same_phone} record(s)")
    if same_email: score += .20; reasons.append(f"Email shared with {same_email} record(s)")
    if name_similarity > .90: score += .30; reasons.append(f"Name {int(name_similarity*100)}% similar at same institution")
    if not valid_phone: score += .25; reasons.append("Phone format looks invalid")
    if not valid_email: score += .25; reasons.append("Email format looks invalid")
    return {"risk_score": round(min(score, 1.0), 2),
            "is_duplicate": bool(same_id or same_phone or same_email or name_similarity > .90),
            "anomaly": False, "reasons": reasons}
