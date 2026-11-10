"""Helpers for the trusted-contact alert email."""
import re
import smtplib
import time
from email.message import EmailMessage
from typing import Literal

ScamType = Literal[
    "none",
    "account_verification",
    "payment_or_invoice",
    "pretending_to_be_someone_you_know",
    "prize_or_lottery",
    "tech_support",
    "job_or_investment",
    "other",
]

SCAM_TYPE_TEXT = {
    "none": "an email that looked suspicious",
    "account_verification": "a fake account warning that pushes the reader to log in or verify",
    "payment_or_invoice": "a fake bill, invoice, or payment request",
    "pretending_to_be_someone_you_know": "someone pretending to be a friend, family member, or coworker who needs help or money",
    "prize_or_lottery": "a fake prize, lottery, or giveaway",
    "tech_support": "a fake tech support or security warning",
    "job_or_investment": "a fake job offer or investment opportunity",
    "other": "an email that looked like a scam",
}

EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
MAX_ALERTS_PER_HOUR = 5
_alert_log: dict[str, list[float]] = {}


def is_valid_email(address: str) -> bool:
    return bool(EMAIL_PATTERN.match(address))


def allow_alert(contact_email: str) -> bool:
    """Simple rate limit: at most MAX_ALERTS_PER_HOUR per contact."""
    key = contact_email.lower()
    now = time.time()
    recent = [t for t in _alert_log.get(key, []) if now - t < 3600]
    if len(recent) >= MAX_ALERTS_PER_HOUR:
        _alert_log[key] = recent
        return False
    recent.append(now)
    _alert_log[key] = recent
    return True


def clean_text(value: str, limit: int) -> str:
    """One line, printable characters only, cut to `limit` characters."""
    value = re.sub(r"\s+", " ", value)
    value = "".join(ch for ch in value if ch.isprintable())
    return value.strip()[:limit]


def clean_subject(subject: str) -> str:
    """Make a subject line safe to show: no live links, no line breaks, short."""
    subject = re.sub(r"(https?://|www\.)\S+", "[link removed]", subject, flags=re.IGNORECASE)
    subject = clean_text(subject, 80)
    # Defang anything that still looks like a domain so mail apps don't link it.
    return re.sub(r"\b([\w-]+)\.([A-Za-z]{2,})\b", r"\1[.]\2", subject)


def build_alert_message(from_address, to_address, user_name, contact_name,
                        risk_level, scam_type, subject) -> EmailMessage:
    user = clean_text(user_name, 60) or "Someone you know"
    contact = clean_text(contact_name, 60) or "there"
    what = SCAM_TYPE_TEXT.get(scam_type, SCAM_TYPE_TEXT["other"])
    level = "HIGH" if risk_level == "high" else "MEDIUM"
    safe_subject = clean_subject(subject)

    lines = [
        f"Hi {contact},",
        "",
        f"FoxWatch, a Gmail safety tool that {user} uses, flagged an email they received as {level} risk.",
        "",
        f"What it looks like: {what}.",
    ]
    if safe_subject:
        lines.append(f'Subject line (links removed): "{safe_subject}"')
    lines += [
        "",
        f"What you can do: check in with {user}. A phone call is best, using a number you "
        "already have, not one from the email. Remind them not to click links, open "
        "attachments, or send money, gift cards, or passwords.",
        "",
        "This alert has no links and includes none of the email's contents"
        + (" beyond the subject line above." if safe_subject else "."),
        "FoxWatch is a student project. If you did not agree to be someone's trusted "
        "contact, you can ignore this message.",
    ]

    message = EmailMessage()
    message["Subject"] = f"FoxWatch alert: {user} may have received a scam email"
    message["From"] = from_address
    message["To"] = to_address
    message.set_content("\n".join(lines))
    return message


def send_alert_email(message: EmailMessage, smtp_user: str, smtp_password: str) -> None:
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(message)