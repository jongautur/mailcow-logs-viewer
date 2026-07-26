"""SMTP abuse detection, whitelist management, and mailbox controls."""
import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, field_validator, Field
from sqlalchemy import func, case

from ..config import settings
from ..database import get_db_context
from ..mailcow_api import mailcow_api
from ..models import MessageCorrelation, SMTPAbuseAction, SMTPAbuseWhitelist
from ..services.smtp_service import send_notification_email

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/smtp-abuse")


class WhitelistRequest(BaseModel):
    email: str
    notes: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            raise ValueError("Invalid email format")
        return value


class WhitelistBulkRequest(BaseModel):
    emails: List[str] = Field(default_factory=list)


def normalized(email: str) -> str:
    return email.strip().lower()


def require_control_access() -> None:
    """Keep the write API consistent with the locked Security UI."""
    if not settings.smtp_abuse_enabled:
        raise HTTPException(status_code=403, detail="SMTP abuse protection is disabled")
    if not mailcow_api.has_rw_key:
        raise HTTPException(status_code=503, detail="MAILCOW_API_KEY_RW is required")


async def revoke_app_passwords(email: str) -> int:
    entries = await mailcow_api.get_app_passwords(email)
    ids = [str(entry["id"]) for entry in entries if isinstance(entry, dict) and entry.get("id") is not None]
    if ids:
        await mailcow_api.delete_app_passwords(ids)
    return len(ids)


async def notify_blocked(email: str, count: int, threshold: int, window: int) -> None:
    if not settings.smtp_enabled or not settings.smtp_from:
        logger.warning("SMTP abuse notification skipped: SMTP notifications are not configured")
        return
    subject = "Security alert for your email account"
    text = f"""SMTP sending has been temporarily disabled for {email}.

We detected {count} sent messages during the last {window} minutes. The configured limit is {threshold}.
IMAP access remains enabled. Please change your password and/or revoke your app passwords.

Contact {settings.smtp_abuse_help_address or "your support team"} if you need assistance.
"""
    await asyncio.to_thread(send_notification_email, email, subject, text, text.replace("\n", "<br>"))


async def block_mailbox(email: str, count: int, automatic: bool = False, operator: Optional[str] = None):
    email = normalized(email)
    await mailcow_api.edit_mailbox(email, {"smtp_access": "0"})
    revoked = 0
    revoke_error = None
    try:
        revoked = await revoke_app_passwords(email)
    except Exception as exc:
        revoke_error = str(exc)
        logger.error("Could not revoke app passwords for %s: %s", email, exc, exc_info=True)
    try:
        await notify_blocked(email, count, settings.smtp_abuse_threshold, settings.smtp_abuse_window_minutes)
    except Exception as exc:
        logger.error("Could not send SMTP abuse notification to %s: %s", email, exc, exc_info=True)
    with get_db_context() as db:
        db.add(SMTPAbuseAction(
            email=email,
            message_count=count,
            threshold=settings.smtp_abuse_threshold,
            window_minutes=settings.smtp_abuse_window_minutes,
            action="blocked",
            automatic=automatic,
            operator=operator or "system",
        ))
    return {"email": email, "smtp_access": False, "app_passwords_revoked": revoked,
            "app_password_revoke_failed": revoke_error is not None}


@router.get("/status")
async def status(limit: int = Query(200, ge=1, le=1000)):
    cutoff = datetime.utcnow() - timedelta(minutes=settings.smtp_abuse_window_minutes)
    mailbox_access = {}
    try:
        mailboxes = await mailcow_api.get_mailboxes()
        for mailbox in mailboxes:
            address = mailbox.get("username")
            if address:
                # Mailcow versions expose access flags inside `attributes`.
                # Some versions also expose them at the mailbox top level.
                attributes = mailbox.get("attributes") or {}
                access = mailbox.get("smtp_access", attributes.get("smtp_access", 1))
                mailbox_access[normalized(address)] = not (access is False or str(access).lower() in ("0", "false", "no"))
    except Exception as exc:
        logger.warning("Could not load mailbox SMTP access states: %s", exc)

    with get_db_context() as db:
        counts = db.query(
            MessageCorrelation.sender.label("email"),
            func.count(MessageCorrelation.id).label("message_count"),
            func.sum(case((func.lower(MessageCorrelation.direction) == "outbound", 1), else_=0)).label("outbound_count")
        ).filter(
            func.lower(MessageCorrelation.direction).in_(["outbound", "internal"]),
            MessageCorrelation.first_seen >= cutoff,
            MessageCorrelation.sender.isnot(None),
        ).group_by(MessageCorrelation.sender).order_by(func.count(MessageCorrelation.id).desc()).limit(limit).all()
        whitelist = {row.email for row in db.query(SMTPAbuseWhitelist).filter(SMTPAbuseWhitelist.active.is_(True)).all()}
        latest_action = db.query(
            SMTPAbuseAction.email.label("email"),
            func.max(SMTPAbuseAction.created_at).label("latest_created_at")
        ).group_by(SMTPAbuseAction.email).subquery()
        actions = db.query(SMTPAbuseAction).join(
            latest_action,
            (SMTPAbuseAction.email == latest_action.c.email) &
            (SMTPAbuseAction.created_at == latest_action.c.latest_created_at)
        ).all()
        # Do not treat every mailbox with smtp_access=0 as an abuse case.
        # Incoming-only mailboxes (for example DMARC report mailboxes) also
        # intentionally have SMTP disabled. Only show mailboxes whose latest
        # recorded action in this system is a block.
        closed_by_protection = {normalized(action.email) for action in actions if action.action == "blocked"}
        count_by_email = {normalized(row.email): int(row.message_count) for row in counts if row.email}
        outbound_by_email = {normalized(row.email): int(row.outbound_count or 0) for row in counts if row.email}
        visible_emails = [
            email for email in count_by_email
            if mailbox_access.get(email, True) or email in closed_by_protection
        ]
        for email, smtp_open in mailbox_access.items():
            if not smtp_open and email in closed_by_protection and email not in count_by_email:
                visible_emails.append(email)
        return {
            "enabled": settings.smtp_abuse_enabled,
            "threshold": settings.smtp_abuse_threshold,
            "window_minutes": settings.smtp_abuse_window_minutes,
            "mailboxes": [
                {"email": email, "message_count": count_by_email.get(email, 0),
                 "whitelisted": email in whitelist,
                 "outbound_count": outbound_by_email.get(email, 0),
                 "over_threshold": outbound_by_email.get(email, 0) > settings.smtp_abuse_threshold,
                 "smtp_access": mailbox_access.get(email, True)}
                for email in visible_emails
            ],
            "whitelist": sorted(whitelist),
        }


@router.get("/whitelist")
async def get_whitelist():
    with get_db_context() as db:
        return [{"email": row.email, "notes": row.notes, "active": row.active}
                for row in db.query(SMTPAbuseWhitelist).filter(SMTPAbuseWhitelist.active.is_(True)).order_by(SMTPAbuseWhitelist.email).all()]


@router.post("/whitelist")
async def add_whitelist(request: WhitelistRequest):
    require_control_access()
    email = normalized(str(request.email))
    with get_db_context() as db:
        row = db.query(SMTPAbuseWhitelist).filter(SMTPAbuseWhitelist.email == email).first()
        if row:
            row.active = True
            row.notes = request.notes
        else:
            db.add(SMTPAbuseWhitelist(email=email, notes=request.notes, active=True))
    return {"email": email, "active": True}


@router.put("/whitelist")
async def replace_whitelist(request: WhitelistBulkRequest):
    require_control_access()
    emails = set()
    for value in request.emails:
        email = normalized(value)
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            raise HTTPException(status_code=422, detail=f"Invalid email format: {value}")
        emails.add(email)

    with get_db_context() as db:
        existing = {row.email: row for row in db.query(SMTPAbuseWhitelist).all()}
        for email, row in existing.items():
            row.active = email in emails
        for email in emails - set(existing):
            db.add(SMTPAbuseWhitelist(email=email, active=True))
    return {"active": sorted(emails), "count": len(emails)}


@router.delete("/whitelist/{email}")
async def remove_whitelist(email: str):
    require_control_access()
    email = normalized(email)
    with get_db_context() as db:
        row = db.query(SMTPAbuseWhitelist).filter(SMTPAbuseWhitelist.email == email).first()
        if not row:
            raise HTTPException(status_code=404, detail="Email is not on the whitelist")
        row.active = False
    return {"email": email, "active": False}


@router.post("/mailboxes/{email}/block")
async def manual_block(email: str):
    require_control_access()
    with get_db_context() as db:
        count = db.query(MessageCorrelation).filter(
            func.lower(MessageCorrelation.sender) == normalized(email),
            func.lower(MessageCorrelation.direction) == "outbound",
            MessageCorrelation.first_seen >= datetime.utcnow() - timedelta(minutes=settings.smtp_abuse_window_minutes)
        ).count()
    return await block_mailbox(email, count, automatic=False, operator="manual")


@router.post("/mailboxes/{email}/unblock")
async def manual_unblock(email: str):
    require_control_access()
    await mailcow_api.edit_mailbox(normalized(email), {"smtp_access": "1"})
    with get_db_context() as db:
        db.add(SMTPAbuseAction(email=normalized(email), message_count=0,
                               threshold=settings.smtp_abuse_threshold,
                               window_minutes=settings.smtp_abuse_window_minutes,
                               action="unblocked", automatic=False, operator="manual"))
    return {"email": normalized(email), "smtp_access": True}
