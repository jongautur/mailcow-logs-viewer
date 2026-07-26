# SMTP Abuse Protection

This guide describes the optional SMTP abuse protection feature in mailcow Logs Viewer.

---

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Configuration](#configuration)
4. [Security UI](#security-ui)
5. [API](#api)
6. [Notifications](#notifications)
7. [Deployment](#deployment)
8. [Safety Notes](#safety-notes)

---

## Overview

The feature counts correlated outbound messages in a rolling time window. When a mailbox exceeds the configured threshold, the application can disable SMTP sending for that mailbox. The Security activity view also displays internal SMTP activity for visibility, but internal messages do not trigger automatic blocking.

- Only `smtp_access` is changed.
- IMAP and SOGo remain enabled.
- App passwords are revoked when SMTP is blocked.
- The mailbox receives a security notification when SMTP notifications are configured.
- Whitelisted mailboxes are excluded from automatic blocking.
- Automatic actions are recorded in the `smtp_abuse_actions` table.
- Incoming-only mailboxes with SMTP intentionally disabled are not shown unless this system recorded a block for them.

The scheduler checks once per minute. Newly imported messages can take a short time to appear because they must first pass through log ingestion and correlation.

## Requirements

The following are required:

- `MAILCOW_API_KEY` for log ingestion.
- `MAILCOW_API_KEY_RW` with permission to edit mailboxes and delete app passwords.
- SMTP notification settings if users should receive block notifications.
- A container image built from this fork.

## Configuration

Add the following to `.env`:

```env
SMTP_ABUSE_ENABLED=true
SMTP_ABUSE_THRESHOLD=100
SMTP_ABUSE_WINDOW_MINUTES=60
SMTP_ABUSE_HELP_ADDRESS=example@example.com
```

Automatic enforcement is disabled unless `SMTP_ABUSE_ENABLED=true`. The default threshold is 100 messages during 60 minutes.

## Security UI

Open the **Security** tab and expand **Abuse Protection**, directly below the **Fail2ban IP Lists** section, to:

- Click **Edit whitelist** to edit one email address per line, then click **Save whitelist**.
- Filter the saved whitelist entries.
- View the top 10 SMTP activity mailboxes, five per page.
- Close SMTP from a row action or enter any mailbox address in the single-mailbox field.
- Re-enable SMTP for a mailbox from the closed-mailbox list.

When protection is disabled or `MAILCOW_API_KEY_RW` is unavailable, the panel displays a lock overlay and write controls are unavailable.

Re-enabling SMTP does not change IMAP or SOGo access. A mailbox can be automatically blocked again if it exceeds the threshold after it is removed from the whitelist.

## API

All endpoints require application authentication:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/smtp-abuse/status` | View counts, threshold, and whitelist state |
| `GET` | `/api/smtp-abuse/whitelist` | List whitelist entries |
| `POST` | `/api/smtp-abuse/whitelist` | Add or reactivate a whitelist entry |
| `PUT` | `/api/smtp-abuse/whitelist` | Replace the active whitelist; one email per list item |
| `DELETE` | `/api/smtp-abuse/whitelist/{email}` | Deactivate a whitelist entry |
| `POST` | `/api/smtp-abuse/mailboxes/{email}/block` | Disable SMTP and revoke app passwords |
| `POST` | `/api/smtp-abuse/mailboxes/{email}/unblock` | Re-enable SMTP only |

Whitelist request body:

```json
{
  "email": "trusted@example.com",
  "notes": "Monitoring mailbox"
}
```

The bulk whitelist editor uses this request body:

```json
{
  "emails": [
    "trusted@example.com",
    "monitoring@example.com"
  ]
}
```

`PUT /api/smtp-abuse/whitelist` replaces the active list. An email removed from the submitted list is deactivated.

Write operations require both `SMTP_ABUSE_ENABLED=true` and `MAILCOW_API_KEY_RW`. The application authentication middleware protects all endpoints; keep the Logs Viewer restricted to administrators because these operations can modify mailbox SMTP access.

## Notifications

Block notifications use the existing global SMTP settings:

```env
SMTP_ENABLED=true
SMTP_HOST=mail.example.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=...
```

If notification SMTP is not configured, the mailbox is still blocked and the event is logged, but no email is sent.

The current notification subject and plaintext email are stored in `backend/app/routers/smtp_abuse.py`, inside the `notify_blocked()` function. The current message is in English. The HTML body is generated automatically from the plaintext body by converting line breaks to `<br>` elements. Separate editable template files are not currently used.

## Deployment

After changing environment variables or source code, rebuild and restart the application:

```bash
cd /opt/mailcow-logs
sudo docker compose up -d --build app
```

Verify the application health:

```bash
curl http://localhost:8080/api/health
```

## Safety Notes

- Keep automatic enforcement disabled until the threshold has been reviewed.
- Start with a threshold appropriate for the normal sending pattern of the installation.
- Whitelist known high-volume service accounts before enabling enforcement.
- Protect the read-write Mailcow API key because it grants mailbox modification capability.
- Restrict access to the Logs Viewer to trusted administrators; the feature follows the application’s authentication boundary and does not currently implement a separate Keycloak role check.

---

For the environment variable reference, see [ENV Settings](ENV_Settings.md). For the complete API reference, see [API Documentation](API.md).
