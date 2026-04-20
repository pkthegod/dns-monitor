"""
email_report.py — Envio de relatorio mensal por email via SMTP.
"""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

logger = logging.getLogger("infra-vision.email")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")
SMTP_TLS = os.environ.get("SMTP_TLS", "true").lower() in ("true", "1", "yes")


def is_configured() -> bool:
    """Retorna True se SMTP esta configurado."""
    return bool(SMTP_HOST and SMTP_USER and SMTP_FROM)


def send_report_email(
    to_email: str,
    client_name: str,
    month_label: str,
    pdf_bytes: bytes,
    uptime_pct: float,
) -> bool:
    """
    Envia email com relatorio PDF anexado.
    Retorna True se enviou com sucesso.
    """
    if not is_configured():
        logger.warning("SMTP nao configurado — email nao enviado para %s", to_email)
        return False

    msg = MIMEMultipart()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = f"Infra-Vision — Relatorio {month_label}"

    # Corpo do email (HTML simples)
    body = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto;
                background: #1a1b26; color: #a9b1d6; padding: 32px; border-radius: 12px;">
        <h2 style="color: #7aa2f7; margin-top: 0;">Infra-Vision</h2>
        <p>Ola, <strong>{client_name}</strong>.</p>
        <p>Segue em anexo o relatorio mensal de monitoramento DNS referente a <strong>{month_label}</strong>.</p>
        <div style="background: #24283b; padding: 16px 20px; border-radius: 8px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px;">
                Disponibilidade: <strong style="color: {'#9ece6a' if uptime_pct >= 99.9 else '#e0af68' if uptime_pct >= 99 else '#f7768e'};">{uptime_pct}%</strong>
            </p>
        </div>
        <p>Para mais detalhes, acesse o <a href="#" style="color: #7aa2f7;">portal do cliente</a> ou abra o PDF anexo.</p>
        <hr style="border: none; border-top: 1px solid #3b4261; margin: 24px 0;">
        <p style="font-size: 11px; color: #565f89;">
            Este email foi gerado automaticamente pelo Infra-Vision. Nao responda este email.
        </p>
    </div>
    """
    msg.attach(MIMEText(body, "html", "utf-8"))

    # Anexa PDF
    part = MIMEBase("application", "pdf")
    part.set_payload(pdf_bytes)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="dns-report-{month_label}.pdf"')
    msg.attach(part)

    try:
        if SMTP_TLS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        if SMTP_USER and SMTP_PASS:
            server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, to_email, msg.as_string())
        server.quit()
        logger.info("Email relatorio enviado para %s (%s)", to_email, month_label)
        return True
    except Exception as exc:
        logger.error("Falha ao enviar email para %s: %s", to_email, exc)
        return False
