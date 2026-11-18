"""Read-only Gmail (IMAP) checker used to confirm real bank credit alerts."""
import imaplib, email, re, html
from decimal import Decimal, InvalidOperation
from email.utils import parsedate_to_datetime
from datetime import timezone

AMT = re.compile(r"(?:rs\.?|inr|\u20b9)\s*([\d,]+(?:\.\d{1,2})?)", re.I)


def _connect(user, pw):
    m = imaplib.IMAP4_SSL("imap.gmail.com", timeout=25)
    m.login(user, pw)
    return m


def test_login(user, pw):
    try:
        m = _connect(user, pw)
        m.logout()
        return True, None
    except Exception as e:
        return False, "Gmail login failed. Use a 16 letter app password with IMAP enabled."


def _text(msg):
    parts = []
    for p in msg.walk():
        ct = p.get_content_type()
        if ct not in ("text/plain", "text/html"):
            continue
        try:
            raw = p.get_payload(decode=True) or b""
            s = raw.decode(p.get_content_charset() or "utf-8", "replace")
        except Exception:
            continue
        if ct == "text/html":
            s = html.unescape(re.sub(r"<[^>]+>", " ", s))
        parts.append(s)
    return re.sub(r"\s+", " ", " ".join(parts))


def find_credit(user, pw, utr, amount, not_before):
    """Returns (ok, reason). ok only if a credit mail has this UTR and exact amount."""
    try:
        m = _connect(user, pw)
    except Exception:
        return False, "Merchant mailbox login failed. Merchant must update the app password."
    seen_utr = False
    try:
        for box in ('"[Gmail]/All Mail"', "INBOX"):
            typ, _ = m.select(box, readonly=True)
            if typ != "OK":
                continue
            typ, data = m.search(None, "X-GM-RAW", utr)
            if typ != "OK" or not data or not data[0]:
                continue
            for i in data[0].split()[-10:]:
                typ, md = m.fetch(i, "(RFC822)")
                if typ != "OK" or not md or not md[0]:
                    continue
                msg = email.message_from_bytes(md[0][1])
                try:
                    dt = parsedate_to_datetime(msg.get("Date"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                except Exception:
                    continue
                if dt < not_before:
                    continue
                body = _text(msg)
                if utr not in body.replace(" ", ""):
                    continue
                low = body.lower()
                if "credit" not in low or "debit" in low.split("credit")[0][-40:]:
                    continue
                seen_utr = True
                for a in AMT.findall(body):
                    try:
                        if Decimal(a.replace(",", "")) == Decimal(amount):
                            return True, "ok"
                    except InvalidOperation:
                        pass
        return False, ("UTR found but the amount does not match this order." if seen_utr
                       else "Payment not found yet. Bank alerts can take 1 to 2 minutes, try again shortly.")
    except Exception:
        return False, "Could not read the mailbox right now. Try again."
    finally:
        try:
            m.logout()
        except Exception:
            pass
