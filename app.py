import os, re, json, csv, io, base64, hashlib, hmac, secrets, socket, threading, ipaddress, time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from urllib.parse import urlparse, quote

from flask import (Flask, render_template, request, redirect, url_for, session,
                   flash, jsonify, abort, g, send_file, Response)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
import segno, requests

import mailcheck

SITE_NAME = os.environ.get("SITE_NAME", "Azura Pay")
TG_CONTACT = os.environ.get("TG_CONTACT", "zadosint")
TTL_MIN = int(os.environ.get("ORDER_TTL_MIN", "30"))
MAX_ATTEMPTS = 8

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
SECRET = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config.update(
    SECRET_KEY=SECRET,
    SQLALCHEMY_DATABASE_URI=(os.environ.get("DATABASE_URL") or "sqlite:///gateway.db").replace("postgres://", "postgresql://", 1),
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("PROD")),
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
)
db = SQLAlchemy(app)
FERNET = Fernet(base64.urlsafe_b64encode(hashlib.sha256((os.environ.get("ENCRYPTION_KEY") or SECRET).encode()).digest()))


def now():
    return datetime.utcnow()


def new_key():
    return "az_" + secrets.token_urlsafe(30)


# ------------------------------------------------------------------ models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default="user")
    phone = db.Column(db.String(15))
    email = db.Column(db.String(120))
    gmail = db.Column(db.String(120))
    app_pw_enc = db.Column(db.Text)
    upi_id = db.Column(db.String(80))
    biz_name = db.Column(db.String(60))
    api_key = db.Column(db.String(80), unique=True)
    banned = db.Column(db.Boolean, default=False)
    referred_by = db.Column(db.String(40))
    created_at = db.Column(db.DateTime, default=now)
    last_login = db.Column(db.DateTime)

    @property
    def setup_done(self):
        return all([self.phone, self.email, self.gmail, self.app_pw_enc, self.upi_id])


class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(40), unique=True, nullable=False)
    created_by = db.Column(db.Integer)
    max_uses = db.Column(db.Integer, default=1)  # 0 = unlimited
    uses = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)
    note = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=now)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(24), unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    note = db.Column(db.String(120))
    customer_ref = db.Column(db.String(80))
    callback_url = db.Column(db.String(300))
    status = db.Column(db.String(12), default="pending")  # pending paid expired cancelled
    utr = db.Column(db.String(20), unique=True)
    attempts = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=now)
    expires_at = db.Column(db.DateTime)
    paid_at = db.Column(db.DateTime)
    user = db.relationship("User")


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    sender = db.Column(db.String(6))  # user / admin
    body = db.Column(db.String(1000))
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now)


class Setting(db.Model):
    key = db.Column(db.String(40), primary_key=True)
    value = db.Column(db.Text)


def get_setting(k, d=""):
    s = db.session.get(Setting, k)
    return s.value if s else d


def set_setting(k, v):
    s = db.session.get(Setting, k)
    if s:
        s.value = v
    else:
        db.session.add(Setting(key=k, value=v))
    db.session.commit()


# ------------------------------------------------------------------ helpers
def encrypt(s):
    return FERNET.encrypt(s.encode()).decode()


def decrypt(s):
    try:
        return FERNET.decrypt(s.encode()).decode()
    except (InvalidToken, AttributeError):
        return None


def money(v):
    try:
        d = Decimal(str(v).strip()).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return None
    return d if Decimal("1") <= d <= Decimal("100000") else None


_hits = {}


def limited(key, n, sec):
    t = time.time()
    lst = [x for x in _hits.get(key, []) if t - x < sec]
    if len(lst) >= n:
        _hits[key] = lst
        return True
    lst.append(t)
    _hits[key] = lst
    return False


def client_ip():
    return request.remote_addr or "?"


def safe_url(u):
    try:
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        for info in socket.getaddrinfo(p.hostname, p.port or 443):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return True
    except Exception:
        return False


def upi_uri(o):
    m = o.user
    name = quote(m.biz_name or m.username)
    return f"upi://pay?pa={quote(m.upi_id)}&pn={name}&am={o.amount:.2f}&cu=INR&tn={o.order_id}&tr={o.order_id}"


def qr_uri(text):
    return segno.make(text, error="m").svg_data_uri(scale=8, border=2, dark="#0a3d91")


def refresh(o):
    if o.status == "pending" and o.expires_at and now() > o.expires_at:
        o.status = "expired"
        db.session.commit()
    return o


def new_order(user, amount, note="", callback="", ref=""):
    o = Order(order_id="ORD" + secrets.token_hex(6).upper(), user_id=user.id, amount=amount,
              note=(note or "")[:120], callback_url=(callback or "")[:300], customer_ref=(ref or "")[:80],
              expires_at=now() + timedelta(minutes=TTL_MIN))
    db.session.add(o)
    db.session.commit()
    return o


def fire_callback(o):
    if not o.callback_url or not safe_url(o.callback_url):
        return
    body = json.dumps({"order_id": o.order_id, "status": o.status, "amount": str(o.amount), "utr": o.utr,
                       "customer_ref": o.customer_ref, "paid_at": o.paid_at.isoformat() + "Z" if o.paid_at else None},
                      sort_keys=True)
    sig = hmac.new(o.user.api_key.encode(), body.encode(), hashlib.sha256).hexdigest()
    url = o.callback_url

    def run():
        try:
            requests.post(url, data=body, timeout=8, allow_redirects=False,
                          headers={"Content-Type": "application/json", "X-Signature": sig})
        except Exception:
            pass
    threading.Thread(target=run, daemon=True).start()


def do_verify(o, utr):
    refresh(o)
    if o.status == "paid":
        return True, "This order is already paid."
    if o.status != "pending":
        return False, "This order has expired or was cancelled."
    utr = re.sub(r"\s", "", utr or "")
    if not re.fullmatch(r"\d{12}", utr):
        return False, "UTR must be exactly 12 digits."
    if o.attempts >= MAX_ATTEMPTS:
        return False, "Too many attempts. Contact the merchant."
    if Order.query.filter_by(utr=utr).first():
        return False, "This UTR was already used."
    m = o.user
    pw = decrypt(m.app_pw_enc)
    if not pw:
        return False, "Merchant mailbox is not connected."
    o.attempts += 1
    db.session.commit()
    ok, reason = mailcheck.find_credit(m.gmail, pw, utr, o.amount,
                                       o.created_at.replace(tzinfo=timezone.utc) - timedelta(minutes=2))
    if not ok:
        return False, reason
    o.utr, o.status, o.paid_at = utr, "paid", now()
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return False, "This UTR was already used."
    fire_callback(o)
    return True, "Payment verified."


def order_json(o):
    return {"order_id": o.order_id, "status": o.status, "amount": str(o.amount), "note": o.note,
            "created_at": o.created_at.isoformat() + "Z", "paid_at": o.paid_at.isoformat() + "Z" if o.paid_at else None}


# ------------------------------------------------------------------ request hooks
@app.before_request
def load_user():
    g.user = db.session.get(User, session["uid"]) if "uid" in session else None
    if g.user and g.user.banned:
        session.clear()
        g.user = None
    if request.method == "POST" and not request.path.startswith("/api/"):
        tok = request.form.get("_csrf") or request.headers.get("X-CSRF") or ""
        if not tok or not hmac.compare_digest(tok, session.get("csrf", "")):
            abort(400, "Session expired. Reload the page and try again.")


@app.context_processor
def inject():
    unread = 0
    if g.get("user"):
        if g.user.role == "admin":
            unread = Message.query.filter_by(sender="user", read=False).count()
        else:
            unread = Message.query.filter_by(user_id=g.user.id, sender="admin", read=False).count()
    return dict(me=g.get("user"), site=SITE_NAME, tg=TG_CONTACT, unread=unread, ttl=TTL_MIN,
                csrf=session.setdefault("csrf", secrets.token_hex(16)), base=request.url_root.rstrip("/"))


@app.template_filter("ist")
def ist(dt):
    return (dt + timedelta(hours=5, minutes=30)).strftime("%d %b %Y, %I:%M %p") if dt else "-"


def login_required(setup=True, admin=False):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not g.user:
                return redirect(url_for("login"))
            if admin and g.user.role != "admin":
                abort(403)
            if setup and g.user.role != "admin" and not g.user.setup_done:
                return redirect(url_for("setup"))
            return f(*a, **k)
        return w
    return deco


# ------------------------------------------------------------------ auth
@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if limited("reg" + client_ip(), 10, 600):
            flash("Too many attempts. Wait a few minutes.", "err")
            return render_template("register.html")
        uname = request.form.get("username", "").strip().lower()
        pw = request.form.get("password", "")
        code = request.form.get("referral", "").strip().upper()
        ref = Referral.query.filter_by(code=code).first() if code else None
        if not re.fullmatch(r"[a-z0-9_]{3,24}", uname):
            flash("Username: 3 to 24 letters, numbers or underscore.", "err")
        elif len(pw) < 8:
            flash("Password must be at least 8 characters.", "err")
        elif not ref or not ref.active:
            flash("Invalid referral code. Registration needs a valid code.", "err")
        elif User.query.filter_by(username=uname).first():
            flash("Username already taken.", "err")
        else:
            n = Referral.query.filter(Referral.id == ref.id, or_(Referral.max_uses == 0, Referral.uses < Referral.max_uses)) \
                .update({"uses": Referral.uses + 1})
            if not n:
                db.session.rollback()
                flash("This referral code has reached its limit.", "err")
            else:
                u = User(username=uname, password_hash=generate_password_hash(pw), api_key=new_key(), referred_by=code)
                db.session.add(u)
                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    flash("Username already taken.", "err")
                    return render_template("register.html")
                session.clear()
                session["uid"] = u.id
                flash("Account created. Finish your payment profile to continue.", "ok")
                return redirect(url_for("setup"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if limited("login" + client_ip(), 10, 600):
            flash("Too many attempts. Wait a few minutes.", "err")
            return render_template("login.html")
        u = User.query.filter_by(username=request.form.get("username", "").strip().lower()).first()
        if not u or not check_password_hash(u.password_hash, request.form.get("password", "")):
            flash("Wrong username or password.", "err")
        elif u.banned:
            flash("This account is blocked. Contact the admin.", "err")
        else:
            session.clear()
            session["uid"] = u.id
            session.permanent = True
            u.last_login = now()
            db.session.commit()
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/setup", methods=["GET", "POST"])
@login_required(setup=False)
def setup():
    u = g.user
    if request.method == "POST":
        f = request.form
        phone = re.sub(r"\D", "", f.get("phone", ""))[-10:]
        mail = f.get("email", "").strip().lower()
        gmail = f.get("gmail", "").strip().lower()
        apw = re.sub(r"\s", "", f.get("app_password", ""))
        upi = f.get("upi_id", "").strip().lower()
        biz = f.get("biz_name", "").strip()[:60]
        err = None
        if not re.fullmatch(r"[6-9]\d{9}", phone):
            err = "Enter a valid 10 digit mobile number."
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", mail):
            err = "Enter a valid email."
        elif not re.fullmatch(r"[a-z0-9.]+@gmail\.com", gmail):
            err = "Enter the Gmail address that receives your bank alerts."
        elif not re.fullmatch(r"[\w.\-]{2,}@[a-z]{2,}", upi):
            err = "Enter a valid UPI id like name@bank."
        elif not apw and not u.app_pw_enc:
            err = "Google app password is required."
        elif apw and not re.fullmatch(r"[a-z]{16}", apw.lower()):
            err = "Google app password is 16 letters (spaces are fine)."
        if not err and (apw or gmail != u.gmail):
            pw = apw.lower() if apw else decrypt(u.app_pw_enc)
            ok, why = mailcheck.test_login(gmail, pw or "")
            if not ok:
                err = why
            elif apw:
                u.app_pw_enc = encrypt(apw.lower())
        if err:
            flash(err, "err")
        else:
            u.phone, u.email, u.gmail, u.upi_id, u.biz_name = phone, mail, gmail, upi, biz or u.username
            db.session.commit()
            flash("Profile saved and mailbox connected.", "ok")
            return redirect(url_for("dashboard"))
    return render_template("setup.html", u=u)


# ------------------------------------------------------------------ merchant area
@app.route("/dashboard")
@login_required()
def dashboard():
    u = g.user
    q = Order.query.filter_by(user_id=u.id)
    paid = q.filter_by(status="paid")
    stats = dict(
        volume=db.session.query(func.coalesce(func.sum(Order.amount), 0)).filter(Order.user_id == u.id, Order.status == "paid").scalar(),
        paid=paid.count(), pending=q.filter_by(status="pending").count(), total=q.count())
    orders = q.order_by(Order.id.desc()).limit(8).all()
    for o in orders:
        refresh(o)
    codes = Referral.query.filter_by(created_by=u.id).order_by(Referral.id.desc()).all()
    return render_template("dashboard.html", stats=stats, orders=orders, codes=codes,
                           notice=get_setting("announcement"))


@app.route("/order/create", methods=["POST"])
@login_required()
def order_create():
    amt = money(request.form.get("amount"))
    if not amt:
        flash("Amount must be between Rs. 1 and Rs. 1,00,000.", "err")
        return redirect(url_for("dashboard"))
    if not g.user.setup_done:
        flash("Finish your payment profile first.", "err")
        return redirect(url_for("setup"))
    o = new_order(g.user, amt, request.form.get("note", ""))
    return redirect(url_for("payment", oid=o.order_id))


@app.route("/key/regen", methods=["POST"])
@login_required(setup=False)
def key_regen():
    g.user.api_key = new_key()
    db.session.commit()
    flash("New API key generated. The old key stopped working.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/referral/new", methods=["POST"])
@login_required()
def referral_new():
    active = Referral.query.filter_by(created_by=g.user.id, active=True).filter(Referral.uses < Referral.max_uses).count()
    if g.user.role != "admin" and active >= 5:
        flash("You already have 5 unused codes.", "err")
    else:
        db.session.add(Referral(code="AZ-" + secrets.token_hex(4).upper(), created_by=g.user.id, max_uses=1,
                                note="by " + g.user.username))
        db.session.commit()
        flash("New single use referral code created.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/history")
@login_required()
def history():
    st = request.args.get("status", "")
    q = Order.query.filter_by(user_id=g.user.id)
    if st in ("paid", "pending", "expired", "cancelled"):
        q = q.filter_by(status=st)
    orders = q.order_by(Order.id.desc()).limit(500).all()
    for o in orders:
        refresh(o)
    return render_template("history.html", orders=orders, st=st)


@app.route("/history.csv")
@login_required()
def history_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["order_id", "amount", "status", "utr", "note", "created_utc", "paid_utc"])
    for o in Order.query.filter_by(user_id=g.user.id).order_by(Order.id.desc()):
        w.writerow([o.order_id, o.amount, o.status, o.utr or "", o.note or "", o.created_at, o.paid_at or ""])
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=history.csv"})


# ------------------------------------------------------------------ public payer pages
@app.route("/payment")
@app.route("/payment/<oid>")
def payment(oid=None):
    oid = (oid or request.args.get("order_id", "")).strip().upper()
    if not oid:
        return render_template("payment.html", o=None)
    o = Order.query.filter_by(order_id=oid).first()
    if not o:
        flash("Order not found.", "err")
        return render_template("payment.html", o=None)
    refresh(o)
    qr = uri = None
    if o.status == "pending":
        uri = upi_uri(o)
        qr = qr_uri(uri)
    return render_template("payment.html", o=o, qr=qr, uri=uri)


@app.route("/verify_order", methods=["GET", "POST"])
def verify_order():
    oid = (request.values.get("order_id", "")).strip().upper()
    if request.method == "POST":
        o = Order.query.filter_by(order_id=oid).first()
        if limited("ver" + client_ip(), 12, 300):
            flash("Too many verification attempts. Wait 5 minutes.", "err")
        elif not o:
            flash("Order not found.", "err")
        else:
            ok, msg = do_verify(o, request.form.get("utr", ""))
            flash(msg, "ok" if ok else "err")
            if ok:
                return redirect(url_for("payment", oid=o.order_id))
    return render_template("verify_order.html", oid=oid)


@app.route("/order_check")
def order_check():
    oid = request.args.get("order_id", "").strip().upper()
    o = Order.query.filter_by(order_id=oid).first() if oid else None
    if o:
        refresh(o)
    elif oid:
        flash("Order not found.", "err")
    return render_template("order_check.html", o=o, oid=oid)


# ------------------------------------------------------------------ merchant API
def api_user():
    u = User.query.filter_by(api_key=request.headers.get("X-API-Key", "")).first() if request.headers.get("X-API-Key") else None
    if not u or u.banned or not u.setup_done:
        return None
    return u


@app.route("/api/create_order", methods=["POST"])
def api_create_order():
    u = api_user()
    if not u:
        return jsonify(error="invalid api key or incomplete profile"), 401
    d = request.get_json(silent=True) or {}
    amt = money(d.get("amount"))
    if not amt:
        return jsonify(error="amount must be between 1 and 100000"), 400
    cb = d.get("callback_url") or ""
    if cb and not safe_url(cb):
        return jsonify(error="callback_url must be a public http(s) url"), 400
    o = new_order(u, amt, d.get("note", ""), cb, d.get("customer_ref", ""))
    return jsonify(order_json(o), payment_url=f"{request.url_root.rstrip('/')}/payment/{o.order_id}",
                   upi_uri=upi_uri(o), expires_at=o.expires_at.isoformat() + "Z")


@app.route("/api/order_status/<oid>")
def api_order_status(oid):
    o = Order.query.filter_by(order_id=oid.upper()).first()
    if not o:
        return jsonify(error="not found"), 404
    return jsonify(order_json(refresh(o)))


@app.route("/api/verify", methods=["POST"])
def api_verify():
    u = api_user()
    if not u:
        return jsonify(error="invalid api key"), 401
    d = request.get_json(silent=True) or {}
    o = Order.query.filter_by(order_id=str(d.get("order_id", "")).upper(), user_id=u.id).first()
    if not o:
        return jsonify(error="order not found"), 404
    if limited("apiv" + u.api_key, 30, 300):
        return jsonify(error="rate limited"), 429
    ok, msg = do_verify(o, str(d.get("utr", "")))
    return jsonify(ok=ok, message=msg, order=order_json(o))


# ------------------------------------------------------------------ chat
@app.route("/chat")
@login_required(setup=False)
def chat():
    return render_template("chat.html", uid=g.user.id, title="Chat with admin")


@app.route("/chat/poll")
@login_required(setup=False)
def chat_poll():
    uid = request.args.get("uid", type=int) if g.user.role == "admin" else g.user.id
    after = request.args.get("after", 0, type=int)
    if not uid:
        abort(400)
    msgs = Message.query.filter(Message.user_id == uid, Message.id > after).order_by(Message.id).all()
    other = "user" if g.user.role == "admin" else "admin"
    for m in msgs:
        if m.sender == other:
            m.read = True
    db.session.commit()
    return jsonify([dict(id=m.id, sender=m.sender, body=m.body, t=ist(m.created_at)) for m in msgs])


@app.route("/chat/send", methods=["POST"])
@login_required(setup=False)
def chat_send():
    body = (request.form.get("body") or "").strip()[:1000]
    uid = request.form.get("uid", type=int) if g.user.role == "admin" else g.user.id
    if not body or not uid or limited("chat%s" % g.user.id, 20, 60):
        return jsonify(ok=False), 400
    db.session.add(Message(user_id=uid, sender="admin" if g.user.role == "admin" else "user", body=body))
    db.session.commit()
    return jsonify(ok=True)


# ------------------------------------------------------------------ admin
@app.route("/admin")
@login_required(setup=False, admin=True)
def admin():
    s = dict(
        users=User.query.count(), orders=Order.query.count(),
        paid=Order.query.filter_by(status="paid").count(),
        pending=Order.query.filter_by(status="pending").count(),
        volume=db.session.query(func.coalesce(func.sum(Order.amount), 0)).filter(Order.status == "paid").scalar())
    codes = Referral.query.order_by(Referral.id.desc()).limit(200).all()
    return render_template("admin.html", s=s, codes=codes, notice=get_setting("announcement"))


@app.route("/admin/notice", methods=["POST"])
@login_required(setup=False, admin=True)
def admin_notice():
    set_setting("announcement", request.form.get("text", "").strip()[:300])
    flash("Announcement updated.", "ok")
    return redirect(url_for("admin"))


@app.route("/admin/code", methods=["POST"])
@login_required(setup=False, admin=True)
def admin_code():
    f = request.form
    act = f.get("act")
    if act == "create":
        code = re.sub(r"[^A-Z0-9\-]", "", f.get("code", "").upper())[:40] or "AZ-" + secrets.token_hex(4).upper()
        db.session.add(Referral(code=code, created_by=g.user.id, max_uses=max(0, f.get("max_uses", 1, type=int)),
                                note=f.get("note", "")[:120]))
        try:
            db.session.commit()
            flash(f"Code {code} created.", "ok")
        except IntegrityError:
            db.session.rollback()
            flash("That code already exists.", "err")
    else:
        r = db.session.get(Referral, f.get("id", type=int))
        if r and act == "toggle":
            r.active = not r.active
        elif r and act == "delete":
            db.session.delete(r)
        db.session.commit()
    return redirect(url_for("admin"))


@app.route("/admin/users")
@login_required(setup=False, admin=True)
def admin_users():
    q = request.args.get("q", "").strip().lower()
    qs = User.query
    if q:
        qs = qs.filter(or_(User.username.contains(q), User.email.contains(q), User.phone.contains(q), User.upi_id.contains(q)))
    users = qs.order_by(User.id.desc()).limit(300).all()
    vol = dict(db.session.query(Order.user_id, func.sum(Order.amount)).filter(Order.status == "paid").group_by(Order.user_id).all())
    return render_template("admin_users.html", users=users, q=q, vol=vol)


@app.route("/admin/user/<int:uid>/<act>", methods=["POST"])
@login_required(setup=False, admin=True)
def admin_user_act(uid, act):
    u = db.session.get(User, uid) or abort(404)
    if u.id == g.user.id and act in ("ban", "demote", "delete"):
        flash("You cannot do that to your own account.", "err")
        return redirect(url_for("admin_users"))
    if act == "ban":
        u.banned = True
    elif act == "unban":
        u.banned = False
    elif act == "promote":
        u.role = "admin"
    elif act == "demote":
        u.role = "user"
    elif act == "clear_mail":
        u.app_pw_enc = None
    elif act == "regen_key":
        u.api_key = new_key()
    elif act == "resetpw":
        tmp = secrets.token_urlsafe(8)
        u.password_hash = generate_password_hash(tmp)
        flash(f"Temporary password for {u.username}: {tmp}", "ok")
    elif act == "delete":
        Message.query.filter_by(user_id=u.id).delete()
        Order.query.filter_by(user_id=u.id).delete()
        Referral.query.filter_by(created_by=u.id).delete()
        db.session.delete(u)
    else:
        abort(404)
    db.session.commit()
    return redirect(url_for("admin_users"))


@app.route("/admin/orders")
@login_required(setup=False, admin=True)
def admin_orders():
    q = request.args.get("q", "").strip()
    st = request.args.get("status", "")
    qs = Order.query.join(User)
    if q:
        qs = qs.filter(or_(Order.order_id.contains(q.upper()), Order.utr.contains(q), User.username.contains(q.lower())))
    if st:
        qs = qs.filter(Order.status == st)
    orders = qs.order_by(Order.id.desc()).limit(300).all()
    for o in orders:
        refresh(o)
    return render_template("admin_orders.html", orders=orders, q=q, st=st)


@app.route("/admin/order/<int:oid>/<act>", methods=["POST"])
@login_required(setup=False, admin=True)
def admin_order_act(oid, act):
    o = db.session.get(Order, oid) or abort(404)
    if act == "paid" and o.status != "paid":
        o.status, o.paid_at = "paid", now()
        db.session.commit()
        fire_callback(o)
    elif act == "cancel" and o.status == "pending":
        o.status = "cancelled"
    db.session.commit()
    return redirect(request.referrer or url_for("admin_orders"))


@app.route("/admin/chat")
@login_required(setup=False, admin=True)
def admin_chat():
    rows = []
    for u in User.query.filter(User.id.in_(db.session.query(Message.user_id).distinct())).all():
        last = Message.query.filter_by(user_id=u.id).order_by(Message.id.desc()).first()
        un = Message.query.filter_by(user_id=u.id, sender="user", read=False).count()
        rows.append((u, last, un))
    rows.sort(key=lambda r: r[1].id, reverse=True)
    return render_template("admin_chat.html", rows=rows)


@app.route("/admin/chat/<int:uid>")
@login_required(setup=False, admin=True)
def admin_chat_user(uid):
    u = db.session.get(User, uid) or abort(404)
    return render_template("chat.html", uid=u.id, title="Chat with " + u.username)


def _ser(v):
    if isinstance(v, (datetime,)):
        return v.isoformat()
    if isinstance(v, Decimal):
        return str(v)
    return v


@app.route("/admin/export/<kind>")
@login_required(setup=False, admin=True)
def admin_export(kind):
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if kind == "db" and uri.startswith("sqlite"):
        path = db.engine.url.database
        if not os.path.isabs(path):
            path = os.path.join(app.instance_path, path)
        return send_file(path, as_attachment=True, download_name="gateway.db")
    data = {}
    for M in (User, Referral, Order, Message, Setting):
        data[M.__tablename__] = [{c.name: _ser(getattr(r, c.name)) for c in M.__table__.columns} for r in M.query.all()]
    return Response(json.dumps(data, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=gateway_export.json"})


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def err(e):
    return render_template("error.html", e=e), e.code


# ------------------------------------------------------------------ bootstrap
def init():
    with app.app_context():
        try:
            db.create_all()
            if not User.query.filter_by(role="admin").first():
                name = os.environ.get("ADMIN_USERNAME", "admin").lower()
                pw = os.environ.get("ADMIN_PASSWORD")
                gen = not pw
                pw = pw or secrets.token_urlsafe(10)
                db.session.add(User(username=name, password_hash=generate_password_hash(pw), role="admin", api_key=new_key()))
                db.session.commit()
                if gen:
                    print(f"[setup] admin created -> username: {name}  password: {pw}", flush=True)
        except IntegrityError:
            db.session.rollback()


init()

if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
