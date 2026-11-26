import csv, io, secrets, sqlite3
import qrcode, qrcode.image.svg
from datetime import datetime, date, timedelta
from functools import wraps
from flask import (Flask, g, request, redirect, url_for, session, flash,
                   render_template, Response, abort, jsonify)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-before-real-deployment"
DB = "visitrack.db"
OFFICES = ["Registrar", "Cashier", "Guidance Office", "Admissions", "Library", "President's Office", "Faculty"]
SLOTS = ["08:00", "09:00", "10:00", "11:00", "13:00", "14:00", "15:00", "16:00"]
CAPACITY = 3  # visitors per office per time slot

# --- Helper for 12-hour formatting ---
def to12(slot):
    try:
        h, m = slot.split(":")[:2]
        h = int(h)
        ap = "AM" if h < 12 else "PM"
        h12 = h % 12 or 12
        return f"{h12}:{m} {ap}"
    except:
        return slot

app.jinja_env.filters["to12"] = to12

# ---------- database ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE,
  contact TEXT, password TEXT, role TEXT DEFAULT 'visitor', office TEXT, is_super INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY, user_id INTEGER, office TEXT,
  date TEXT, slot TEXT, purpose TEXT, status TEXT DEFAULT 'pending', created_at TEXT, token TEXT);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY, appointment_id INTEGER, visitor_name TEXT,
  contact TEXT, office TEXT, purpose TEXT, time_in TEXT, time_out TEXT);
CREATE TABLE IF NOT EXISTS resets(id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT UNIQUE,
  expires TEXT, used INTEGER DEFAULT 0);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def q(sql, args=(), one=False):
    rows = db().execute(sql, args).fetchall()
    return (rows[0] if rows else None) if one else rows

def run(sql, args=()):
    cur = db().execute(sql, args)
    db().commit()
    return cur.lastrowid

def init_db():
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    
    # Auto-upgrade older DBs safely
    cols = [r[1] for r in con.execute("PRAGMA table_info(appointments)")]
    if "token" not in cols:
        con.execute("ALTER TABLE appointments ADD COLUMN token TEXT")
    for (i,) in con.execute("SELECT id FROM appointments WHERE token IS NULL").fetchall():
        con.execute("UPDATE appointments SET token=? WHERE id=?", (secrets.token_urlsafe(8), i))
    
    ucols = [r[1] for r in con.execute("PRAGMA table_info(users)")]
    if "office" not in ucols:
        con.execute("ALTER TABLE users ADD COLUMN office TEXT")
    if "is_super" not in ucols:
        con.execute("ALTER TABLE users ADD COLUMN is_super INTEGER DEFAULT 0")
        
    con.commit()
    
    if not con.execute("SELECT 1 FROM users").fetchone():
        # GIN-BAG-O: President na an una nga admin
        seed = [("President", "president@bipsu.edu.ph", "admin123", "admin", "President's Office", 1),
                ("Office Staff", "staff@bipsu.edu.ph", "staff123", "staff", None, 0),
                ("Demo Visitor", "visitor@example.com", "visitor123", "visitor", None, 0)]
        for n, e, p, r, o, s in seed:
            con.execute("INSERT INTO users(name,email,password,role,office,is_super) VALUES(?,?,?,?,?,?)",
                        (n, e, generate_password_hash(p), r, o, s))
        con.commit()
    con.close()

# ---------- auth ----------
def current_user():
    uid = session.get("uid")
    return q("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None

@app.context_processor
def inject():
    return {"user": current_user()}

def need(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if roles and u["role"] not in roles:
                abort(403)
            return f(*a, **k)
        return wrapper
    return deco

STAFF = ("staff", "admin")

@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    return redirect(url_for("my" if u["role"] == "visitor" else "staff"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        name, email, pw = f["name"].strip(), f["email"].strip().lower(), f["password"]
        if not (name and email and len(pw) >= 6):
            flash("Fill in all fields. Password needs at least 6 characters.")
        elif q("SELECT 1 FROM users WHERE email=?", (email,), one=True):
            flash("That email is already registered.")
        else:
            run("INSERT INTO users(name,email,contact,password,role) VALUES(?,?,?,?, 'visitor')",
                (name, email, f.get("contact", ""), generate_password_hash(pw)))
            flash("Account created. You can log in now.")
            return redirect(url_for("login"))
    return render_template("register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = q("SELECT * FROM users WHERE email=?", (request.form["email"].strip().lower(),), one=True)
        if u and check_password_hash(u["password"], request.form["password"]):
            session.clear()
            session["uid"] = u["id"]
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))
        flash("Wrong email or password.")
    return render_template("login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- FORGOT PASSWORD ----------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        u = q("SELECT * FROM users WHERE email=?", (email,), one=True)
        if u:
            token = secrets.token_urlsafe(24)
            expires = (datetime.now() + timedelta(minutes=30)).isoformat(" ", "seconds")
            run("INSERT INTO resets(user_id,token,expires) VALUES(?,?,?)", (u["id"], token, expires))
            link = url_for("reset", token=token, _external=True)
            flash(f"Password reset link (valid 30 min): {link}")
        else:
            flash("If that email exists, a reset link has been generated.")
    return render_template("forgot")

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    r = q("SELECT r.*, u.email FROM resets r JOIN users u ON u.id=r.user_id WHERE r.token=? AND r.used=0", (token,), one=True)
    if not r or datetime.fromisoformat(r["expires"]) < datetime.now():
        flash("Invalid or expired reset link.")
        return redirect(url_for("login"))
    if request.method == "POST":
        pw = request.form["password"]
        if len(pw) < 6:
            flash("Password needs at least 6 characters.")
        else:
            run("UPDATE users SET password=? WHERE id=?", (generate_password_hash(pw), r["user_id"]))
            run("UPDATE resets SET used=1 WHERE id=?", (r["id"],))
            flash("Password updated. You can log in now.")
            return redirect(url_for("login"))
    return render_template("reset", token=token)

# ---------- booking (visitor) ----------
def taken(office, d, slot, exclude=None):
    return q("""SELECT COUNT(*) c FROM appointments WHERE office=? AND date=? AND slot=?
                AND status IN ('pending','approved') AND id IS NOT ?""",
             (office, d, slot, exclude), one=True)["c"]

def check_slot(office, d, slot, exclude=None, user_id=None):
    try:
        day = date.fromisoformat(d)
    except ValueError:
        return "Choose a valid date."
        
    # GIN-TANGGAL NATON AN CHECK KUN NAA BA HA SLOTS LISTAHAN
    if office not in OFFICES:
        return "Choose an office."
    if not slot:
        return "Choose a valid time."
        
    if day < date.today():
        return "Pick today or a later date."
    if day.weekday() >= 5:
        return "Offices are closed on weekends."
        
    if taken(office, d, slot, exclude) >= CAPACITY:
        return "That time is full. Pick another slot."
        
    if user_id:
        existing = q("""SELECT 1 FROM appointments WHERE user_id=? AND office=? AND date=? AND slot=? 
                        AND status IN ('pending', 'approved') AND id IS NOT ?""", 
                     (user_id, office, d, slot, exclude), one=True)
        if existing:
            return "You already have an appointment for this office at this exact date and time."
        
@app.route("/availability")
def availability():
    office, d = request.args.get("office"), request.args.get("date")
    if not office or not d:
        return jsonify({})
    return jsonify({"status": "ok"})

@app.route("/book", methods=["GET", "POST"])
@need("visitor")
def book():
    u = current_user()
    if request.method == "POST":
        f = request.form
        err = check_slot(f.get("office"), f.get("date", ""), f.get("slot"), user_id=u["id"])
        if err:
            flash(err)
        else:
            run("""INSERT INTO appointments(user_id,office,date,slot,purpose,created_at,token)
                   VALUES(?,?,?,?,?,?,?)""", (u["id"], f["office"], f["date"], f["slot"],
                 f.get("purpose", "").strip(), datetime.now().isoformat(" ", "seconds"),
                 secrets.token_urlsafe(8)))
            flash("Appointment requested. Staff will confirm it.")
            return redirect(url_for("my"))
    return render_template("book", a=None, offices=OFFICES, slots=SLOTS, today=date.today().isoformat())

@app.route("/my")
@need("visitor")
def my():
    u = current_user()
    rows = q("SELECT * FROM appointments WHERE user_id=? ORDER BY date DESC, slot", (u["id"],))
    soon = {date.today().isoformat(): "today", (date.today() + timedelta(days=1)).isoformat(): "tomorrow"}
    reminders = []
    nowdt = datetime.now()
    
    for r in rows:
        if r["date"] not in soon or r["status"] not in ("pending", "approved"):
            continue
        if r["date"] == date.today().isoformat():
            try:
                appt_time = datetime.fromisoformat(f"{r['date']}T{r['slot']}:00")
                mins_left = int((appt_time - nowdt).total_seconds() // 60)
                if 0 <= mins_left <= 10:
                    reminders.append((r, f"in {mins_left} minute(s) ({to12(r['slot'])})"))
                    continue
            except ValueError:
                pass
        reminders.append((r, soon[r["date"]]))
        
    return render_template("my", rows=rows, reminders=reminders, today=date.today().isoformat())

def own_open(aid):
    a = q("SELECT * FROM appointments WHERE id=? AND user_id=?", (aid, session["uid"]), one=True)
    if not a:
        abort(404)
    return a

@app.route("/reschedule/<int:aid>", methods=["GET", "POST"])
@need("visitor")
def reschedule(aid):
    a = own_open(aid)
    if a["status"] not in ("pending", "approved"):
        flash("Only pending or approved appointments can be rescheduled.")
        return redirect(url_for("my"))
    if request.method == "POST":
        d, s = request.form.get("date", ""), request.form.get("slot")
        err = check_slot(a["office"], d, s, exclude=aid, user_id=session["uid"])
        if err:
            flash(err)
        else:
            run("UPDATE appointments SET date=?, slot=?, status='pending' WHERE id=?", (d, s, aid))
            flash("Appointment rescheduled. Staff will confirm the new time.")
            return redirect(url_for("my"))
    return render_template("book", a=a, offices=OFFICES, slots=SLOTS, today=date.today().isoformat())

@app.route("/cancel/<int:aid>", methods=["POST"])
@need("visitor")
def cancel(aid):
    own_open(aid)
    run("UPDATE appointments SET status='cancelled' WHERE id=? AND status IN ('pending','approved')", (aid,))
    flash("Appointment cancelled.")
    return redirect(url_for("my"))

# ---------- staff: appointments ----------
@app.route("/staff")
@need(*STAFF)
def staff():
    u = current_user()
    st, d, off = request.args.get("status", ""), request.args.get("date", ""), request.args.get("office", "")
    
    sql = """SELECT a.*, u.name visitor, u.contact FROM appointments a
             JOIN users u ON u.id=a.user_id WHERE 1=1"""
    args = []
    
    if not u["is_super"]:
        if u["office"]:
            sql += " AND a.office = ?"
            args.append(u["office"])
    else:
        if off:
            sql += " AND a.office = ?"
            args.append(off)
            
    if st:
        sql += " AND a.status = ?"
        args.append(st)
    if d:
        sql += " AND a.date = ?"
        args.append(d)
        
    rows = q(sql + " ORDER BY a.date, a.slot", args)
    
    if u["is_super"]:
        today_count = q("SELECT COUNT(*) c FROM appointments WHERE date=? AND status!='cancelled'", (date.today().isoformat(),), one=True)["c"]
        pending_count = q("SELECT COUNT(*) c FROM appointments WHERE status='pending'", one=True)["c"]
    else:
        today_count = q("SELECT COUNT(*) c FROM appointments WHERE date=? AND office=? AND status!='cancelled'", (date.today().isoformat(), u["office"]), one=True)["c"]
        pending_count = q("SELECT COUNT(*) c FROM appointments WHERE status='pending' AND office=?", (u["office"],), one=True)["c"]

    stats = {
        "today": today_count,
        "pending": pending_count,
        "inside": q("SELECT COUNT(*) c FROM logs WHERE time_out IS NULL", one=True)["c"],
    }
    return render_template("staff", rows=rows, stats=stats, offices=OFFICES, f=dict(status=st, date=d, office=off))

@app.route("/appointment/<int:aid>/<action>", methods=["POST"])
@need(*STAFF)
def appt_action(aid, action):
    a = q("SELECT a.*, u.name, u.contact FROM appointments a JOIN users u ON u.id=a.user_id WHERE a.id=?",
          (aid,), one=True) or abort(404)
    if action == "approve" and a["status"] == "pending":
        run("UPDATE appointments SET status='approved' WHERE id=?", (aid,))
    elif action == "decline" and a["status"] in ("pending", "approved"):
        run("UPDATE appointments SET status='declined' WHERE id=?", (aid,))
    elif action == "checkin" and a["status"] == "approved":
        check_in(a)
    else:
        flash("That action isn't available for this appointment.")
    return redirect(request.referrer or url_for("staff"))

# ---------- staff: e-log sheet ----------
def now():
    return datetime.now().isoformat(" ", "seconds")

def log_rows():
    s, a, b = request.args.get("q", "").strip(), request.args.get("from", ""), request.args.get("to", "")
    inside = request.args.get("inside")
    sql, args = "SELECT * FROM logs WHERE 1=1", []
    if s:
        sql += " AND (visitor_name LIKE ? OR office LIKE ? OR purpose LIKE ?)"
        args += [f"%{s}%"] * 3
    if a:
        sql += " AND date(time_in)>=?"; args.append(a)
    if b:
        sql += " AND date(time_in)<=?"; args.append(b)
    if inside:
        sql += " AND time_out IS NULL"
    out = []
    for r in q(sql + " ORDER BY time_in DESC", args):
        r = dict(r)
        r["minutes"] = None
        r["duration"] = None
        if r["time_out"]:
            delta = datetime.fromisoformat(r["time_out"]) - datetime.fromisoformat(r["time_in"])
            r["minutes"] = round(delta.total_seconds() / 60, 2)
            r["duration"] = str(delta).split(".")[0]
        out.append(r)
    return out

@app.route("/log")
@need(*STAFF)
def log():
    return render_template("log", rows=log_rows(), f=request.args)

@app.route("/log/new", methods=["GET", "POST"])
@need(*STAFF)
def log_new():
    if request.method == "POST":
        f = request.form
        if not f.get("name", "").strip():
            flash("Enter the visitor's name.")
        else:
            run("INSERT INTO logs(visitor_name,contact,office,purpose,time_in) VALUES(?,?,?,?,?)",
                (f["name"].strip(), f.get("contact", ""), f.get("office"), f.get("purpose", ""), now()))
            flash("Walk-in logged.")
            return redirect(url_for("log"))
    return render_template("log_new", offices=OFFICES)

@app.route("/log/<int:lid>/out", methods=["POST"])
@need(*STAFF)
def log_out(lid):
    check_out(lid)
    return redirect(request.referrer or url_for("log"))

@app.route("/log/export.csv")
@need(*STAFF)
def log_export():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Visitor", "Contact", "Office", "Purpose", "Time in", "Time out", "Minutes"])
    for r in log_rows():
        w.writerow([r["visitor_name"], r["contact"], r["office"], r["purpose"], r["time_in"], r["time_out"] or "", r["minutes"] or ""])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=visitor_log.csv"})

# ---------- QR passes and scanning ----------
def qr_svg(data):
    buf = io.BytesIO()
    qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, border=2).save(buf)
    return buf.getvalue().decode()

def check_in(a):
    run("""INSERT INTO logs(appointment_id,visitor_name,contact,office,purpose,time_in)
           VALUES(?,?,?,?,?,?)""", (a["id"], a["name"], a["contact"], a["office"], a["purpose"], now()))
    run("UPDATE appointments SET status='checked-in' WHERE id=?", (a["id"],))
    flash(f"{a['name']} checked in.")

def check_out(lid):
    run("UPDATE logs SET time_out=? WHERE id=? AND time_out IS NULL", (now(), lid))
    run("""UPDATE appointments SET status='completed' WHERE id=(SELECT appointment_id FROM logs WHERE id=?)""", (lid,))
    flash("Checked out.")

def by_token(t):
    return q("""SELECT a.*, u.name, u.contact FROM appointments a
                JOIN users u ON u.id=a.user_id WHERE a.token=?""", (t,), one=True)

@app.route("/pass/<int:aid>")
@need("visitor")
def pass_page(aid):
    a = own_open(aid)
    if a["status"] not in ("approved", "checked-in"):
        flash("Your QR pass appears after staff approve the appointment.")
        return redirect(url_for("my"))
    return render_template("pass", a=a, svg=qr_svg(request.host_url + "scan/" + a["token"]))

@app.route("/scan", methods=["GET", "POST"])
@need(*STAFF)
def scan():
    if request.method == "POST":
        code = request.form.get("code", "").strip().rstrip("/").split("/")[-1]
        if by_token(code):
            return redirect(url_for("scan_token", token=code))
        flash("Code not recognized. Scan again or check the code.")
    return render_template("scan")

@app.route("/scan/<token>", methods=["GET", "POST"])
@need(*STAFF)
def scan_token(token):
    a = by_token(token) or abort(404)
    lg = q("SELECT * FROM logs WHERE appointment_id=? ORDER BY id DESC", (a["id"],), one=True)
    if request.method == "POST":
        if a["status"] == "approved" and request.form.get("do") == "in":
            check_in(a)
        elif a["status"] == "checked-in" and lg and not lg["time_out"] and request.form.get("do") == "out":
            check_out(lg["id"])
        return redirect(url_for("scan_token", token=token))
    return render_template("scan_result", a=a, lg=lg, today=date.today().isoformat())

@app.route("/poster")
@need(*STAFF)
def poster():
    return render_template("poster", svg=qr_svg(request.host_url + "login"))

# ---------- admin ----------
@app.route("/admin/users", methods=["GET", "POST"])
@need("admin")
def users():
    u = current_user()
    if request.method == "POST":
        f = request.form
        if q("SELECT 1 FROM users WHERE email=?", (f["email"].lower(),), one=True):
            flash("That email is already registered.")
        elif f["role"] in ("staff", "admin") and len(f["password"]) >= 6:
            target_office = f.get("office")
            if not u["is_super"]:
                target_office = u["office"]
            run("INSERT INTO users(name,email,password,role,office,is_super) VALUES(?,?,?,?,?,0)",
                (f["name"], f["email"].lower(), generate_password_hash(f["password"]), f["role"], target_office))
            flash("Account added.")
        else:
            flash("Check the role and use a password of 6+ characters.")
            
    edit_id = request.args.get("edit", type=int)
    edit_user = q("SELECT * FROM users WHERE id=?", (edit_id,), one=True) if edit_id else None
    
    if u["is_super"]:
        rows = q("SELECT * FROM users WHERE role IN ('staff', 'admin') ORDER BY role, name")
    else:
        rows = q("SELECT * FROM users WHERE office=? AND role IN ('staff', 'admin') ORDER BY role, name", (u["office"],))
        
    return render_template("users", rows=rows, offices=OFFICES, edit_user=edit_user)

@app.route("/admin/users/edit/<int:uid>", methods=["POST"])
@need("admin")
def edit_user(uid):
    u = current_user()
    target = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not target:
        abort(404)
    if not u["is_super"] and target["office"] != u["office"]:
        flash("You can only edit accounts within your own office.")
        return redirect(url_for("users"))

    f = request.form
    new_pw = f.get("password", "").strip()
    target_office = f.get("office") if u["is_super"] else u["office"]
    is_super = 1 if u["is_super"] and f.get("is_super") else 0

    if new_pw:
        if len(new_pw) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(url_for("users"))
        run("UPDATE users SET name=?, email=?, password=?, role=?, office=?, is_super=? WHERE id=?",
            (f["name"], f["email"].lower(), generate_password_hash(new_pw), f["role"], target_office, is_super, uid))
    else:
        run("UPDATE users SET name=?, email=?, role=?, office=?, is_super=? WHERE id=?",
            (f["name"], f["email"].lower(), f["role"], target_office, is_super, uid))
    flash("Account updated successfully.")
    return redirect(url_for("users"))

@app.route("/admin/users/delete/<int:uid>", methods=["POST"])
@need("admin")
def delete_user(uid):
    u = current_user()
    target = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not target:
        abort(404)
    if target["id"] == u["id"]:
        flash("You cannot delete your own account.")
    elif target["is_super"]:
        flash("You cannot delete the President.")
    elif not u["is_super"] and target["office"] != u["office"]: 
        flash("You can only delete accounts within your own office.")
    else:
        run("DELETE FROM users WHERE id=?", (uid,))
        flash("Account deleted.")
    return redirect(url_for("users"))

# ---------- templates ----------
BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>VisiTrack</title><link rel="icon" href="/static/logo.png">
<style>
:root{--ink:#16231f;--mute:#5d6b66;--bg:#eef2f0;--card:#fff;--line:#d9e1dd;--pri:#0f4c3a;--gold:#c9a227;--bad:#b3392b}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink)}
nav{position:sticky;top:0;z-index:5;background:var(--pri);color:#fff;display:flex;gap:18px;align-items:center;padding:12px 22px;flex-wrap:wrap;border-bottom:4px solid var(--gold)}
nav a{color:#fff;text-decoration:none}nav a:hover{text-decoration:underline}
nav .brand{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:700;margin-right:auto;letter-spacing:.3px}
nav .brand img{width:46px;height:46px;border-radius:50%;background:#fff;padding:2px;box-shadow:0 2px 6px rgba(0,0,0,.35)}
.logo-big{display:block;margin:0 auto 12px;width:140px;height:140px;border-radius:50%}
.logo-big+h1{text-align:center}
main{max-width:1040px;margin:24px auto;padding:0 16px}
h1{font-size:24px;margin:0 0 14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:18px;margin-bottom:16px;box-shadow:0 4px 14px rgba(15,76,58,.15)}
.card.narrow{box-shadow:0 10px 30px rgba(15,76,58,.22)}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:16px}
.stat{flex:1;min-width:150px;background:var(--card);border:1px solid var(--line);border-left:5px solid var(--gold);border-radius:8px;padding:12px 16px}
.stat b{font-size:28px;display:block}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:middle}
th{color:var(--mute);font-weight:600}
label{font-weight:600;font-size:14px}
input,select,textarea{width:100%;padding:9px;border:1px solid var(--line);border-radius:6px;margin:4px 0 12px;font:inherit;background:#fff}
input:focus,select:focus,textarea:focus,button:focus-visible,a:focus-visible{outline:3px solid var(--gold);outline-offset:1px}
button,.btn{background:var(--pri);color:#fff;border:0;padding:7px 14px;border-radius:6px;cursor:pointer;text-decoration:none;font:inherit;font-size:14px;display:inline-block;box-shadow:0 3px 8px rgba(0,0,0,.28);transition:transform .12s,box-shadow .12s}
button:hover,.btn:hover{transform:translateY(-1px);box-shadow:0 6px 12px rgba(0,0,0,.3)}
button:active,.btn:active{transform:translateY(1px);box-shadow:0 1px 3px rgba(0,0,0,.3)}
.btn.alt{background:#fff;color:var(--pri);border:1px solid var(--pri)}
button.bad{background:var(--bad)}
.tag{padding:2px 10px;border-radius:99px;font-size:12px;background:#e3ece8;color:var(--pri)}
.tag.pending{background:#fbf0c8;color:#7a5d00}.tag.declined,.tag.cancelled{background:#f5dcd8;color:var(--bad)}
.flash{background:#fff7d6;border:1px solid #e4cf74;padding:10px 14px;border-radius:6px;margin-bottom:14px}
.remind{background:#e3f1ea;border:1px solid #a9d1bd;padding:10px 14px;border-radius:6px;margin-bottom:12px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}.row>*{flex:1;min-width:140px}
form.inline{display:inline}.narrow{max-width:440px;margin:0 auto}.mute{color:var(--mute)}
.qr{width:260px;max-width:100%;margin:0 auto 12px;padding:10px;background:#fff;border:1px solid var(--line);border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.15)}
.qr svg{width:100%;height:auto;display:block}
.shell{display:flex;max-width:1320px;margin:0 auto}
.side{width:250px;flex:none;position:sticky;top:74px;align-self:flex-start;height:calc(100vh - 74px);overflow-y:auto;background:#fff;border-right:1px solid var(--line);padding:20px 14px;display:flex;flex-direction:column;gap:4px}
.me{display:flex;align-items:center;gap:12px;padding:0 6px 16px;margin-bottom:10px;border-bottom:1px solid var(--line)}
.me i{font-style:normal;width:42px;height:42px;flex:none;border-radius:50%;background:var(--pri);color:#fff;display:grid;place-items:center;font-weight:700;box-shadow:0 2px 6px rgba(0,0,0,.25)}
.me b{display:block;line-height:1.25}
.side a{color:var(--ink);text-decoration:none;padding:9px 12px;border-radius:6px;border-left:4px solid transparent}
.side a:hover{background:#eef2f0}
.side a.on{background:#e3ece8;border-left-color:var(--gold);font-weight:600;color:var(--pri)}
.side .out{margin-top:auto;border-top:1px solid var(--line);border-radius:0 0 6px 6px;padding-top:14px}
.shell main{flex:1;min-width:0;margin:24px 0;padding:0 24px}
@media(max-width:820px){.shell{flex-direction:column}.side{position:static;width:100%;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;border-right:0;border-bottom:1px solid var(--line);padding:12px}
.me{border:0;margin:0 auto 0 0;padding:0}.side .out{margin-top:0;border:0;padding-top:9px}.shell main{padding:0 14px}}
@media print{nav,.side,.noprint{display:none}body{background:#fff}.card{box-shadow:none;border:0}}
</style></head><body>
<nav><a class="brand" href="/"><img src="/static/logo.png" alt="VisiTrack logo"><span>VisiTrack</span></a>
{% if not user %}<a href="/login">Log in</a><a href="/register">Create account</a>{% endif %}</nav>
<div class="{{ 'shell' if user }}">
{% if user %}
  {% if user.role == 'visitor' %}
    {% set links = [('/my','My appointments'), ('/book','Book a visit')] %}
  {% else %}
    {% set links = [('/staff','Appointments'), ('/log','E-log sheet'), ('/scan','Scan QR')] %}
    {% if user.role == 'admin' %}
      {% set links = links + [('/admin/users','Accounts')] %}
    {% endif %}
  {% endif %}
  
  <aside class="side"><div class="me"><i>{{ user.name[:1]|upper }}</i><div><b>{{ user.name }}</b><span class="mute">{{ user.role }}</span></div></div>
  {% for href,label in links %}<a href="{{ href }}" class="{{ 'on' if request.path==href or request.path.startswith(href+'/') }}">{{ label }}</a>{% endfor %}
  <a class="out" href="/logout">Log out</a></aside>
{% endif %}
<main>
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}
</main></div></body></html>"""

LOGIN = """{% extends 'base' %}{% block body %}<div class="card narrow"><img class="logo-big" src="/static/logo.png" alt="VisiTrack logo"><h1>Login</h1>
<form method="post">
  <label>Email</label><input name="email" type="email" required>
  
  <label>Password</label>
  <input name="password" type="password" required>
  
  <div style="text-align:right; margin-top:-8px; margin-bottom:16px;">
    <a href="/forgot" style="font-size:13px; color:var(--mute); text-decoration:none;">Forgot password?</a>
  </div>
  
  <div style="text-align:center;">
    <button style="padding: 12px 24px; font-size: 16px; width: 40%;">Login</button>
  </div>
</form>
<p class="mute" style="text-align:center; margin-top:24px;">New visitor? <a href="/register">Create an account</a></p></div>{% endblock %}"""

REGISTER = """{% extends 'base' %}{% block body %}<div class="card narrow"><img class="logo-big" src="/static/logo.png" alt="VisiTrack logo"><h1>Create a visitor account</h1>
<form method="post"><label>Full name</label><input name="name" required>
<label>Email</label><input name="email" type="email" required>
<label>Contact number</label><input name="contact">
<label>Password (6+ characters)</label><input name="password" type="password" required>
<button>Create account</button></form></div>{% endblock %}"""

BOOK = """{% extends 'base' %}{% block body %}<div class="card narrow">
<h1>{{ 'Reschedule appointment' if a else 'Book a visit' }}</h1>
<form method="post">
{% if a %}<input type="hidden" id="office" value="{{ a.office }}"><p>Office: <b>{{ a.office }}</b></p>
{% else %}<label>Office</label><select id="office" name="office">{% for o in offices %}<option>{{ o }}</option>{% endfor %}</select>{% endif %}

<label>Date</label><input type="date" id="date" name="date" min="{{ today }}" value="{{ a.date if a else '' }}" required>

<label>Time (Select AM or PM)</label>
<input type="time" id="time" name="slot" value="{{ a.slot if a else '08:00' }}" required style="width:100%; padding:10px; font-size:16px;">

{% if not a %}<label>Purpose of visit</label><textarea name="purpose" rows="3" required></textarea>{% endif %}
<div style="text-align:center; margin-top:16px;">
  <button>{{ 'Save new time' if a else 'Request appointment' }}</button> 
  <a class="btn alt" href="/my">Back</a>
</div>
</form></div>{% endblock %}"""

MY = """{% extends 'base' %}{% block body %}<h1>My appointments</h1>
{% for r,when in reminders %}<div class="remind">Reminder: your visit to {{ r.office }} is {{ when }} at {{ r.slot|to12 }}.</div>{% endfor %}
<div class="card scroll">{% if rows %}<table><tr><th>Date</th><th>Time</th><th>Office</th><th>Purpose</th><th>Status</th><th>Countdown</th><th>Actions</th></tr>
{% for r in rows %}<tr><td>{{ r.date }}</td><td>{{ r.slot|to12 }}</td><td>{{ r.office }}</td><td>{{ r.purpose }}</td>
<td><span class="tag {{ r.status }}">{{ r.status }}</span></td>
<td>{% if r.status in ('approved','pending') and r.date == today %}<span class="countdown" data-when="{{ r.date }}T{{ r.slot }}:00"></span>{% endif %}</td>
<td>
  <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
    {% if r.status in ('approved','checked-in') %}<a class="btn" href="/pass/{{ r.id }}" style="width: 100px; text-align:center; padding: 6px 0;">Show QR</a>{% endif %}
    {% if r.status in ('pending','approved') %}
      <a class="btn alt" href="/reschedule/{{ r.id }}" style="width: 100px; text-align:center; padding: 6px 0;">Reschedule</a>
      <form class="inline" method="post" action="/cancel/{{ r.id }}" style="margin:0;">
        <button class="bad" style="width: 100px; padding: 6px 0;">Cancel</button>
      </form>
    {% endif %}
  </div>
</td></tr>{% endfor %}</table>
{% else %}<p>No appointments yet. <a href="/book">Book your first visit</a>.</p>{% endif %}</div>

<script>
const fmt = s => {
  const h = Math.floor(s/3600), m = Math.floor(s%3600/60), sec = s%60;
  return (h? h+"h ":"") + m + "m " + String(sec).padStart(2,"0") + "s";
};
function tick(){
  document.querySelectorAll(".countdown").forEach(el=>{
    const t = new Date(el.dataset.when).getTime();
    const left = Math.floor((t - Date.now())/1000);
    if (left <= 0){ el.textContent = "Starting now / passed"; el.style.color = "#b3392b"; return; }
    el.textContent = "in " + fmt(left);
    el.style.fontWeight = "600";
    if (left <= 600){ el.style.color = "#b3392b"; el.dataset.warn = "1"; }
  });
  const any = [...document.querySelectorAll(".countdown")].some(e=>e.dataset.warn==="1" && !e.dataset.shown);
  if (any){
    [...document.querySelectorAll(".countdown")].forEach(e=>e.dataset.shown="1");
    const b = document.createElement("div");
    b.className = "remind";
    b.style.background = "#fde2dc"; b.style.borderColor = "#e8a99e";
    b.textContent = "⏰ Reminder: an appointment is starting within 10 minutes!";
    document.querySelector("main").prepend(b);
  }
}
tick(); setInterval(tick, 1000);
</script>
{% endblock %}"""

STAFF_T = """{% extends 'base' %}{% block body %}<h1>Appointments</h1>
<div class="stats"><div class="stat"><b>{{ stats.today }}</b>Visits today</div>
<div class="stat"><b>{{ stats.pending }}</b>Awaiting approval</div>
<div class="stat"><b>{{ stats.inside }}</b>Inside now</div></div>

<form class="card row" method="get" style="display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap;">
  <div style="flex:1; min-width:140px;">
    <label>Status</label>
    <select name="status">
      <option value="">All</option>
      {% for s in ['pending','approved','checked-in','completed','declined','cancelled'] %}
      <option {{ 'selected' if f.status==s }}>{{ s }}</option>
      {% endfor %}
    </select>
  </div>
  <div style="flex:1; min-width:140px;">
    <label>Date</label>
    <input type="date" name="date" value="{{ f.date }}">
  </div>
  <div style="flex:1; min-width:140px;">
    <label>Office</label>
    <select name="office">
      <option value="">All</option>
      {% for o in offices %}
      <option {{ 'selected' if f.office==o }}>{{ o }}</option>
      {% endfor %}
    </select>
  </div>
  <div style="display:flex; gap:8px; margin-bottom: 12px;">
    <button style="padding: 9px 16px; margin: 0; height: 40px;">Filter</button> 
    <a class="btn alt" href="/staff" style="padding: 9px 16px; margin: 0; height: 40px; display:flex; align-items:center; justify-content:center;">Clear</a>
  </div>
</form>

<div class="card scroll">
  <table>
    <tr><th>Date</th><th>Time</th><th>Visitor</th><th>Office</th><th>Purpose</th><th>Status</th><th>Actions</th></tr>
    {% for r in rows %}
    <tr>
      <td>{{ r.date }}</td>
      <td>{{ r.slot|to12 }}</td>
      <td>{{ r.visitor }}<br><span class="mute">{{ r.contact or '' }}</span></td>
      <td>{{ r.office }}</td>
      <td>{{ r.purpose }}</td>
      <td><span class="tag {{ r.status }}">{{ r.status }}</span></td>
      <td>
        <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
          {% if r.status=='pending' %}
            <form class="inline" method="post" action="/appointment/{{ r.id }}/approve" style="margin:0;"><button style="padding: 6px 12px;">Approve</button></form>
          {% endif %}
          {% if r.status=='approved' %}
            <form class="inline" method="post" action="/appointment/{{ r.id }}/checkin" style="margin:0;"><button style="padding: 6px 12px;">Check in</button></form>
          {% endif %}
          {% if r.status in ('pending','approved') %}
            <form class="inline" method="post" action="/appointment/{{ r.id }}/decline" style="margin:0;"><button class="bad" style="padding: 6px 12px;">Decline</button></form>
          {% endif %}
        </div>
      </td>
    </tr>
    {% else %}
    <tr><td colspan="7">No appointments match these filters.</td></tr>
    {% endfor %}
  </table>
</div>
{% endblock %}"""

LOG = """{% extends 'base' %}{% block body %}<h1>E-log sheet</h1>
<form class="card row" method="get" style="display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap;">
  <div style="flex:2; min-width:150px;"><label>Search</label><input name="q" value="{{ f.get('q','') }}" placeholder="Name, office, purpose"></div>
  <div style="flex:1; min-width:130px;"><label>From</label><input type="date" name="from" value="{{ f.get('from','') }}"></div>
  <div style="flex:1; min-width:130px;"><label>To</label><input type="date" name="to" value="{{ f.get('to','') }}"></div>
  <div style="flex:1; min-width:100px;"><label style="display:flex; align-items:center; gap:8px; height:40px;"><input type="checkbox" name="inside" value="1" style="width:auto; margin:0;" {{ 'checked' if f.get('inside') }}> Inside</label></div>
  <div style="display:flex; gap:8px; margin-bottom: 12px;">
    <button style="padding: 9px 16px; margin: 0; height: 40px;">Search</button> 
    <a class="btn alt" href="/log" style="padding: 9px 16px; margin: 0; height: 40px; display:flex; align-items:center; justify-content:center;">Clear</a>
  </div>
</form>
<p><a class="btn" href="/log/new">Log a walk-in</a> <a class="btn alt" href="/log/export.csv?{{ request.query_string.decode() }}">Download CSV</a></p>
<div class="card scroll"><table><tr><th>Visitor</th><th>Office</th><th>Purpose</th><th>Time in</th><th>Time out</th><th>Stay</th><th></th></tr>
{% for r in rows %}<tr><td>{{ r.visitor_name }}<br><span class="mute">{{ r.contact or '' }}</span></td><td>{{ r.office }}</td><td>{{ r.purpose }}</td>
<td>{{ r.time_in }}</td><td>{{ r.time_out or '' }}</td><td>{{ (r.duration ~ ' (' ~ r.minutes ~ ' min)') if r.duration else '' }}</td>
<td>{% if not r.time_out %}<form class="inline" method="post" action="/log/{{ r.id }}/out"><button>Check out</button></form>{% endif %}</td></tr>
{% else %}<tr><td colspan="7">No log entries found.</td></tr>{% endfor %}</table></div>{% endblock %}"""

LOG_NEW = """{% extends 'base' %}{% block body %}<div class="card narrow"><h1>Log a walk-in</h1><form method="post">
<label>Visitor name</label><input name="name" required><label>Contact number</label><input name="contact">
<label>Office</label><select name="office">{% for o in offices %}<option>{{ o }}</option>{% endfor %}</select>
<label>Purpose</label><input name="purpose"><button>Save entry</button> <a class="btn alt" href="/log">Back</a></form></div>{% endblock %}"""

USERS = """{% extends 'base' %}{% block body %}<h1>Accounts Management</h1>

<form class="card" method="post" action="{{ '/admin/users/edit/' ~ edit_user.id if edit_user else '/admin/users' }}" style="display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end;">
  {% if edit_user %}<h2 style="width:100%; margin-top:0; color:var(--pri);">Edit Account: {{ edit_user.name }}</h2>{% endif %}
  
  <div style="flex:1; min-width:150px;"><label>Name</label><input name="name" value="{{ edit_user.name if edit_user else '' }}" required></div>
  <div style="flex:1; min-width:150px;"><label>Email</label><input name="email" type="email" value="{{ edit_user.email if edit_user else '' }}" required></div>
  <div style="flex:1; min-width:150px;"><label>Password {% if edit_user %}(Leave blank to keep){% endif %}</label><input name="password" type="password" {% if not edit_user %}required{% endif %}></div>
  
  <div style="flex:1; min-width:100px;"><label>Role</label>
    <select name="role">
      <option {{ 'selected' if edit_user and edit_user.role == 'staff' }}>staff</option>
      <option {{ 'selected' if edit_user and edit_user.role == 'admin' }}>admin</option>
    </select>
  </div>

  {% if user.is_super %}
  <div style="flex:1; min-width:150px;"><label>Assigned Office</label>
    <select name="office">
      <option value="">None (All)</option>
      {% for o in offices %}
      <option {{ 'selected' if edit_user and edit_user.office == o }}>{{ o }}</option>
      {% endfor %}
    </select>
  </div>
  <div style="flex:1; min-width:100px; margin-bottom:12px;">
    <label style="display:flex; align-items:center; gap:8px; font-weight:normal;">
      <input type="checkbox" name="is_super" value="1" style="width:auto; margin:0;" {{ 'checked' if edit_user and edit_user.is_super }}> President
    </label>
  </div>
  {% else %}
  <input type="hidden" name="office" value="{{ user.office }}">
  <p style="flex:1; min-width:150px; margin-bottom:16px; color:var(--mute);">Office: <b>{{ user.office }}</b></p>
  {% endif %}
  
  <div style="display:flex; gap:8px; margin-bottom:12px;">
    <div style="display:flex; flex-direction:column; gap:4px;">
      <label style="visibility:hidden; font-size:14px; margin-bottom:4px;">Spacer</label>
      <button style="padding: 9px 16px; height: 40px;">{{ 'Save Changes' if edit_user else 'Add account' }}</button>
    </div>
    {% if edit_user %}
      <div style="display:flex; flex-direction:column; gap:4px;">
        <label style="visibility:hidden; font-size:14px; margin-bottom:4px;">Spacer</label>
        <a class="btn alt" href="/admin/users" style="padding: 9px 16px; height: 40px; display:flex; align-items:center; justify-content:center;">Cancel</a>
      </div>
    {% endif %}
  </div>
</form>

<div class="card scroll">
  <table>
    <tr><th>Name</th><th>Email</th><th>Role</th><th>Assigned Office</th><th>Actions</th></tr>
    {% for r in rows %}
    <tr>
      <td>{{ r.name }} {% if r.is_super %}<span class="tag" style="background:#c9a227; color:#fff;">President</span>{% endif %}</td>
      <td>{{ r.email }}</td><td>{{ r.role }}</td><td>{{ r.office or 'All' }}</td>
      <td>
        <div style="display:flex; gap:8px;">
          <a class="btn alt" href="/admin/users?edit={{ r.id }}" style="padding: 6px 12px;">Edit</a>
          {% if r.id != session.uid and not r.is_super %}
          <form method="post" action="/admin/users/delete/{{ r.id }}" style="margin:0;" onsubmit="return confirm('Are you sure you want to delete this account?');">
            <button class="bad" style="padding: 6px 12px;">Delete</button>
          </form>
          {% endif %}
        </div>
      </td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endblock %}"""

PASS = """{% extends 'base' %}{% block body %}<div class="card narrow" style="text-align:center">
<h1>Your visit pass</h1><div class="qr">{{ svg|safe }}</div>
<p><b>{{ a.office }}</b><br>{{ a.date }} at {{ a.slot|to12 }}</p>
<p class="mute">Show this QR to the staff when you arrive and again when you leave.<br>Code: {{ a.token }}</p>
<a class="btn alt" href="/my">Back</a></div>{% endblock %}"""

SCAN = """{% extends 'base' %}{% block body %}<div class="card narrow"><h1>Scan a visitor pass</h1>
<p class="mute">Scan the QR with your phone camera, or use a USB scanner or type the code below.</p>
<form method="post"><label>Pass code</label><input name="code" autofocus autocomplete="off" required>
<button>Open pass</button></form><p><a href="/poster">Print the entrance poster</a></p></div>{% endblock %}"""

SCAN_RESULT = """{% extends 'base' %}{% block body %}<div class="card narrow"><h1>{{ a.name }}</h1>
<p>{{ a.office }}<br>{{ a.date }} at {{ a.slot|to12 }}<br>{{ a.purpose }}</p>
<p>Status: <span class="tag {{ a.status }}">{{ a.status }}</span></p>

<div style="margin-top:20px;">
{% if a.status=='approved' %}
  {% if a.date != today %}<div class="flash">This appointment is for {{ a.date }}, not today.</div>{% endif %}
  <form method="post" style="margin:0;">
    <input type="hidden" name="do" value="in">
    <button style="padding: 12px 24px; font-size: 16px; width:100%; background:#0f4c3a; color:#fff;">Check IN (Log in)</button>
  </form>
  
{% elif a.status=='checked-in' and lg and not lg.time_out %}
  <p style="font-weight:bold; color:#0f4c3a;">Inside since: {{ lg.time_in }}</p>
  <form method="post" style="margin:0;">
    <input type="hidden" name="do" value="out">
    <button style="padding: 12px 24px; font-size: 16px; width:100%; background:#b3392b; color:#fff;">Check OUT (Log out)</button>
  </form>

{% elif a.status=='completed' %}
  <p style="font-size:16px;">This visit is complete. Time out: {{ lg.time_out }}.</p>
  
{% else %}
  <p>This pass can't be used for entry. The appointment is {{ a.status }}.</p>
{% endif %}
</div>

<p style="text-align:center; margin-top:20px;"><a class="btn alt" href="/scan">Scan another</a></p>
</div>{% endblock %}"""

POSTER = """{% extends 'base' %}{% block body %}<div class="card narrow" style="text-align:center">
<img class="logo-big" src="/static/logo.png" alt="VisiTrack logo"><h1>Scan to book your visit</h1>
<div class="qr">{{ svg|safe }}</div><p>Skip the line. Book a time, then show your QR pass at the door.</p>
<button class="noprint" onclick="window.print()">Print poster</button></div>{% endblock %}"""

FORGOT = """{% extends 'base' %}{% block body %}<div class="card narrow"><h1>Forgot password</h1>
<form method="post"><label>Email</label><input name="email" type="email" required>
<button>Generate reset link</button></form>
<p class="mute"><a href="/login">Back to login</a></p></div>{% endblock %}"""

RESET = """{% extends 'base' %}{% block body %}<div class="card narrow"><h1>Choose a new password</h1>
<form method="post"><label>New password (6+ characters)</label>
<input name="password" type="password" required><button>Save password</button></form></div>{% endblock %}"""

app.jinja_env.loader = DictLoader({
    "base": BASE, "login": LOGIN, "register": REGISTER, "book": BOOK,
    "my": MY, "staff": STAFF_T, "log": LOG, "log_new": LOG_NEW, "users": USERS,
    "pass": PASS, "scan": SCAN, "scan_result": SCAN_RESULT, "poster": POSTER,
    "forgot": FORGOT, "reset": RESET
})

_orig = render_template
def render_template(name, **ctx):  # templates live in this file, not in /templates
    return app.jinja_env.get_template(name).render(**ctx, **_ctx())
def _ctx():
    from flask import get_flashed_messages, request as rq
    return {"get_flashed_messages": get_flashed_messages, "request": rq, "user": current_user()}

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)