import json, os, threading, time, collections, random, uuid, urllib.request, urllib.parse, urllib.error, smtplib, secrets
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, make_response
import logging
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from email.message import EmailMessage
from instagrapi import Client
from instagrapi.exceptions import LoginRequired, RateLimitError
from igrapiweb import make_ig_web_socket
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken

load_dotenv()

DATA_ENCRYPTION_KEY = os.environ.get("DATA_ENCRYPTION_KEY", "").strip()
if not DATA_ENCRYPTION_KEY:
    raise RuntimeError("DATA_ENCRYPTION_KEY must be set. Generate it with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
try:
    _DATA_FERNET = Fernet(DATA_ENCRYPTION_KEY.encode())
except Exception as exc:
    raise RuntimeError("DATA_ENCRYPTION_KEY is not a valid Fernet key") from exc
                                                                                             
BREVO_API_KEY = os.getenv("BREVO_API_KEY", "").strip()
BREVO_SENDER_EMAIL = os.getenv("BREVO_SENDER_EMAIL", "").strip()
BREVO_SENDER_NAME = os.getenv("BREVO_SENDER_NAME", "DAKSH SX7").strip()

def send_otp_email(to_email, username, otp):
    if not BREVO_API_KEY:
        raise RuntimeError("BREVO_API_KEY is not configured.")
    if not BREVO_SENDER_EMAIL:
        raise RuntimeError("BREVO_SENDER_EMAIL is not configured.")

    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": to_email, "name": username}],
        "subject": "DAKSH SX7 • Registration OTP",
        "textContent": (
            f"Hello {username},\n\n"
            f"Your DAKSH SX7 registration OTP is: {otp}\n\n"
            f"This OTP expires in {OTP_EXPIRY_SECONDS // 60} minutes.\n"
            "If you did not request this, you can ignore this email.\n\n"
            "DAKSH SX7"
        ),
        "htmlContent": f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px">
          <h2>DAKSH SX7</h2>
          <p>Hello {username},</p>
          <p>Your registration OTP is:</p>
          <div style="font-size:32px;font-weight:700;letter-spacing:8px;
                      margin:20px 0;padding:16px;border:1px solid #ddd;
                      border-radius:10px;text-align:center">{otp}</div>
          <p>This code expires in {OTP_EXPIRY_SECONDS // 60} minutes.</p>
          <p>If you did not request this, you can ignore this email.</p>
        </div>
        """
    }

    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "accept": "application/json",
            "api-key": BREVO_API_KEY,
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            if not 200 <= response.status < 300:
                raise RuntimeError(
                    f"Brevo email error (HTTP {response.status}): {body}"
                )
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Brevo email error (HTTP {e.code}): {detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Brevo connection error: {e.reason}") from e


app = Flask(__name__)

# Render (and other reverse-proxy deployments) terminates HTTPS before forwarding
# the request to Flask. Trust the standard single-proxy forwarding headers so
# request.host_url reflects the public HTTPS URL used by the browser.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Security configuration: all secrets must be supplied through environment variables.
PANEL_SECRET_KEY = os.environ.get("PANEL_SECRET_KEY", "").strip()
PANEL_USERNAME = os.environ.get("PANEL_USERNAME", "DAKSH").strip()
PANEL_PASSWORD_HASH = os.environ.get("PANEL_PASSWORD_HASH", "").strip()
if not PANEL_SECRET_KEY or len(PANEL_SECRET_KEY) < 32:
    raise RuntimeError("PANEL_SECRET_KEY must be set to a random value of at least 32 characters.")
if not PANEL_PASSWORD_HASH:
    raise RuntimeError("PANEL_PASSWORD_HASH must be set. Generate it with werkzeug.security.generate_password_hash().")
app.secret_key = PANEL_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1").lower() not in ("0", "false", "no"),
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024)),
)

# Small in-memory rate limiter. For multi-instance deployments, put the same logic
# behind a shared reverse proxy/Redis rate limiter.
_rate_lock = threading.Lock()
_rate_buckets = {}
def _rate_limit(key, limit, window):
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets.setdefault(key, [])
        bucket[:] = [t for t in bucket if now - t < window]
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") or request.path in ("/login", "/") else response.headers.get("Cache-Control", "no-cache")
    return response

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if request.path == "/login" and request.method == "POST":
        if not _rate_limit(f"login:{ip}", 10, 300):
            return render_login("Too many login attempts. Try again later."), 429
    if request.path == "/register/request-otp" and request.method == "POST":
        if not _rate_limit(f"otp:{ip}", 5, 900):
            return jsonify({"success": False, "error": "Too many OTP requests. Try again later."}), 429
    if request.path == "/register/verify-otp" and request.method == "POST":
        if not _rate_limit(f"otpverify:{ip}", 10, 900):
            return jsonify({"success": False, "error": "Too many OTP attempts. Try again later."}), 429

                                 
                                                
                                                                           
OTP_EXPIRY_SECONDS = int(os.environ.get("OTP_EXPIRY_SECONDS", "600"))
OTP_RESEND_SECONDS = int(os.environ.get("OTP_RESEND_SECONDS", "60"))
otp_lock = threading.Lock()
pending_registrations = {}

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("panel_logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Login required"}), 401
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("panel_logged_in") or session.get("login_role") != "admin":
            return jsonify({"success": False, "error": "Admin access required"}), 403
        return view(*args, **kwargs)
    return wrapped


LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>DAKSH SX7 • Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Orbitron:wght@500;600;700;800;900&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:100%;min-height:100%;overflow-x:hidden;overflow-y:auto;scroll-behavior:smooth;background:#000;color:#fff;font-family:Inter,Arial,sans-serif}
body{scroll-snap-type:y proximity}
.page{width:100%;min-height:200vh;position:relative;background:#000}
.hero{min-height:100vh;height:100vh;position:relative;display:flex;align-items:center;justify-content:center;overflow:hidden;background:#000;scroll-snap-align:start}
#shader-canvas{position:absolute;inset:0;width:100%;height:100%;display:block;background:#000}
.shader-overlay{position:absolute;inset:0;z-index:1;pointer-events:none;background:radial-gradient(circle at center,transparent 0%,rgba(0,0,0,.12) 48%,rgba(0,0,0,.72) 100%),linear-gradient(180deg,rgba(0,0,0,.05),rgba(0,0,0,.45))}
.welcome-content{position:relative;z-index:5;width:min(1100px,92vw);text-align:center;display:flex;flex-direction:column;align-items:center;pointer-events:none;transform:translateY(-2vh)}
.welcome-kicker{font-family:'Orbitron',sans-serif;font-size:clamp(9px,1.3vw,13px);letter-spacing:6px;color:rgba(255,255,255,.64);margin-bottom:24px;text-shadow:0 0 18px rgba(255,255,255,.45)}
.welcome-content h1{font-family:'Orbitron',sans-serif;font-size:clamp(34px,6vw,82px);line-height:1.08;font-weight:900;letter-spacing:2px;color:#fff;text-shadow:0 0 12px rgba(255,255,255,.75),0 0 35px rgba(255,255,255,.3),0 0 75px rgba(255,255,255,.12)}
.welcome-content h1 span{color:#d9d9d9}
.welcome-content p{margin-top:20px;font-family:'Orbitron',sans-serif;font-size:11px;letter-spacing:7px;color:rgba(255,255,255,.45)}
.scroll-down{position:absolute;z-index:8;bottom:28px;left:50%;transform:translateX(-50%);border:0;background:transparent;color:#fff;display:flex;flex-direction:column;align-items:center;gap:8px;cursor:pointer;font-family:'Orbitron',sans-serif;letter-spacing:4px;font-size:9px;opacity:.7;animation:scrollPulse 1.8s ease-in-out infinite}
.scroll-down b{font-family:Inter,sans-serif;font-size:22px;line-height:1;font-weight:300}
@keyframes scrollPulse{0%,100%{opacity:.45;transform:translateX(-50%) translateY(0)}50%{opacity:1;transform:translateX(-50%) translateY(7px)}}
.login-screen{min-height:100vh;position:relative;display:flex;align-items:center;justify-content:center;padding:70px 20px;background:#000;scroll-snap-align:start;overflow:hidden}
.login-screen:before{content:"";position:absolute;inset:0;pointer-events:none;background:radial-gradient(circle at 50% 35%,rgba(35,35,35,.16),transparent 38%),#000}
.login-wrap{position:relative;z-index:5;width:min(390px,88vw);display:flex;flex-direction:column;align-items:center}
.moon-login{width:min(430px,92vw);height:245px;position:relative;margin:0 auto 4px;display:flex;align-items:center;justify-content:center;z-index:6;pointer-events:auto;overflow:visible}
#moon-canvas{width:100%;height:100%;display:block}
.moon-glow{position:absolute;width:145px;height:145px;border-radius:50%;background:radial-gradient(circle,rgba(190,210,235,.12),transparent 68%);filter:blur(14px);pointer-events:none}
.logo{font-family:'Orbitron',sans-serif;font-size:clamp(34px,7vw,58px);font-weight:900;letter-spacing:-2px;line-height:1;color:#fff;text-align:center;text-shadow:0 0 10px rgba(255,255,255,.65),0 0 30px rgba(255,255,255,.22);margin-bottom:28px;user-select:none}
.logo span{color:#cfcfcf}
.auth-card{width:100%;padding:28px;border:1px solid rgba(255,255,255,.16);border-radius:22px;background:rgba(5,5,8,.42);box-shadow:0 25px 90px rgba(0,0,0,.75),inset 0 1px 0 rgba(255,255,255,.06);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px)}
.tabs{display:grid;grid-template-columns:repeat(3,1fr);gap:5px;padding:5px;margin-bottom:25px;border:1px solid rgba(255,255,255,.12);border-radius:13px;background:rgba(255,255,255,.035)}
.tab{border:0;background:transparent;color:rgba(255,255,255,.45);padding:11px 5px;border-radius:9px;cursor:pointer;font-size:11px;font-weight:800;letter-spacing:2px;transition:.2s}
.tab:hover{color:#fff}.tab.active{color:#fff;background:rgba(255,255,255,.11);text-shadow:0 0 12px rgba(255,255,255,.7)}
.form{display:none}.form.active{display:block}.field{margin-top:13px}
label{display:block;margin:0 0 8px 2px;color:rgba(255,255,255,.7);font-size:10px;text-transform:uppercase;letter-spacing:2px;font-weight:700}
input{width:100%;height:52px;padding:0 16px;border:1px solid rgba(255,255,255,.28);border-radius:10px;background:rgba(0,0,0,.38);color:#fff;outline:none;font-size:13px;box-shadow:inset 0 0 20px rgba(0,0,0,.18);transition:.2s}
input::placeholder{color:rgba(255,255,255,.28)}input:focus{border-color:rgba(255,255,255,.8);box-shadow:0 0 0 2px rgba(255,255,255,.08),0 0 25px rgba(255,255,255,.08)}
.action{width:100%;height:52px;margin-top:20px;border:1px solid rgba(255,255,255,.55);border-radius:10px;background:rgba(255,255,255,.08);color:#fff;font-weight:800;letter-spacing:2px;font-size:11px;cursor:pointer;transition:.2s;backdrop-filter:blur(5px)}
.action:hover{background:rgba(255,255,255,.17);border-color:#fff;box-shadow:0 0 28px rgba(255,255,255,.14);transform:translateY(-1px)}
.hint{text-align:center;color:rgba(255,255,255,.45);font-size:9px;margin-top:13px;line-height:1.5;letter-spacing:1px}
.error{min-height:18px;margin-top:13px;text-align:center;color:#ff8585;font-size:10px}
@media(max-width:600px){.welcome-content h1{font-size:clamp(30px,9vw,48px);letter-spacing:1px}.welcome-kicker{letter-spacing:3px}.welcome-content p{letter-spacing:4px}.moon-login{height:210px;margin-bottom:0}.login-wrap{width:min(340px,84vw)}.auth-card{padding:20px;border-radius:18px}.tabs{gap:3px}}


#atc-background{position:fixed;inset:0;width:100%;height:100%;z-index:0;display:block;background:#000;pointer-events:none}
#atc-glass-tint{position:fixed;inset:0;z-index:1;pointer-events:none;background:radial-gradient(circle at 50% 0%,rgba(255,255,255,.08),transparent 35%),linear-gradient(180deg,rgba(0,0,0,.12),rgba(0,0,0,.48))}
.shell{position:relative;z-index:2}
.sidebar,.topbar,.panel,.stat-card,.acc-card,.tg-card,.tg-bot,.mini-panel,.modal,.modal-overlay,.gc-picker,.form-section,.log-panel,.empty,.search,.btn,.system-pill,.acc-header,.stats-row,.gc-row,.info-row,.last-action,.tg-frame-wrap,.portal-card,.section,.contact{
background:linear-gradient(135deg,rgba(255,255,255,.105),rgba(255,255,255,.035))!important;
border:1px solid rgba(255,255,255,.16)!important;
box-shadow:0 20px 55px rgba(0,0,0,.30),inset 0 1px 0 rgba(255,255,255,.16),inset 0 -1px 0 rgba(255,255,255,.035)!important;
backdrop-filter:blur(12px) saturate(125%)!important;-webkit-backdrop-filter:blur(12px) saturate(125%)!important;
}
body{background:#000!important}
.sidebar{background:linear-gradient(180deg,rgba(10,10,14,.70),rgba(5,5,8,.42))!important}
.topbar{background:rgba(8,8,12,.40)!important}
.stat-card,.acc-card,.tg-card,.tg-bot,.mini-panel,.modal{border-radius:20px!important}
.acc-card:hover,.tg-bot:hover,.stat-card:hover{border-color:rgba(255,255,255,.30)!important;transform:translateY(-2px);box-shadow:0 25px 65px rgba(0,0,0,.38),inset 0 1px 0 rgba(255,255,255,.18)!important}
.acc-header{background:rgba(255,255,255,.045)!important}
input,textarea,select,.search{background:rgba(0,0,0,.28)!important;border-color:rgba(255,255,255,.17)!important;backdrop-filter:blur(16px)!important}
input:focus,textarea:focus,select:focus{border-color:rgba(255,255,255,.55)!important;box-shadow:0 0 0 3px rgba(255,255,255,.06),0 0 30px rgba(255,255,255,.05)!important}
.btn{background:rgba(255,255,255,.055)!important;color:#f5f5f5!important}
.btn:hover{background:rgba(255,255,255,.12)!important;border-color:rgba(255,255,255,.38)!important}
.btn-add,.btn-save{background:linear-gradient(135deg,rgba(255,255,255,.20),rgba(255,255,255,.07))!important;border-color:rgba(255,255,255,.42)!important}
.nav-item.active,.nav-item:hover{background:rgba(255,255,255,.10)!important;border-color:rgba(255,255,255,.20)!important}
.log-panel{background:rgba(0,0,0,.24)!important}
.modal-overlay{background:rgba(0,0,0,.58)!important}
</style>
</head>
<body>
<canvas id="atc-background" aria-hidden="true"></canvas><div id="atc-glass-tint" aria-hidden="true"></div>

<div class="page">
<section class="hero" id="welcome">
<canvas id="shader-canvas"></canvas>
<div class="shader-overlay"></div>
<div class="welcome-content">
<div class="welcome-kicker">✦ DOMINATE ✦</div>
<h1>WELCOME TO<br><span>DAKSH</span><br>PANEL</h1>
<p>INSTAGRAM</p>
</div>
<button class="scroll-down" type="button" onclick="document.getElementById('login').scrollIntoView({behavior:'smooth',block:'start'})"><span>SCROLL DOWN</span><b>↓</b></button>
</section>
<section class="login-screen" id="login">
<div class="login-wrap">
<div class="moon-login" aria-label="Interactive lunar display"><div class="moon-glow"></div><canvas id="moon-canvas"></canvas></div>
<div class="logo">DAKSH <span>SX7</span></div>
<div class="auth-card">
<div class="tabs">
<button class="tab active" onclick="showTab('user',this)">USER</button>
<button class="tab" onclick="showTab('register',this)">REGISTER</button>
<button class="tab" onclick="showTab('admin',this)">ADMIN</button>
</div>
<form class="form active" id="user" method="POST" action="/login">
<input type="hidden" name="mode" value="user"/>
<div class="field"><label>USER</label><input name="username" autocomplete="username" placeholder="Enter username" required autofocus></div>
<div class="field"><label>PASS</label><input type="password" name="password" autocomplete="current-password" placeholder="Enter password" required></div>
<button class="action">ENTER PANEL</button>
</form>
<form class="form" id="register" onsubmit="return false;">
 <div class="field"><label>USER</label><input id="reg-username" name="username" minlength="3" maxlength="32" placeholder="Choose username" autocomplete="username" required></div>
 <div class="field"><label>PASS</label><input id="reg-password" type="password" name="password" minlength="6" placeholder="Choose password" autocomplete="new-password" required></div>
 <div class="field"><label>EMAIL</label><input id="reg-email" type="email" name="email" placeholder="Your email address" autocomplete="email" required></div>
 <div class="field" id="otp-field" style="display:none"><label>EMAIL OTP</label><input id="reg-otp" name="otp" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" placeholder="Enter 6-digit OTP" autocomplete="one-time-code"></div>
 <button class="action" id="send-otp-btn" type="button" onclick="sendRegistrationOTP()">SEND OTP</button>
 <button class="action" id="verify-otp-btn" type="button" onclick="verifyRegistrationOTP()" style="display:none">VERIFY &amp; CREATE ACCOUNT</button>
 <div class="hint" id="register-hint">A 6-digit OTP will be sent to your email.</div><div class="hint">CONTACT TG : @ayansx1</div>
 </form>
<form class="form" id="admin" method="POST" action="/login">
<input type="hidden" name="mode" value="admin"/>
<div class="field"><label>USER</label><input name="username" autocomplete="username" placeholder="Admin username" required></div>
<div class="field"><label>PASS</label><input type="password" name="password" autocomplete="current-password" placeholder="Admin password" required></div>
<button class="action">ADMIN LOGIN</button><div class="hint">CONTACT TG : @ayansx1</div>
</form>
<div class="error">{{ error }}</div>
</div></div>
</section>
</div>
<script>
 function showTab(id,btn){
 document.querySelectorAll('.form').forEach(x=>x.classList.remove('active'));
 document.getElementById(id).classList.add('active');
 document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
 btn.classList.add('active');
 }
 async function sendRegistrationOTP(){
   const username=document.getElementById('reg-username').value.trim(), password=document.getElementById('reg-password').value, email=document.getElementById('reg-email').value.trim();
   const hint=document.getElementById('register-hint'), btn=document.getElementById('send-otp-btn');
   if(!username||!password||!email){hint.textContent='Username, password and email are required.';return;}
   btn.disabled=true;btn.textContent='SENDING OTP...';
   try{
     const r=await fetch('/register/request-otp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,email})});
     const data=await r.json();
     if(data.success){
       document.getElementById('otp-field').style.display='block';
       document.getElementById('verify-otp-btn').style.display='block';
       btn.style.display='none';hint.textContent='OTP sent. Check your email. It expires in 10 minutes.';
       document.getElementById('reg-otp').focus();
     }else{hint.textContent=data.error||'Could not send OTP.';btn.disabled=false;btn.textContent='SEND OTP';}
   }catch(e){hint.textContent='Network error. Please try again.';btn.disabled=false;btn.textContent='SEND OTP';}
 }
 async function verifyRegistrationOTP(){
   const otp=document.getElementById('reg-otp').value.trim(), hint=document.getElementById('register-hint'), btn=document.getElementById('verify-otp-btn');
   if(!/^\d{6}$/.test(otp)){hint.textContent='Enter the 6-digit OTP from your email.';return;}
   btn.disabled=true;btn.textContent='VERIFYING...';
   try{
     const r=await fetch('/register/verify-otp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({otp})});
     const data=await r.json();
     if(data.success){hint.textContent='Registration successful. You can now log in.';setTimeout(()=>{showTab('user',document.querySelector('.tab'));},700);}
     else{hint.textContent=data.error||'Invalid OTP.';btn.disabled=false;btn.textContent='VERIFY & CREATE ACCOUNT';}
   }catch(e){hint.textContent='Network error. Please try again.';btn.disabled=false;btn.textContent='VERIFY & CREATE ACCOUNT';}
 }
 </script>
<script>

(function(){
const canvas=document.getElementById('shader-canvas'); if(!canvas)return;
const gl=canvas.getContext('webgl2',{premultipliedAlpha:false,antialias:false}); if(!gl)return;
const vertSrc=`#version 300 es
precision highp float;
layout(location=0) in vec2 a_pos;
void main(){gl_Position=vec4(a_pos,0.0,1.0);}`;
const fragSrc=`#version 300 es
precision highp float;
out vec4 fragColor;
uniform vec2 iResolution;
uniform float iTime;
uniform sampler2D iChannel0;
vec4 O_color;
void mainImage(out vec4 O, vec2 I){
vec2 r=iResolution.xy,p=(I+I-r)/r.y*mat2(3.,4.,4.,-3.)/1e2;
vec4 S=vec4(0.0),C=vec4(1.,2.,3.,0.),W;
for(float t=iTime,T=.1*t+p.y,i=0.;i<28.;i+=1.){
S+=(cos(W=sin(i)*C)+1.)*exp(sin(i+i*T))/length(max(p,p/vec2(2.0,texture(iChannel0,p/exp(W.x)+vec2(i,t)/8.).r*40.)))/1e4;
p+=.02*cos(i*(C.xz+8.0+i)+T+T);
}
O=vec4(tanh((S*S).rgb),1.0);
}
void main(){vec4 O;mainImage(O,gl_FragCoord.xy);fragColor=O;}`;
function compile(type,src){const sh=gl.createShader(type);gl.shaderSource(sh,src);gl.compileShader(sh);if(!gl.getShaderParameter(sh,gl.COMPILE_STATUS))throw new Error(gl.getShaderInfoLog(sh)||'compile error');return sh}
const prog=gl.createProgram();gl.attachShader(prog,compile(gl.VERTEX_SHADER,vertSrc));gl.attachShader(prog,compile(gl.FRAGMENT_SHADER,fragSrc));gl.linkProgram(prog);if(!gl.getProgramParameter(prog,gl.LINK_STATUS))return;
gl.useProgram(prog);
const buf=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,buf);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]),gl.STATIC_DRAW);gl.enableVertexAttribArray(0);gl.vertexAttribPointer(0,2,gl.FLOAT,false,0,0);
const tw=256,th=256,data=new Uint8Array(tw*th*4);for(let i=0;i<data.length;i++)data[i]=Math.floor(Math.random()*256);
const tex=gl.createTexture();gl.activeTexture(gl.TEXTURE0);gl.bindTexture(gl.TEXTURE_2D,tex);gl.texImage2D(gl.TEXTURE_2D,0,gl.RGBA,tw,th,0,gl.RGBA,gl.UNSIGNED_BYTE,data);gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_S,gl.REPEAT);gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_WRAP_T,gl.REPEAT);gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MIN_FILTER,gl.LINEAR);gl.texParameteri(gl.TEXTURE_2D,gl.TEXTURE_MAG_FILTER,gl.LINEAR);
const uRes=gl.getUniformLocation(prog,'iResolution'),uTime=gl.getUniformLocation(prog,'iTime'),uTex=gl.getUniformLocation(prog,'iChannel0');gl.uniform1i(uTex,0);
function resize(){const dpr=Math.min(1.25,Math.max(1,devicePixelRatio||1)),w=Math.floor(canvas.clientWidth*dpr),h=Math.floor(canvas.clientHeight*dpr);if(canvas.width!==w||canvas.height!==h){canvas.width=w;canvas.height=h}gl.viewport(0,0,w,h);gl.uniform2f(uRes,w,h)}
addEventListener('resize',resize,{passive:true});resize();let raf=0,t0=performance.now();
let lastFrame=0;const frameInterval=1000/30;function draw(now=performance.now()){if(now-lastFrame>=frameInterval){lastFrame=now;gl.uniform1f(uTime,(now-t0)/1000);gl.drawArrays(gl.TRIANGLES,0,6)}raf=requestAnimationFrame(draw)}draw();
addEventListener('beforeunload',()=>cancelAnimationFrame(raf));
})();
</script>
<script>

(function(){
const canvas=document.getElementById('moon-canvas');if(!canvas||!window.THREE)return;
})();
</script>
{% if error %}<script>window.scrollTo({top:document.getElementById('login').offsetTop,behavior:'instant'});</script>{% endif %}

<script>

(function(){
const canvas=document.getElementById('atc-background');if(!canvas)return;
const gl=canvas.getContext('webgl2',{premultipliedAlpha:false,antialias:false});if(!gl)return;
const vertSrc=`#version 300 es
precision highp float;
layout(location=0) in vec2 a_pos;
void main(){gl_Position=vec4(a_pos,0.0,1.0);}`;
const fragSrc=`#version 300 es
precision highp float;
out vec4 fragColor;
uniform vec2 u_res;
uniform float u_time;
float tanh1(float x){float e=exp(2.0*x);return(e-1.0)/(e+1.0);}
vec4 tanh4(vec4 v){return vec4(tanh1(v.x),tanh1(v.y),tanh1(v.z),tanh1(v.w));}
void main(){
vec3 FC=vec3(gl_FragCoord.xy,0.0);vec3 r=vec3(u_res,max(u_res.x,u_res.y));float t=u_time;
vec4 o=vec4(0.0);vec3 p=vec3(0.0);vec3 v=vec3(1.0,2.0,6.0);float i=0.0,z=1.0,d=1.0,f=1.0;
for(;i++<28.0;o.rgb+=(cos((p.x+z+v)*0.1)+1.0)/d/f/z){
p=z*normalize(FC*2.0-r.xyy);
vec4 m=cos((p+sin(p)).y*0.4+vec4(0.0,33.0,11.0,0.0));
p.xz=mat2(m)*p.xz;p.x+=t/0.55;
z+=(d=length(cos(p/v)*v+v.zxx/7.0)/(f=2.0+d/exp(p.y*0.2)));
}
o=tanh4(0.2*o);o.a=1.0;fragColor=o;}`;
function compile(type,src){const sh=gl.createShader(type);gl.shaderSource(sh,src);gl.compileShader(sh);if(!gl.getShaderParameter(sh,gl.COMPILE_STATUS))throw new Error(gl.getShaderInfoLog(sh)||'compile error');return sh}
const prog=gl.createProgram();gl.attachShader(prog,compile(gl.VERTEX_SHADER,vertSrc));gl.attachShader(prog,compile(gl.FRAGMENT_SHADER,fragSrc));gl.linkProgram(prog);if(!gl.getProgramParameter(prog,gl.LINK_STATUS))return;
gl.useProgram(prog);
const buf=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,buf);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]),gl.STATIC_DRAW);gl.enableVertexAttribArray(0);gl.vertexAttribPointer(0,2,gl.FLOAT,false,0,0);
const uRes=gl.getUniformLocation(prog,'u_res'),uTime=gl.getUniformLocation(prog,'u_time');
function resize(){const dpr=Math.min(1.25,Math.max(1,devicePixelRatio||1)),w=Math.max(1,Math.floor(innerWidth*dpr)),h=Math.max(1,Math.floor(innerHeight*dpr));if(canvas.width!==w||canvas.height!==h){canvas.width=w;canvas.height=h}gl.viewport(0,0,w,h);gl.uniform2f(uRes,w,h)}
addEventListener('resize',resize,{passive:true});resize();let raf=0,t0=performance.now();
function draw(){if(document.hidden){raf=0;return}gl.uniform1f(uTime,(performance.now()-t0)/1000);gl.drawArrays(gl.TRIANGLES,0,6);raf=requestAnimationFrame(draw)}draw();
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!raf)draw()});
})();
</script>

<script>
window.addEventListener('load', function () {
    setTimeout(function () {
        window.scrollTo({
            top: 0,
            left: 0,
            behavior: 'instant'
        });
    }, 50);
});

if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual';
}
</script>

</body></html>"""



# ---------------------------------------------------------------------------
# Supabase persistence
# ---------------------------------------------------------------------------
# The application state is stored in Supabase instead of creating data/data.json.
# Expected table: app_state
# Columns: id (text), data (jsonb), updated_at (timestamptz, optional/default now())
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "").strip()
SUPABASE_TABLE = os.environ.get("SUPABASE_TABLE", "app_state").strip() or "app_state"
SUPABASE_ROW_ID = os.environ.get("SUPABASE_ROW_ID", "main").strip() or "main"

if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL must be set in the environment.")
if not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_KEY must be set in the environment.")

data_lock = threading.RLock()

def _supabase_request(method, path, payload=None):
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Prefer": "return=minimal, resolution=merge-duplicates",
    }
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read().decode("utf-8", errors="replace")
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Supabase error (HTTP {exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Supabase connection error: {exc.reason}") from exc


def _enc(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8") if not isinstance(value, str) else value.encode("utf-8")
    return "enc:" + _DATA_FERNET.encrypt(raw).decode("ascii")

def _dec(value):
    if not isinstance(value, str) or not value.startswith("enc:"):
        return value
    try:
        raw = _DATA_FERNET.decrypt(value[4:].encode("ascii"))
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return raw.decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Encrypted data cannot be decrypted. Check DATA_ENCRYPTION_KEY.") from exc

def _protect_data(d):
    out = json.loads(json.dumps(d))
    for item in out.get("accounts", {}).values():
        for key in ("session_id", "csrf_token"):
            if item.get(key) and not str(item[key]).startswith("enc:"):
                item[key] = _enc(str(item[key]))
        if item.get("session_settings") and not (isinstance(item["session_settings"], str) and item["session_settings"].startswith("enc:")):
            item["session_settings"] = _enc(item["session_settings"])
    for item in out.get("gc_creator_ids", {}).values():
        if item.get("session_id") and not str(item["session_id"]).startswith("enc:"):
            item["session_id"] = _enc(str(item["session_id"]))
        if item.get("session_settings") and not (isinstance(item["session_settings"], str) and item["session_settings"].startswith("enc:")):
            item["session_settings"] = _enc(item["session_settings"])
    return out

def _unprotect_data(d):
    for item in d.get("accounts", {}).values():
        for key in ("session_id", "csrf_token", "session_settings"):
            if key in item and item.get(key):
                item[key] = _dec(item[key])
    for item in d.get("gc_creator_ids", {}).values():
        for key in ("session_id", "session_settings"):
            if key in item and item.get(key):
                item[key] = _dec(item[key])
    return d

def load_data():
    """Load the single application-state row from Supabase."""
    protected = _supabase_request(
        "GET",
        f"{SUPABASE_TABLE}?id=eq.{urllib.parse.quote(SUPABASE_ROW_ID, safe='')}&select=data&limit=1",
    )
    if isinstance(protected, list) and protected:
        row_data = protected[0].get("data")
        if isinstance(row_data, dict):
            return _unprotect_data(row_data)
    return {"accounts": {}, "users": {}, "gc_creator_ids": {}}

def save_data(d):
    """Persist the complete application state to Supabase.

    Sensitive Instagram session fields are still Fernet-encrypted by
    _protect_data() before they leave the process. No local data file is
    created or modified.
    """
    protected = _protect_data(d)
    payload = {
        "id": SUPABASE_ROW_ID,
        "data": protected,
    }
    _supabase_request(
        "POST",
        f"{SUPABASE_TABLE}?on_conflict=id",
        payload,
    )


def current_owner():
    return session.get("login_username", "")


def can_access_account(acc_id, d=None):
    if session.get("login_role") == "admin":
        return True
    if d is None:
        d = load_data()
    acc = d.get("accounts", {}).get(acc_id)
    return bool(acc and acc.get("owner") == current_owner())


def visible_accounts(d):
    if session.get("login_role") == "admin":
        return d.get("accounts", {})
    owner = current_owner()
    return {
        acc_id: acc for acc_id, acc in d.get("accounts", {}).items()
        if acc.get("owner") == owner
    }

bot_threads = {}
bot_stop    = {}
bot_status  = {}
ig_clients  = {}
bot_logs    = {}

gc_creator_jobs = {}
gc_creator_lock = threading.Lock()

def gc_creator_worker(job_id, gc_id, group_count, usernames, remove_username, message_text):
    with gc_creator_lock:
        gc_creator_jobs[job_id] = {
            "running": True,
            "done": 0,
            "total": group_count,
            "logs": [],
            "error": "",
            "gc_id": gc_id
        }

    def add_gc_log(message):
        with gc_creator_lock:
            job = gc_creator_jobs.get(job_id)
            if job:
                job["logs"].append(f"[{time.strftime('%H:%M:%S')}] {message}")
                job["logs"] = job["logs"][-100:]

    cl = None

    try:
        with data_lock:
            d = load_data()
            acc = d.get("gc_creator_ids", {}).get(gc_id)
            if not acc:
                raise RuntimeError("GC Creator ID not found")

        session_id = acc.get("session_id", "").strip()
        if not session_id:
            raise RuntimeError("This GC Creator ID has no session ID")

        proxy = acc.get("proxy", "").strip() or None
        session_id = decode_session(session_id)

        cl = Client()
        if proxy:
            cl.set_proxy(proxy)
        cl.login_by_sessionid(session_id)

        try:
            user_ids = [
                cl.user_id_from_username(username)
                for username in usernames
            ]
            remove_user_id = cl.user_id_from_username(remove_username)
        except Exception as e:
            add_gc_log(f"❌ Username resolve failed → {e}")
            return

        add_gc_log(f"\n⚡ Creating {group_count} Gcs\n")

        for i in range(1, group_count + 1):
            try:
                add_gc_log(f"🌼 GC {i}/{group_count}")

                cl.direct_send(
                    message_text,
                    user_ids=user_ids
                )

                time.sleep(4)

                thread = cl.direct_threads(
                    amount=1
                )[0]

                thread_id = thread.id

                time.sleep(3)

                cl.private.post(
                    f"https://i.instagram.com/api/v1/direct_v2/"
                    f"threads/{thread_id}/remove_users/",
                    data={
                        "user_ids": f"[{remove_user_id}]"
                    }
                )

                add_gc_log(
                    f"💠Members Added : "
                    f"{', '.join(usernames)}"
                )

                add_gc_log(
                    f"🧃 Removed : "
                    f"{remove_username}\n"
                )

                with gc_creator_lock:
                    job = gc_creator_jobs.get(job_id)
                    if job:
                        job["done"] = i

                time.sleep(1)

            except LoginRequired:
                add_gc_log("🔐 Login expired, relogging...")

                try:
                    cl = Client()
                    if proxy:
                        cl.set_proxy(proxy)
                    cl.login_by_sessionid(decode_session(session_id))
                    user_ids = [
                        cl.user_id_from_username(username)
                        for username in usernames
                    ]
                    remove_user_id = cl.user_id_from_username(remove_username)
                except Exception:
                    add_gc_log("❌ Relogin failed")
                    return

            except RateLimitError:
                add_gc_log("⏳ Rate limited, cooling down...")
                time.sleep(2)

            except Exception as e:
                add_gc_log(f"❌ Error → {e}")
                time.sleep(2)

        add_gc_log("⚡ GCS DONE")

    except Exception as e:
        add_gc_log(f"❌ Error → {e}")
        with gc_creator_lock:
            if job_id in gc_creator_jobs:
                gc_creator_jobs[job_id]["error"] = str(e)

    finally:
        try:
            if cl:
                cl.logout()
        except Exception:
            pass

        with gc_creator_lock:
            if job_id in gc_creator_jobs:
                gc_creator_jobs[job_id]["running"] = False

def log(acc_id, msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    if acc_id not in bot_logs:
        bot_logs[acc_id] = collections.deque(maxlen=300)
    bot_logs[acc_id].append(line)

import urllib.parse
import urllib.request

def decode_session(session_id):
    if not session_id: return session_id
    try: return urllib.parse.unquote(session_id)
    except Exception: return session_id

def persist_client_settings(acc_id, cl):
    """Persist the full instagrapi client settings for this account.

    This keeps device identifiers, cookies and authorization state together
    instead of relying only on the browser sessionid.
    """
    try:
        settings = cl.get_settings()
        if not settings:
            return
        with data_lock:
            d = load_data()
            if acc_id in d.get("accounts", {}):
                d["accounts"][acc_id]["session_settings"] = settings
                save_data(d)
    except Exception:
        pass

def get_client(acc_id, session_id, proxy=None, csrf_token=None):
    if acc_id in ig_clients:
        return ig_clients[acc_id]

                                                               
    if 'fetch_temp' in ig_clients:
        cl = ig_clients.pop('fetch_temp')
        ig_clients[acc_id] = cl
        persist_client_settings(acc_id, cl)
        return cl

                                                                           
                                                                             
                                          
    saved_settings = None
    try:
        with data_lock:
            d = load_data()
            saved_settings = d.get("accounts", {}).get(acc_id, {}).get("session_settings")
    except Exception:
        saved_settings = None

    if saved_settings:
        try:
            cl = Client()
            cl.set_settings(saved_settings)
            if proxy:
                cl.set_proxy(proxy)
                                                         
            cl.account_info()
            ig_clients[acc_id] = cl
            return cl
        except Exception:
                                                                             
                                                                      
            pass

    cl = Client()
    if proxy:
        cl.set_proxy(proxy)
    session_id = decode_session(session_id)
    cl.login_by_sessionid(session_id)
    ig_clients[acc_id] = cl
    persist_client_settings(acc_id, cl)
    return cl

def persist_gc_client_settings(gc_id, cl):
    try:
        settings = cl.get_settings()
        if not settings:
            return
        with data_lock:
            d = load_data()
            if gc_id in d.get("gc_creator_ids", {}):
                d["gc_creator_ids"][gc_id]["session_settings"] = settings
                save_data(d)
    except Exception:
        pass

def get_gc_client(gc_id, session_id, proxy=None):
    cache_key = f"gc:{gc_id}"
    if cache_key in ig_clients:
        return ig_clients[cache_key]
    saved_settings = None
    try:
        with data_lock:
            d = load_data()
            saved_settings = d.get("gc_creator_ids", {}).get(gc_id, {}).get("session_settings")
    except Exception:
        saved_settings = None
    if saved_settings:
        try:
            cl = Client()
            cl.set_settings(saved_settings)
            if proxy:
                cl.set_proxy(proxy)
            cl.account_info()
            ig_clients[cache_key] = cl
            return cl
        except Exception:
            pass
    cl = Client()
    if proxy:
        cl.set_proxy(proxy)
    cl.login_by_sessionid(decode_session(session_id))
    ig_clients[cache_key] = cl
    persist_gc_client_settings(gc_id, cl)
    return cl

def extract_thread_id(s):
    s = s.strip()
    if "instagram.com/direct/t/" in s:
        return s.rstrip("/").split("/")[-1]
    return s

def nc_rename(cl, thread_id, title):
    try:
        result = cl.direct_thread_update_title(thread_id, title)
        if result is not False:
            return True, None
    except Exception: pass
    try:
        cl.private_request(
            f"direct_v2/threads/{thread_id}/update_title/",
            data={"title": title, "_uuid": cl.uuid, "_uid": str(cl.user_id), "_csrftoken": cl.token}
        )
        return True, None
    except Exception: pass
    try:
        thread = cl.direct_thread(thread_id)
        r = thread.update_title(title)
        if r is not False:
            return True, None
    except Exception: pass
    try:
        cl.private_request(
            f"direct_v2/threads/{thread_id}/update_title/",
            data={"title": title, "_uuid": cl.uuid, "_uid": str(cl.user_id), "use_unified_inbox": "true"}
        )
        return True, None
    except Exception as e4:
        return False, str(e4)

def get_thread_title(cl, thread_id):
    try:
        thread = cl.direct_thread(int(thread_id))
        return (thread.thread_title or "").strip()
    except Exception:
        return None


def ravan_send(sock, thread_id, message):
    try:
        result = sock.send_message(
            str(thread_id),
            {
                "text": message
            }
        )
        if isinstance(result, dict) and result.get("ok", True) is False:
            return False, str(result)
        return True, None
    except Exception as e:
        return False, str(e)


def ravan_rename(sock, thread_id, title):
    try:
        result = sock.rename_group(
            str(thread_id),
            title
        )
        if isinstance(result, dict) and result.get("ok", True) is False:
            return False, str(result)
        return True, None
    except Exception as e:
        return False, str(e)


def ravan_fetch_groups(session_id, proxy=None):
    # Working RAVAN source fetch logic preserved.
    cl = Client()

    if proxy:
        cl.set_proxy(proxy)

    cl.login_by_sessionid(
        decode_session(session_id)
    )

    threads = cl.direct_threads(amount=50)

    groups = []

    for t in threads:
        if t.is_group:
            # Use the normal Instagram web thread ID (t.pk) for RAVAN.
            web_thread_id = getattr(t, "pk", None)

            if not web_thread_id:
                raise ValueError(
                    f"Could not get normal web thread ID for group {t.thread_title!r}"
                )

            web_thread_id = str(web_thread_id).strip()
            group_id = str(t.id).strip()
            group_name = t.thread_title or group_id

            group_link = f"https://www.instagram.com/direct/t/{web_thread_id}/"

            groups.append({
                "id": group_id,
                "web_thread_id": web_thread_id,
                "name": group_name,
                "link": group_link
            })

    return groups


def ravan_worker(acc_id, acc, stop_event):
    session_id = acc.get("session_id", "").strip()
    proxy = acc.get("proxy", "").strip() or None
    groups = [extract_thread_id(g) for g in acc.get("groups", "").split("\n") if g.strip()]
    groups = groups[:1]
    titles = [t.strip() for t in acc.get("nc_titles", "").split(",") if t.strip()]
    message_mode = acc.get("message_mode", "DAKSH")
    target_name = acc.get("target_name", "").strip()
    messages = []

    if not session_id:
        bot_status[acc_id] = {"running": False, "sent": 0, "failed": 0, "last_action": "Session ID missing"}
        return

    if not groups:
        bot_status[acc_id] = {"running": False, "sent": 0, "failed": 0, "last_action": "No group selected"}
        return

    if message_mode == "DAKSH":
        try:
            with open("msg.txt", "r", encoding="utf-8") as f:
                template_message = f.read()
            messages = [template_message.replace("<t>", target_name)]
        except Exception as e:
            bot_status[acc_id] = {"running": False, "sent": 0, "failed": 0, "last_action": "msg.txt missing"}
            log(acc_id, f"❌ Could not read msg.txt: {e}")
            return
    else:
        messages = [m.strip() for m in acc.get("messages", "").split("---MSG---") if m.strip()]
        if not messages:
            single = acc.get("message", "").strip()
            if single:
                messages = [single]

    if not messages:
        bot_status[acc_id] = {"running": False, "sent": 0, "failed": 0, "last_action": "No message configured"}
        log(acc_id, "❌ No message configured")
        return

    msg_delay_min = float(acc.get("msg_delay_min", 2))
    msg_delay_max = float(acc.get("msg_delay_max", 5))
    cooldown_after_msgs = int(acc.get("cooldown_after", 0))
    cooldown_dur = float(acc.get("cooldown_dur", 5))
    nc_every_msgs = int(acc.get("nc_every_msgs", 0))

    bot_logs[acc_id] = collections.deque(maxlen=300)
    bot_status[acc_id] = {
        "running": True, "sent": 0, "failed": 0,
        "nc_done": 0, "nc_failed": 0, "nc_skipped": 0,
        "gcs_done": 0, "total_gcs": 1,
        "last_action": "Connecting with RAVAN...", "started_at": time.time(),
        "cooldown": False, "cooldown_end": 0,
        "reauth_attempted": False
    }

    thread_id = groups[0]
    log(acc_id, "⚡ Starting RAVAN...")
    log(acc_id, f"📋 GC: {thread_id} | Titles: {len(titles)} | Messages: {len(messages)}")
    log(acc_id, f"⏱ Msg delay: {msg_delay_min}-{msg_delay_max}s")

    sock = None
    try:
        sock_kwargs = {"sessionid": decode_session(session_id)}
        if proxy:
            sock_kwargs["proxy"] = proxy
        sock = make_ig_web_socket(**sock_kwargs)
        # Exact connection mode from the supplied working RAVAN script.
        sock.connect(
            dm_receive="dgw",
            send="graphql",
            keep_alive=False
        )
        log(acc_id, f"✅ RAVAN connected{' (proxy)' if proxy else ''}")
        bot_status[acc_id]["last_action"] = f"RAVAN ready → {thread_id}"
    except Exception as e:
        log(acc_id, f"❌ RAVAN login failed: {e}")
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = f"RAVAN login failed: {e}"
        return

    title_idx = 0
    msg_idx = 0
    msgs_since_cd = 0
    msgs_since_nc = 0

    try:
        while not stop_event.is_set():
            if titles and (msgs_since_nc == 0 or (nc_every_msgs > 0 and msgs_since_nc >= nc_every_msgs)):
                title = titles[title_idx % len(titles)]
                bot_status[acc_id]["last_action"] = f"RAVAN rename → {title}"
                ok, err = ravan_rename(sock, thread_id, title)
                if ok:
                    bot_status[acc_id]["nc_done"] += 1
                    log(acc_id, f"💠 RAVAN renamed → {title}")
                else:
                    bot_status[acc_id]["nc_failed"] += 1
                    log(acc_id, f"❌ RAVAN rename failed → {thread_id}: {err}")
                title_idx += 1
                msgs_since_nc = 0

            message = messages[msg_idx % len(messages)]
            bot_status[acc_id]["last_action"] = f"RAVAN sending → {thread_id}"
            ok, err = ravan_send(sock, thread_id, message)
            if ok:
                bot_status[acc_id]["sent"] += 1
                bot_status[acc_id]["gcs_done"] = 1
                msgs_since_cd += 1
                msgs_since_nc += 1
                log(acc_id, f"📨 RAVAN sent → {thread_id}")
            else:
                bot_status[acc_id]["failed"] += 1
                log(acc_id, f"❌ RAVAN send failed → {thread_id}: {err}")

            msg_idx += 1

            if cooldown_after_msgs > 0 and msgs_since_cd >= cooldown_after_msgs:
                dur_secs = cooldown_dur * 60
                bot_status[acc_id]["cooldown"] = True
                bot_status[acc_id]["cooldown_end"] = time.time() + dur_secs
                bot_status[acc_id]["last_action"] = f"Cooldown {cooldown_dur} min"
                while time.time() < bot_status[acc_id]["cooldown_end"] and not stop_event.is_set():
                    time.sleep(1)
                bot_status[acc_id]["cooldown"] = False
                bot_status[acc_id]["cooldown_end"] = 0
                msgs_since_cd = 0
                log(acc_id, "✅ Cooldown done — resuming")

            if stop_event.is_set():
                break

            delay = random.uniform(msg_delay_min, msg_delay_max)
            bot_status[acc_id]["last_action"] = f"RAVAN delay {delay:.1f}s"
            time.sleep(delay)

    except Exception as e:
        log(acc_id, f"❌ RAVAN error → {e}")
        bot_status[acc_id]["last_action"] = f"RAVAN error: {e}"
    finally:
        try:
            if sock:
                sock.disconnect()
        except Exception:
            pass
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = "RAVAN stopped"
        log(acc_id, "🛑 RAVAN stopped")


def _multi_messages(acc):
    mode = acc.get("message_mode", "DAKSH")
    target = acc.get("target_name", "").strip()
    if mode == "DAKSH":
        try:
            with open("msg.txt", "r", encoding="utf-8") as f:
                return [f.read().replace("<t>", target)]
        except Exception:
            return []
    messages = [m.strip() for m in acc.get("messages", "").split("---MSG---") if m.strip()]
    if not messages and acc.get("message", "").strip():
        messages = [acc.get("message", "").strip()]
    return messages

def _multi_titles(acc):
    return [t.strip() for t in acc.get("nc_titles", "").split(",") if t.strip()]

# AYAN MULTI GC / RAVAN MULTI GC timing is intentionally hardcoded.
# Sending: GC1 -> 40s -> GC2 -> 40s -> GC3 -> 40s -> GC1 ...
# Renaming: GC1 -> 180s -> GC2 -> 180s -> GC3 -> 180s -> GC1 ...
# Sender and renamer threads are started together, but each keeps its own delay.
MULTI_MSG_DELAY = 40
MULTI_RENAME_DELAY = 180

def _multi_wait(stop_event, seconds):
    end = time.time() + seconds
    while time.time() < end and not stop_event.is_set():
        time.sleep(min(1.0, max(0.05, end - time.time())))

def _init_multi_status(acc_id, groups, method, titles, messages):
    bot_logs[acc_id] = collections.deque(maxlen=300)
    bot_status[acc_id] = {
        "running": True, "sent": 0, "failed": 0, "nc_done": 0, "nc_failed": 0, "nc_skipped": 0,
        "gcs_done": 0, "total_gcs": len(groups), "last_action": f"Starting {method}...",
        "started_at": time.time(), "cooldown": False, "cooldown_end": 0,
        "reauth_attempted": False, "multi_method": method, "message_delay": MULTI_MSG_DELAY, "rename_delay": MULTI_RENAME_DELAY
    }
    log(acc_id, f"⚡ Starting {method}...")
    log(acc_id, f"📋 GCs: {len(groups)} | Titles: {len(titles)} | Messages: {len(messages)}")
    log(acc_id, f"⏱ Send delay: {MULTI_MSG_DELAY}s | Rename delay: {MULTI_RENAME_DELAY}s")

def ayaan_multi_gc_worker(acc_id, acc, stop_event):
    session_id = acc.get("session_id", "").strip()
    proxy = acc.get("proxy", "").strip() or None
    raw_groups = acc.get("groups", "")
    raw_groups = raw_groups.replace("\\n", "\n")
    groups = [
        extract_thread_id(g.strip())
        for g in raw_groups.splitlines()
        if g.strip()
    ][:50]
    titles = _multi_titles(acc)
    messages = _multi_messages(acc)
    cooldown_after_msgs = int(acc.get("cooldown_after", 0))
    cooldown_dur = float(acc.get("cooldown_dur", 5))
    nc_every_msgs = int(acc.get("nc_every_msgs", 0))

    if not session_id or not groups or not messages:
        bot_status[acc_id] = {"running": False, "sent": 0, "failed": 0, "nc_done": 0, "nc_failed": 0, "nc_skipped": 0, "total_gcs": len(groups), "last_action": "Missing session, groups or messages"}
        return

    _init_multi_status(acc_id, groups, "AYAN MULTI GC", titles, messages)
    bot_status[acc_id]["message_delay"] = MULTI_MSG_DELAY
    bot_status[acc_id]["rename_delay"] = MULTI_RENAME_DELAY
    bot_status[acc_id]["nc_every_msgs"] = nc_every_msgs
    bot_status[acc_id]["cooldown_after"] = cooldown_after_msgs
    bot_status[acc_id]["cooldown_dur"] = cooldown_dur

    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(get_client, acc_id, session_id, proxy, acc.get("csrf_token", "") or None)
            cl = future.result(timeout=30)
        log(acc_id, "✅ Instagrapi connected")
    except concurrent.futures.TimeoutError:
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = "Login timed out"
        log(acc_id, "❌ Login timed out after 30s — check session ID")
        return
    except Exception as e:
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = f"Login failed: {e}"
        log(acc_id, f"❌ Instagrapi login failed: {e}")
        return

    title_idx = 0
    msg_idx = 0
    msgs_since_cd = 0
    msgs_since_nc = 0

    def do_nc_for_all():
        nonlocal title_idx
        if not titles:
            return
        title = titles[title_idx % len(titles)]
        for thread_id in groups:
            if stop_event.is_set():
                break
            bot_status[acc_id]["last_action"] = f"Checking NC → {thread_id}"
            try:
                current_title = get_thread_title(cl, thread_id)
            except Exception:
                current_title = None
            if current_title is not None and current_title.strip() == title.strip():
                log(acc_id, f"⏭ AYAN MULTI NC skip (already '{title}') → {thread_id}")
                bot_status[acc_id]["nc_skipped"] += 1
                continue
            bot_status[acc_id]["last_action"] = f"AYAN MULTI NC → {title}"
            try:
                ok, err = nc_rename(cl, int(thread_id), title)
                if ok:
                    bot_status[acc_id]["nc_done"] += 1
                    persist_client_settings(acc_id, cl)
                    log(acc_id, f"💠 AYAN MULTI renamed → {title} | {thread_id}")
                else:
                    bot_status[acc_id]["nc_failed"] += 1
                    log(acc_id, f"❌ AYAN MULTI rename failed → {thread_id}: {err}")
            except Exception as e:
                bot_status[acc_id]["nc_failed"] += 1
                log(acc_id, f"❌ AYAN MULTI rename error → {thread_id}: {e}")
            if stop_event.is_set():
                break
            _multi_wait(stop_event, MULTI_RENAME_DELAY)
        title_idx += 1

    try:
        if titles:
            log(acc_id, "✏️ Initial NC...")
            do_nc_for_all()

        while not stop_event.is_set():
            bot_status[acc_id]["gcs_done"] = 0

            if titles and nc_every_msgs > 0 and msgs_since_nc >= nc_every_msgs:
                log(acc_id, f"✏️ NC after {nc_every_msgs} messages...")
                do_nc_for_all()
                msgs_since_nc = 0

            for i, thread_id in enumerate(groups):
                if stop_event.is_set():
                    break
                message = messages[msg_idx % len(messages)] if messages else ""
                bot_status[acc_id]["last_action"] = f"AYAN MULTI sending → {thread_id}"
                try:
                    cl.direct_send(message, thread_ids=[int(thread_id)])
                    bot_status[acc_id]["sent"] += 1
                    bot_status[acc_id]["gcs_done"] = i + 1
                    msgs_since_cd += 1
                    msgs_since_nc += 1
                    persist_client_settings(acc_id, cl)
                    log(acc_id, f"📨 AYAN MULTI sent → {thread_id}")
                except Exception as e:
                    bot_status[acc_id]["failed"] += 1
                    log(acc_id, f"❌ AYAN MULTI send failed → {thread_id}: {e}")

                msg_idx += 1
                if stop_event.is_set():
                    break

                if stop_event.is_set():
                    break
                bot_status[acc_id]["last_action"] = f"AYAN MULTI delay {MULTI_MSG_DELAY}s"
                _multi_wait(stop_event, MULTI_MSG_DELAY)

            if cooldown_after_msgs > 0 and msgs_since_cd >= cooldown_after_msgs:
                dur_secs = cooldown_dur * 60
                bot_status[acc_id]["cooldown"] = True
                bot_status[acc_id]["cooldown_end"] = time.time() + dur_secs
                bot_status[acc_id]["last_action"] = f"Cooldown {cooldown_dur} min"
                log(acc_id, f"😴 Cooldown after {cooldown_after_msgs} messages — {cooldown_dur} min pause...")
                while time.time() < bot_status[acc_id]["cooldown_end"] and not stop_event.is_set():
                    time.sleep(1)
                bot_status[acc_id]["cooldown"] = False
                bot_status[acc_id]["cooldown_end"] = 0
                msgs_since_cd = 0
                log(acc_id, "✅ Cooldown done — resuming")

            bot_status[acc_id]["last_action"] = "Loop complete ✓"

    except Exception as e:
        log(acc_id, f"❌ AYAN MULTI error → {e}")
        bot_status[acc_id]["last_action"] = f"AYAN MULTI error: {e}"
    finally:
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = "AYAN MULTI stopped"
        log(acc_id, "🛑 AYAN MULTI GC stopped")


def ravan_multi_gc_worker(acc_id, acc, stop_event):
    session_id = acc.get("session_id", "").strip()
    proxy = acc.get("proxy", "").strip() or None
    raw_groups = acc.get("groups", "")
    raw_groups = raw_groups.replace("\\n", "\n")
    groups = [
        extract_thread_id(g.strip())
        for g in raw_groups.splitlines()
        if g.strip()
    ][:50]
    titles = _multi_titles(acc)
    messages = _multi_messages(acc)
    cooldown_after_msgs = int(acc.get("cooldown_after", 0))
    cooldown_dur = float(acc.get("cooldown_dur", 5))
    nc_every_msgs = int(acc.get("nc_every_msgs", 0))

    if not session_id or not groups or not messages:
        bot_status[acc_id] = {"running": False, "sent": 0, "failed": 0, "nc_done": 0, "nc_failed": 0, "nc_skipped": 0, "total_gcs": len(groups), "last_action": "Missing session, groups or messages"}
        return

    _init_multi_status(acc_id, groups, "RAVAN MULTI GC", titles, messages)
    bot_status[acc_id]["message_delay"] = MULTI_MSG_DELAY
    bot_status[acc_id]["rename_delay"] = MULTI_RENAME_DELAY
    bot_status[acc_id]["nc_every_msgs"] = nc_every_msgs
    bot_status[acc_id]["cooldown_after"] = cooldown_after_msgs
    bot_status[acc_id]["cooldown_dur"] = cooldown_dur

    sock = None
    try:
        kw = {"sessionid": decode_session(session_id)}
        if proxy:
            kw["proxy"] = proxy
        sock = make_ig_web_socket(**kw)
        sock.connect(dm_receive="dgw", send="graphql", keep_alive=False)
        log(acc_id, f"✅ RAVAN connected{' (proxy)' if proxy else ''}")
    except Exception as e:
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = f"RAVAN login failed: {e}"
        log(acc_id, f"❌ RAVAN login failed: {e}")
        return

    title_idx = 0
    msg_idx = 0
    msgs_since_cd = 0
    msgs_since_nc = 0

    def do_nc_for_all():
        nonlocal title_idx
        if not titles:
            return
        title = titles[title_idx % len(titles)]
        for thread_id in groups:
            if stop_event.is_set():
                break
            bot_status[acc_id]["last_action"] = f"RAVAN MULTI NC → {title}"
            try:
                ok, err = ravan_rename(sock, thread_id, title)
                if ok:
                    bot_status[acc_id]["nc_done"] += 1
                    log(acc_id, f"💠 RAVAN MULTI renamed → {title} | {thread_id}")
                else:
                    bot_status[acc_id]["nc_failed"] += 1
                    log(acc_id, f"❌ RAVAN MULTI rename failed → {thread_id}: {err}")
            except Exception as e:
                bot_status[acc_id]["nc_failed"] += 1
                log(acc_id, f"❌ RAVAN MULTI rename error → {thread_id}: {e}")
            if stop_event.is_set():
                break
            _multi_wait(stop_event, MULTI_RENAME_DELAY)
        title_idx += 1

    try:
        if titles:
            log(acc_id, "✏️ Initial NC...")
            do_nc_for_all()

        while not stop_event.is_set():
            bot_status[acc_id]["gcs_done"] = 0

            if titles and nc_every_msgs > 0 and msgs_since_nc >= nc_every_msgs:
                log(acc_id, f"✏️ NC after {nc_every_msgs} messages...")
                do_nc_for_all()
                msgs_since_nc = 0

            for i, thread_id in enumerate(groups):
                if stop_event.is_set():
                    break
                message = messages[msg_idx % len(messages)] if messages else ""
                bot_status[acc_id]["last_action"] = f"RAVAN MULTI sending → {thread_id}"
                ok, err = ravan_send(sock, thread_id, message)
                if ok:
                    bot_status[acc_id]["sent"] += 1
                    bot_status[acc_id]["gcs_done"] = i + 1
                    msgs_since_cd += 1
                    msgs_since_nc += 1
                    log(acc_id, f"📨 RAVAN MULTI sent → {thread_id}")
                else:
                    bot_status[acc_id]["failed"] += 1
                    log(acc_id, f"❌ RAVAN MULTI send failed → {thread_id}: {err}")

                msg_idx += 1
                if stop_event.is_set():
                    break

                if stop_event.is_set():
                    break
                bot_status[acc_id]["last_action"] = f"RAVAN MULTI delay {MULTI_MSG_DELAY}s"
                _multi_wait(stop_event, MULTI_MSG_DELAY)

            if cooldown_after_msgs > 0 and msgs_since_cd >= cooldown_after_msgs:
                dur_secs = cooldown_dur * 60
                bot_status[acc_id]["cooldown"] = True
                bot_status[acc_id]["cooldown_end"] = time.time() + dur_secs
                bot_status[acc_id]["last_action"] = f"Cooldown {cooldown_dur} min"
                log(acc_id, f"😴 Cooldown after {cooldown_after_msgs} messages — {cooldown_dur} min pause...")
                while time.time() < bot_status[acc_id]["cooldown_end"] and not stop_event.is_set():
                    time.sleep(1)
                bot_status[acc_id]["cooldown"] = False
                bot_status[acc_id]["cooldown_end"] = 0
                msgs_since_cd = 0
                log(acc_id, "✅ Cooldown done — resuming")

            bot_status[acc_id]["last_action"] = "Loop complete ✓"

    except Exception as e:
        log(acc_id, f"❌ RAVAN MULTI error → {e}")
        bot_status[acc_id]["last_action"] = f"RAVAN MULTI error: {e}"
    finally:
        try:
            if sock:
                sock.disconnect()
        except Exception:
            pass
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = "RAVAN MULTI stopped"
        log(acc_id, "🛑 RAVAN MULTI GC stopped")

def bot_worker(acc_id, acc, stop_event):
    session_id = acc["session_id"]
    proxy = acc.get("proxy", "").strip() or None
    csrf_token = acc.get("csrf_token", "").strip() or None
               
    raw_groups = [extract_thread_id(g) for g in acc.get("groups", "").split("\n") if g.strip()]
    groups = raw_groups[:5]
    titles = [t.strip() for t in acc.get("nc_titles", "").split(",") if t.strip()]
    message_mode = acc.get("message_mode", "DAKSH")
    target_name = acc.get("target_name", "").strip()
    messages = []
    if message_mode == "DAKSH":
        try:
            with open("msg.txt", "r", encoding="utf-8") as f:
                template_message = f.read()
            messages = [template_message.replace("<t>", target_name)]
        except Exception as e:
            log(acc_id, f"❌ Could not read msg.txt: {e}")
            bot_status[acc_id] = {"running": False, "sent": 0, "failed": 0, "last_action": "msg.txt missing"}
            return
    else:
        messages = [m.strip() for m in acc.get("messages", "").split("---MSG---") if m.strip()]
        if not messages:
            single = acc.get("message", "").strip()
            if single: messages = [single]

            
    msg_delay_min  = float(acc.get("msg_delay_min", 2))
    msg_delay_max  = float(acc.get("msg_delay_max", 5))

                               
    cooldown_after_msgs = int(acc.get("cooldown_after", 0))                
    cooldown_dur        = float(acc.get("cooldown_dur", 5))           

                                             
    nc_every_msgs = int(acc.get("nc_every_msgs", 0))

    bot_logs[acc_id] = collections.deque(maxlen=300)
    bot_status[acc_id] = {
        "running": True, "sent": 0, "failed": 0,
        "nc_done": 0, "nc_failed": 0, "nc_skipped": 0,
        "gcs_done": 0, "total_gcs": len(groups),
        "last_action": "Logging in...", "started_at": time.time(),
        "cooldown": False, "cooldown_end": 0,
        "reauth_attempted": False
    }

    log(acc_id, "⚡ Starting bot...")
    log(acc_id, f"📋 GCs: {len(groups)} | Titles: {len(titles)} | Messages: {len(messages)}")
    log(acc_id, f"⏱ Msg delay: {msg_delay_min}-{msg_delay_max}s")
    if cooldown_after_msgs > 0:
        log(acc_id, f"😴 Cooldown: every {cooldown_after_msgs} messages → {cooldown_dur} min pause")

    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(get_client, acc_id, session_id, proxy, csrf_token)
            cl = future.result(timeout=30)
        log(acc_id, f"✅ Logged in successfully{' (proxy)' if proxy else ''}")
        bot_status[acc_id]["last_action"] = "Logged in ✓"
    except concurrent.futures.TimeoutError:
        log(acc_id, "❌ Login timed out after 30s — check session ID")
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = "Login timed out"
        return
    except Exception as e:
        log(acc_id, f"❌ Login failed: {e}")
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = f"Login failed: {e}"
        return

    title_idx     = 0
    msg_idx       = 0
    msgs_since_cd = 0                                     
    msgs_since_nc = 0                               

    def do_nc_for_all():
        nonlocal title_idx
        if not titles: return
        t = titles[title_idx % len(titles)]
        for thread_id in groups:
            if stop_event.is_set(): break
            bot_status[acc_id]["last_action"] = f"Checking NC → {thread_id}"
            try:
                current_title = get_thread_title(cl, thread_id)
            except Exception:
                current_title = None
            if current_title is not None and current_title.strip() == t.strip():
                log(acc_id, f"⏭ NC skip (already '{t}') → {thread_id}")
                bot_status[acc_id]["nc_skipped"] += 1
            else:
                bot_status[acc_id]["last_action"] = f"NC → {t}"
                try:
                    ok, err = nc_rename(cl, int(thread_id), t)
                    if ok:
                        bot_status[acc_id]["nc_done"] += 1
                        persist_client_settings(acc_id, cl)
                        log(acc_id, f"✅ NC done [{t}] → {thread_id}")
                    else:
                        bot_status[acc_id]["nc_failed"] += 1
                        log(acc_id, f"❌ NC failed → {thread_id}: {err}")
                except Exception as e:
                    bot_status[acc_id]["nc_failed"] += 1
                    log(acc_id, f"❌ NC error → {thread_id}: {e}")
        title_idx += 1

                     
    log(acc_id, "✏️ Initial NC...")
    do_nc_for_all()

    while not stop_event.is_set():
        bot_status[acc_id]["gcs_done"] = 0

                             
        if titles and nc_every_msgs > 0 and msgs_since_nc >= nc_every_msgs:
            log(acc_id, f"✏️ NC after {nc_every_msgs} messages...")
            do_nc_for_all()
            msgs_since_nc = 0

        for thread_id in groups:
            if stop_event.is_set(): break

                          
            message = messages[msg_idx % len(messages)] if messages else ""
            bot_status[acc_id]["last_action"] = f"Sending → {thread_id}"
            try:
                cl.direct_send(message, thread_ids=[int(thread_id)])
                bot_status[acc_id]["sent"] += 1
                persist_client_settings(acc_id, cl)
                msgs_since_cd += 1
                msgs_since_nc += 1
                log(acc_id, f"✅ Sent → {thread_id}")
            except Exception as e:
                bot_status[acc_id]["failed"] += 1
                err_str = str(e)
                status_code = None
                if hasattr(e, 'response') and e.response is not None:
                    try:
                        resp_json = e.response.json()
                        ig_msg = resp_json.get('message') or resp_json.get('error_title') or resp_json.get('feedback_message') or err_str
                        status_code = e.response.status_code
                        err_str = f"{ig_msg} (status {status_code})"
                    except Exception:
                        status_code = e.response.status_code
                        err_str = f"{status_code}: {e.response.text[:120]}"
                log(acc_id, f"❌ Send failed → {thread_id}: {err_str}")

                                                                          
                                                              
                if status_code == 403 or "user_has_logged_out" in err_str or "login_required" in err_str:
                    if bot_status[acc_id].get("reauth_attempted"):
                        log(acc_id, "🛑 Session is still invalid — stopping (no retry loop)")
                        bot_status[acc_id]["running"] = False
                        bot_status[acc_id]["last_action"] = "Session expired — re-auth required"
                        return
                    bot_status[acc_id]["reauth_attempted"] = True
                    log(acc_id, "🔄 Session expired — attempting one re-auth...")
                    bot_status[acc_id]["last_action"] = "Re-authenticating..."
                    try:
                        ig_clients.pop(acc_id, None)
                                                                               
                                                                              
                        with data_lock:
                            d = load_data()
                            if acc_id in d.get("accounts", {}):
                                d["accounts"][acc_id].pop("session_settings", None)
                                save_data(d)
                        cl = get_client(acc_id, session_id, proxy, csrf_token)
                        bot_status[acc_id]["reauth_attempted"] = False
                        log(acc_id, "✅ Re-auth successful — resuming")
                        bot_status[acc_id]["last_action"] = "Re-auth done ✓"
                    except Exception as re_err:
                        log(acc_id, f"❌ Re-auth failed: {re_err}")
                        bot_status[acc_id]["running"] = False
                        bot_status[acc_id]["last_action"] = "Session expired — re-auth required"
                        return
                else:
                                                                  
                    log(acc_id, "⏳ Error cooldown — 5 min pause...")
                    bot_status[acc_id]["last_action"] = "Error cooldown 5 min..."
                    bot_status[acc_id]["cooldown"] = True
                    for _ in range(300):
                        if stop_event.is_set(): break
                        time.sleep(1)
                    bot_status[acc_id]["cooldown"] = False
                    log(acc_id, "✅ Error cooldown done — resuming")

            msg_idx += 1
            bot_status[acc_id]["gcs_done"] += 1

            if stop_event.is_set(): break
            delay = random.uniform(msg_delay_min, msg_delay_max)
            log(acc_id, f"💤 Delay: {delay:.1f}s")
            time.sleep(delay)

        bot_status[acc_id]["last_action"] = "Loop complete ✓"
        if cooldown_after_msgs > 0 and msgs_since_cd >= cooldown_after_msgs:
            dur_secs = cooldown_dur * 60
            log(acc_id, f"😴 Cooldown after {cooldown_after_msgs} messages — {cooldown_dur} min pause...")
            bot_status[acc_id]["cooldown"] = True
            bot_status[acc_id]["cooldown_end"] = time.time() + dur_secs
            elapsed = 0
            while elapsed < dur_secs and not stop_event.is_set():
                time.sleep(1)
                elapsed += 1
            bot_status[acc_id]["cooldown"] = False
            bot_status[acc_id]["cooldown_end"] = 0
            msgs_since_cd = 0
            log(acc_id, "✅ Cooldown done — resuming...")

        bot_status[acc_id]["last_action"] = "Loop complete ✓"

    log(acc_id, "🛑 Bot stopped")
    bot_status[acc_id]["running"] = False
    bot_status[acc_id]["last_action"] = "Stopped"


# ---------------------------------------------------------------------------
# MULTI-ACCOUNT STABILITY SUPERVISOR
# ---------------------------------------------------------------------------
# Each account keeps its own worker thread. If a worker unexpectedly crashes,
# only that account is restarted; other accounts are never affected.
def _select_account_worker(acc):
    method = acc.get("method", "INSTAGRAPI")
    if method == "AYAN MULTI GC":
        return ayaan_multi_gc_worker
    if method == "RAVAN MULTI GC":
        return ravan_multi_gc_worker
    if method == "RAVAN":
        return ravan_worker
    return bot_worker


def supervised_account_worker(acc_id, acc, stop_event):
    worker = _select_account_worker(acc)
    crash_count = 0

    while not stop_event.is_set():
        try:
            worker(acc_id, acc, stop_event)
        except Exception as exc:
            crash_count += 1
            if stop_event.is_set():
                break

            # Keep the failure isolated to this account.
            st = bot_status.setdefault(acc_id, {})
            st["running"] = False
            st["last_action"] = f"Worker crashed: {exc}"
            log(acc_id, f"⚠️ Worker crashed: {type(exc).__name__}: {exc}")

            # Back off so a transient Instagram/network failure cannot create
            # a tight restart loop.
            backoff = min(60, 5 * crash_count)
            st["cooldown"] = True
            st["cooldown_end"] = time.time() + backoff
            log(acc_id, f"🔄 Restarting this account in {backoff}s...")
            for _ in range(backoff):
                if stop_event.is_set():
                    break
                time.sleep(1)
            st["cooldown"] = False
            st["cooldown_end"] = 0

            if stop_event.is_set():
                break

            # Force a fresh client after an unexpected worker crash.
            try:
                ig_clients.pop(acc_id, None)
            except Exception:
                pass

            st["running"] = True
            st["started_at"] = time.time()
            st["reauth_attempted"] = False
            continue

        # A worker normally returns when it was deliberately stopped or when
        # it reached a terminal state such as an invalid session. Do not
        # restart those cases.
        if stop_event.is_set():
            break

        st = bot_status.get(acc_id, {})
        last_action = str(st.get("last_action", "")).lower()

        terminal = (
            "session expired" in last_action
            or "login failed" in last_action
            or "login timed out" in last_action
            or "reauth required" in last_action
            or "missing session" in last_action
            or "stopped" in last_action
        )

        # Multi workers catch their own top-level exceptions and return.
        # Restart those only when their status explicitly says it was an error.
        worker_error = " error" in last_action or "failed:" in last_action

        if terminal and not worker_error:
            break

        # If a worker returned without being stopped and without a terminal
        # status, treat it as an unexpected exit and restart that account.
        if not terminal or worker_error:
            crash_count += 1
            st["running"] = False
            st["last_action"] = "Worker exited unexpectedly"
            log(acc_id, "⚠️ Worker exited unexpectedly — restarting this account...")
            try:
                ig_clients.pop(acc_id, None)
            except Exception:
                pass

            backoff = min(60, 5 * crash_count)
            for _ in range(backoff):
                if stop_event.is_set():
                    break
                time.sleep(1)

            if stop_event.is_set():
                break

            st["running"] = True
            st["started_at"] = time.time()
            st["reauth_attempted"] = False
            continue

    if acc_id in bot_status:
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["cooldown"] = False
        bot_status[acc_id]["cooldown_end"] = 0

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>DAKSH SX7</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
<style>
:root{
 --bg:#05090b;--bg2:#081113;--card:#0b1518;--card2:#0d1a1d;--line:#193238;
 --purple:#14b8a6;--purple2:#06b6d4;--cyan:#22d3ee;--blue:#38bdf8;
 --green:#22c55e;--red:#ef4444;--amber:#f97316;--text:#eef2ff;--muted:#7f9aa3;
}
*{box-sizing:border-box;margin:0;padding:0}html{scroll-behavior:smooth}
body{min-height:100vh;background:radial-gradient(900px 500px at 70% -10%,#003f3a44,transparent 60%),radial-gradient(700px 500px at 10% 20%,#004b5740,transparent 65%),var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}
button,input,textarea{font:inherit}.shell{display:flex;min-height:100vh}
.sidebar{width:190px;flex:none;position:fixed;left:0;top:0;bottom:0;padding:18px 12px;background:linear-gradient(180deg,#080b14f2,#090c15f8);border-right:1px solid var(--line);z-index:100;display:flex;flex-direction:column}
.brand{display:flex;align-items:center;gap:10px;padding:8px 10px 22px}.brand-mark{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--purple),var(--cyan));display:grid;place-items:center;color:#fff;font-weight:800;box-shadow:0 0 25px #14b8a655}.brand-name{font:700 20px 'Share Tech Mono';letter-spacing:2px;color:#99f6e4}.brand-sub{font-size:8px;letter-spacing:3px;color:#94a3b8;margin-top:2px}
.nav{display:flex;flex-direction:column;gap:5px}.nav-item{display:flex;align-items:center;gap:10px;padding:10px 11px;border-radius:9px;color:#9aa5bd;font-size:12px;text-decoration:none;border:1px solid transparent}.nav-item:hover,.nav-item.active{color:#fff;background:linear-gradient(90deg,#14b8a61e,#22d3ee08);border-color:#0f766e44}.nav-icon{width:20px;text-align:center;color:#2dd4bf;font-size:15px}.side-bottom{margin-top:auto;border-top:1px solid var(--line);padding-top:14px}.side-owner{font-size:10px;color:#64748b;text-align:center;letter-spacing:2px}.side-owner strong{display:block;color:#67e8f9;font-size:15px;letter-spacing:1px;margin-bottom:3px}
.main{margin-left:190px;width:calc(100% - 190px);padding:20px 24px 34px;max-width:1500px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:18px}
.panel-top{position:relative;justify-content:center!important;text-align:center}
.panel-brand h1{font:700 clamp(28px,4vw,42px) 'Playfair Display',serif;letter-spacing:4px;color:#e2c783}
.panel-brand h1 span{color:#b9975b}
.logged-user{margin-top:7px;color:#8f969e;font-size:10px;letter-spacing:2px}
.logged-user b{color:#e2c783}
.panel-top .top-actions{position:absolute;right:0}
.username-stat{font-size:15px!important;letter-spacing:.5px;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.top-title h1{font-size:22px;letter-spacing:.5px}.top-title p{font-size:11px;color:var(--muted);margin-top:3px}.top-actions{display:flex;gap:8px;align-items:center}.system-pill{padding:8px 12px;border:1px solid #04785766;background:#0a1a1222;border-radius:9px;color:#34d399;font:10px 'Share Tech Mono'}
.btn{border:1px solid var(--line);background:#0b1518;color:#dbe4ff;border-radius:7px;padding:8px 12px;cursor:pointer;font:600 10px 'Share Tech Mono';letter-spacing:1px;transition:.18s}.btn:hover{border-color:#0f766e;box-shadow:0 0 18px #14b8a622}.btn-add{background:linear-gradient(135deg,#0f766e,#14b8a6);border-color:#67e8f9;color:#fff}.btn-start{border-color:#047857;color:#34d399}.btn-stop{border-color:#991b1b;color:#f87171}.btn-logs{border-color:#155e75;color:#67e8f9}.btn-edit{border-color:#334155;color:#7dd3fc}.btn-del{border-color:#991b1b;color:#f87171}.btn-collapse{background:transparent;border:0;color:#64748b;cursor:pointer;padding:8px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}.stat-card{background:linear-gradient(145deg,#0d191c,#081113);border:1px solid var(--line);border-radius:11px;padding:14px 15px;display:flex;align-items:center;gap:12px;box-shadow:0 12px 35px #0004}.stat-icon{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-size:20px;background:#14b8a61c;color:#99f6e4;border:1px solid #14b8a644}.stat-card:nth-child(2) .stat-icon{background:#22c55e16;color:#34d399;border-color:#22c55e44}.stat-card:nth-child(3) .stat-icon{background:#22d3ee16;color:#67e8f9;border-color:#22d3ee44}.stat-card:nth-child(4) .stat-icon{background:#ef444416;color:#f87171;border-color:#ef444444}.stat-label{font-size:10px;color:#94a3b8;letter-spacing:1px;text-transform:uppercase}.stat-number{font:700 22px 'Share Tech Mono';margin-top:3px}.stat-sub{font-size:9px;color:#64748b;margin-top:2px}
.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:8px 0 10px}.panel-head h2{font-size:15px}.panel-head p{font-size:10px;color:var(--muted)}.panel-tools{display:flex;gap:8px}.search{width:250px;background:#090d18;border:1px solid var(--line);color:#e2e8f0;padding:9px 11px;border-radius:8px;outline:none;font-size:11px}.search:focus{border-color:#0e7490}
#accounts-wrap{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;align-items:start}.acc-card{background:linear-gradient(145deg,#0b1518,#090d18);border:1px solid #1a343a;border-radius:12px;overflow:hidden;min-width:0;box-shadow:0 15px 40px #0005;transition:.18s}.acc-card:hover{border-color:#0e7490;transform:translateY(-1px)}.acc-header{display:flex;align-items:center;gap:9px;padding:11px 12px;background:#0c111e;cursor:pointer}.status-dot{width:8px;height:8px;border-radius:50%;flex:none}.dot-on{background:var(--green);box-shadow:0 0 10px #22c55eaa}.dot-off{background:#64748b}.dot-cooldown{background:var(--amber);box-shadow:0 0 10px #f97316aa}.acc-name{font-weight:800;font-size:24px;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-shadow:0 0 5px currentColor,0 0 12px currentColor,0 0 25px currentColor}.acc-runtime{font:10px 'Share Tech Mono';color:#64748b}.acc-btns{display:flex;gap:5px;margin-left:auto}.acc-btns .btn{padding:6px 8px;font-size:9px}
.stats-row{display:grid;grid-template-columns:repeat(5,1fr);background:#090d16;border-top:1px solid var(--line)}.stat{padding:9px 4px;text-align:center;border-right:1px solid var(--line)}.stat:last-child{border-right:0}.stat-val{font:700 16px 'Share Tech Mono'}.stat-lbl{font-size:8px;color:#64748b;letter-spacing:.7px;margin-top:3px}.c-green{color:#34d399}.c-red{color:#f87171}.c-amber{color:#fb923c}.c-purple{color:#67e8f9}.c-blue{color:#67e8f9}
.gc-row{padding:9px 11px;border-top:1px solid var(--line);display:flex;gap:6px;flex-wrap:wrap;align-items:center}.gc-label,.info-key{font-size:8px;color:#64748b;letter-spacing:1px;text-transform:uppercase}.gc-pill{font:9px 'Share Tech Mono';color:#f0abfc;background:#06b6d412;border:1px solid #06b6d433;padding:4px 6px;border-radius:5px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.info-row{padding:9px 11px;border-top:1px solid var(--line);display:flex;flex-direction:column;gap:7px}.info-item{display:grid;grid-template-columns:70px 1fr;gap:6px;font-size:10px}.info-val{color:#cbd5e1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.last-action{padding:9px 11px;border-top:1px solid var(--line);font:10px 'Share Tech Mono';color:#64748b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.last-action span{color:#cbd5e1}.log-panel{display:none;border-top:1px solid var(--line);background:#05070d}.log-panel.open{display:block}.log-header{display:flex;justify-content:space-between;padding:7px 10px;border-bottom:1px solid var(--line)}.log-title{font:9px 'Share Tech Mono';color:#64748b;letter-spacing:1px}.log-live{font-size:9px;color:#34d399}.log-box{height:180px;overflow:auto;padding:8px;font:9px/1.6 'Share Tech Mono';color:#78939a}.log-line.ok{color:#34d399}.log-line.err{color:#f87171}.log-line.warn{color:#fb923c}.log-line.info{color:#67e8f9}.log-line.round{color:#22d3ee}
.empty{grid-column:1/-1;text-align:center;padding:80px 20px;color:#64748b;border:1px dashed #18343a;border-radius:12px;background:#090d16}.empty-icon{font-size:36px;opacity:.5;margin-bottom:10px}.empty-text{font:12px 'Share Tech Mono';letter-spacing:2px}
.bottom-grid{display:grid;grid-template-columns:1.2fr 1fr 1fr;gap:12px;margin-top:18px}.mini-panel{background:linear-gradient(145deg,#0b1518,#090d18);border:1px solid var(--line);border-radius:11px;padding:14px}.mini-title{font-size:12px;font-weight:600;margin-bottom:12px}.mini-line{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #14282d;font-size:10px}.mini-line:last-child{border-bottom:0}.mini-key{color:#64748b}.mini-val{color:#cbd5e1}.quick{display:flex;gap:7px;flex-wrap:wrap}.quick .btn{flex:1;min-width:90px}

.modal-overlay{display:none;position:fixed;inset:0;background:#02040bdd;backdrop-filter:blur(9px);z-index:1000;align-items:center;justify-content:center}.modal-overlay.open{display:flex}.modal{background:#0b101c;border:1px solid #0e7490;border-radius:13px;padding:24px;width:680px;max-width:96vw;max-height:92vh;overflow-y:auto;box-shadow:0 30px 100px #000}.modal::-webkit-scrollbar{width:4px}.modal::-webkit-scrollbar-thumb{background:#155e75}.modal-title{font:18px 'Share Tech Mono';color:#99f6e4;letter-spacing:2px;margin-bottom:20px;border-bottom:1px solid var(--line);padding-bottom:12px}.form-section{margin-bottom:18px}.form-section-title{font-size:10px;color:var(--cyan);letter-spacing:1.7px;text-transform:uppercase;margin-bottom:9px}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:11px}.form-group{display:flex;flex-direction:column;gap:5px}.form-group.full{grid-column:1/-1}label{font-size:9px;color:#7f9aa3;letter-spacing:1px;text-transform:uppercase}input,textarea,select{background:#080c15;border:1px solid #1a353b;color:#e2e8f0;padding:9px 10px;font:11px 'Share Tech Mono';outline:none;width:100%;border-radius:7px}input:focus,textarea:focus{border-color:#0e7490}textarea{resize:vertical;min-height:70px}.hint{font-size:9px;color:#64748b}.fetch-row{display:flex;gap:9px;align-items:flex-end}.btn-fetch{background:#111827;border:1px solid #0891b2;color:#67e8f9;padding:9px 12px;border-radius:7px;cursor:pointer;font:10px 'Share Tech Mono'}.gc-picker{margin-top:9px;display:none}.gc-picker-title{font-size:9px;color:#64748b;margin-bottom:7px;text-transform:uppercase}.gc-list{display:flex;flex-direction:column;gap:5px;max-height:190px;overflow:auto}.gc-item{display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid #1a353b;background:#090d16;border-radius:7px;cursor:pointer}.gc-item:hover,.gc-item.selected{border-color:#0e7490;background:#151027}.gc-item input[type=checkbox]{width:auto}.gc-item-name{font:10px 'Share Tech Mono';flex:1}.gc-item-id{font-size:8px;color:#64748b}.gc-count{font:9px 'Share Tech Mono';color:#fb923c;margin-top:5px}.msgs-wrap{display:flex;flex-direction:column;gap:7px}.msg-row{display:flex;gap:7px}.msg-row textarea{flex:1}.btn-icon{background:#0a0e18;border:1px solid #1a353b;color:#64748b;padding:8px 10px;border-radius:6px;cursor:pointer}.btn-add-msg{margin-top:7px;background:transparent;border:1px dashed #5b3ba3;color:#67e8f9;padding:7px 10px;border-radius:7px;cursor:pointer;font:10px 'Share Tech Mono'}.modal-footer{display:flex;justify-content:flex-end;gap:8px;border-top:1px solid var(--line);padding-top:15px}.btn-save{background:linear-gradient(135deg,#0f766e,#14b8a6);border:1px solid #67e8f9;color:#fff;padding:10px 24px;border-radius:7px;cursor:pointer;font:11px 'Share Tech Mono';letter-spacing:1px}.btn-cancel{background:transparent;border:1px solid #475569;color:#94a3b8;padding:10px 18px;border-radius:7px;cursor:pointer;font:10px 'Share Tech Mono'}
@media(max-width:1100px){ #accounts-wrap{grid-template-columns:repeat(2,minmax(0,1fr))}.stats{grid-template-columns:repeat(2,1fr)}}
@media(max-width:760px){.sidebar{width:58px;padding:10px 7px}.brand{justify-content:center;padding:7px 0 18px}.brand-name,.brand-sub,.nav-label,.side-bottom{display:none}.brand-mark{width:36px;height:36px}.nav-item{justify-content:center;padding:10px 0}.nav-icon{width:auto}.main{margin-left:58px;width:calc(100% - 58px);padding:12px 10px 24px}.topbar{align-items:flex-start}.top-title h1{font-size:18px}.system-pill{display:none}.stats{grid-template-columns:repeat(2,1fr);gap:8px}.stat-card{padding:10px}.stat-icon{width:34px;height:34px}.stat-number{font-size:18px}.panel-head{align-items:stretch;flex-direction:column}.search{width:100%}.panel-tools{width:100%}.panel-tools .btn-add{flex:1}#accounts-wrap{grid-template-columns:1fr}.acc-btns{flex-wrap:wrap}.acc-btns .btn{padding:6px 7px}.bottom-grid{grid-template-columns:1fr}.form-grid{grid-template-columns:1fr}.form-group.full{grid-column:auto}.fetch-row{align-items:stretch;flex-direction:column}.modal{padding:16px}}

.tg-section{margin-top:18px}.tg-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:12px}.tg-card{min-height:150px}.tg-list{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.tg-bot{border:1px solid var(--line);background:linear-gradient(145deg,#0b1015,#080b10);border-radius:12px;padding:14px}.tg-bot-head{display:flex;align-items:center;gap:10px}.tg-dot{width:9px;height:9px;border-radius:50%;background:#64748b}.tg-dot.on{background:#22c55e;box-shadow:0 0 10px #22c55e99}.tg-name{font:14px 'Share Tech Mono';color:#99f6e4;flex:1}.tg-meta{font-size:10px;color:#64748b}.tg-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.tg-users-list{margin-top:10px;color:#94a3b8;font:11px 'Share Tech Mono';line-height:1.8}.tg-token{color:#64748b;font:10px 'Share Tech Mono';margin-top:7px}.tg-empty{border:1px dashed #334155;padding:20px;border-radius:10px;text-align:center;color:#64748b}.tg-modal-note{font-size:10px;color:#64748b;margin-top:5px}@media(max-width:760px){.tg-grid,.tg-list{grid-template-columns:1fr}}

:root{--bg:#05070a!important;--bg2:#0a0e13!important;--card:#101820!important;--card2:#141c24!important;--line:#394650!important;--purple:#8b1235!important;--purple2:#b9975b!important;--cyan:#58d9f2!important;--text:#eee6d8!important;--muted:#89939c!important}
body{background:radial-gradient(circle at 70% -10%,#24475b2b,transparent 35%),repeating-linear-gradient(125deg,#ffffff03 0 2px,transparent 2px 7px),linear-gradient(135deg,#050609,#0a1117)!important}
.sidebar{width:205px!important;background:linear-gradient(180deg,#17171a,#0b0d11 60%,#171014)!important;border-right:1px solid #5b5157!important;box-shadow:10px 0 35px #0009!important}
.brand{padding:10px 8px 26px!important}.brand-mark{background:linear-gradient(145deg,#606a73,#161c22)!important;border:1px solid #c4a96c!important;color:#e6d7ad!important;box-shadow:0 0 24px #000!important}.brand-name{color:#d4b56e!important;font-size:18px!important}.brand-sub{color:#9ba3a9!important}
.nav-item{border-radius:7px!important;color:#9ba3aa!important}.nav-item:hover,.nav-item.active{background:linear-gradient(90deg,#7f123022,#b9975b0d)!important;border-color:#a9874e55!important;color:#f0e2c4!important}.nav-icon{color:#c5a868!important}.nav-icon img{width:100%;height:100%;display:block;object-fit:contain;pointer-events:none}
.main{margin-left:205px!important;padding:22px 28px 34px!important}.top-title h1{font-family:'Share Tech Mono'!important;letter-spacing:3px!important;color:#dfc27c!important}.top-title p{color:#909aa2!important}.system-pill{border-color:#4d6c78!important;background:#07131a!important;color:#59d9a4!important}.btn-add,.btn-save{background:linear-gradient(135deg,#72102c,#9f1c3f)!important;border-color:#c7a96a!important;box-shadow:0 7px 20px #7d173633!important}.btn-fetch,.btn-logs,.btn-edit{border-color:#a9874e66!important;color:#dfc991!important;background:#151a1f!important}.stat-card,.acc-card,.tg-card,.tg-bot,.mini-panel,.form-section{background:linear-gradient(145deg,#151e26f7,#090e13f7)!important;border-color:#45515b!important;box-shadow:0 15px 40px #0008,inset 0 1px #fff1!important}.stat-card,.acc-card,.tg-card,.tg-bot,.form-section{border-radius:13px!important}.stat-icon{background:#b9975b14!important;border-color:#b9975b55!important;color:#e1ca90!important}.acc-header{background:linear-gradient(90deg,#111920,#0a0f14)!important;border-bottom:1px solid #44515a!important}.acc-name{color:#ead6a8!important;text-shadow:0 0 10px #b9975b44!important}.gc-pill{color:#d5bd83!important;background:#8b123514!important;border-color:#b9975b44!important}.last-action{color:#7e8b94!important}.modal{background:#0d1319!important;border-color:#9a7c47!important}.modal-title{color:#e2c783!important}.form-section-title{color:#d1b46f!important}.gc-item:hover,.gc-item.selected{border-color:#9a7c47!important;background:#24141b!important}
@media(max-width:760px){.sidebar{width:58px!important}.main{margin-left:58px!important;width:calc(100% - 58px)!important}}


.tg-frame-wrap{width:100%;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:#050505;box-shadow:0 18px 50px #0006}
.tg-frame{display:block;width:100%;height:860px;border:0;background:#050505}
@media(max-width:760px){.tg-frame{height:calc(100vh - 120px);min-height:720px}}

:root{--uma-bg:#070910;--uma-panel:#0c101a;--uma-panel-2:#101522;--uma-line:#202a3a;--uma-accent:#8b5cf6;--uma-accent-2:#22d3ee;--uma-text:#eef2ff;--uma-muted:#8d99ad}
html{background:var(--uma-bg)!important}
body{background:radial-gradient(900px 420px at 8% -5%,rgba(139,92,246,.13),transparent 55%),radial-gradient(700px 360px at 95% 0%,rgba(34,211,238,.08),transparent 52%),linear-gradient(180deg,#070910,#05070c)!important;color:var(--uma-text)!important}
.sidebar,.topbar,.panel,.stat-card,.acc-card,.tg-card,.tg-bot,.gc-picker,.form-section{background:linear-gradient(145deg,rgba(14,19,30,.98),rgba(8,11,18,.98))!important;border-color:rgba(139,92,246,.20)!important;box-shadow:0 12px 32px rgba(0,0,0,.22),inset 0 1px 0 rgba(255,255,255,.025)!important}
.topbar{backdrop-filter:blur(14px);border-bottom-color:rgba(139,92,246,.22)!important}
.stat-card,.acc-card,.tg-card,.tg-bot,.form-section{border-radius:16px!important}
.btn-add,.btn-save{background:linear-gradient(135deg,#6d28d9,#8b5cf6)!important;border-color:rgba(196,181,253,.35)!important;box-shadow:0 8px 22px rgba(124,58,237,.20)!important}
.btn-fetch,.btn-logs,.btn-edit{border-color:rgba(139,92,246,.38)!important;color:#c4b5fd!important;background:rgba(139,92,246,.045)!important}
input,textarea,select{background:#080c13!important;border-color:#253247!important;color:#eef2ff!important;border-radius:12px!important}
input::placeholder,textarea::placeholder{color:#66738a!important}
input:focus,textarea:focus,select:focus{border-color:#8b5cf6!important;box-shadow:0 0 0 3px rgba(139,92,246,.10),0 0 18px rgba(139,92,246,.07)!important}
button{transition:transform .16s ease,box-shadow .16s ease,background .16s ease}
button:active{transform:translateY(1px)}
.badge,.status,.pill{border-radius:999px!important}


.acc-header{padding:14px 15px!important;gap:11px!important;min-height:64px!important}
.acc-name{font-size:26px!important;font-weight:800!important;line-height:1.15!important;letter-spacing:.4px!important;color:#f1dfb9!important;display:block!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important}
.status-dot{width:10px!important;height:10px!important}
.acc-runtime{font-size:10px!important;flex:none!important}
@media(max-width:760px){.acc-header{padding:13px!important;min-height:60px!important}.acc-name{font-size:22px!important}}

.sidebar{width:178px!important;background:linear-gradient(180deg,#151416,#0b0c0f 65%,#171116)!important;border-right:1px solid #4b443d!important;box-shadow:12px 0 40px #0009!important}.brand{padding:12px 8px 12px!important}.brand-mark{display:none!important}.gc-creator-icon{font-size:28px!important;line-height:1!important;width:22px!important;height:22px!important;display:flex!important;align-items:center!important;justify-content:center!important;color:#c5a868!important;font-weight:400!important}.brand-mark{background:linear-gradient(145deg,#6f6870,#17191d)!important;border:1px solid #c4a96c!important;color:#ead8a6!important;box-shadow:0 8px 25px #000!important}.brand-name{color:#d8bb78!important;letter-spacing:1.5px!important}.brand-sub{color:#8f9296!important}.nav{gap:8px!important}.nav-item{padding:13px 12px!important;border-radius:10px!important;color:#989da3!important}.nav-item:hover,.nav-item.active{background:linear-gradient(90deg,#7b173022,#c09d5a10)!important;border-color:#b9975b55!important;color:#f1dfb9!important}.nav-icon{color:#c5a868!important}.main{margin-left:178px!important;padding:26px 30px 40px!important}.topbar{padding:14px 0 18px!important;border-bottom:1px solid #3b3f45!important}.top-title h1{font-family:'Playfair Display',serif!important;color:#e2c783!important;letter-spacing:2px!important;font-size:26px!important}.top-title p{letter-spacing:2px!important}.stat-card,.acc-card,.tg-card,.tg-bot,.mini-panel{background:linear-gradient(145deg,#15181d,#0b0e12)!important;border-color:#3d434a!important;border-radius:15px!important;box-shadow:0 18px 45px #0007!important}.btn-add,.btn-save{background:linear-gradient(135deg,#71132f,#9b1b3e)!important;border-color:#c6a667!important}.btn{border-color:#3e454c!important}.btn:hover{border-color:#b9975b!important;box-shadow:0 0 18px #b9975b22!important}@media(max-width:760px){.sidebar{width:58px!important}.main{margin-left:58px!important;width:calc(100% - 58px)!important;padding:16px 12px 28px!important}}
.gc-creator-modal{width:620px}.gc-job-status{min-height:20px;margin:0 0 10px;color:#cbd5e1;font:10px 'Share Tech Mono'}.gc-job-log{height:150px;overflow:auto;padding:10px;border:1px solid rgba(255,255,255,.12);border-radius:10px;background:rgba(0,0,0,.18);color:#a8b3bd;font:9px/1.7 'Share Tech Mono';white-space:pre-wrap}.gc-job-log:empty{display:none}


html,body{
  min-height:100%;
  background:transparent!important;
}
body{
  overflow-x:hidden;
  color:#eef2ff;
}


#atc-panel-background{
  position:fixed!important;
  inset:0!important;
  width:100vw!important;
  height:100vh!important;
  display:block!important;
  z-index:0!important;
  background:#000!important;
  pointer-events:none!important;
}


#atc-panel-overlay{
  position:fixed!important;
  inset:0!important;
  z-index:1!important;
  pointer-events:none!important;
  background:
    radial-gradient(circle at 50% 0%,rgba(255,255,255,.055),transparent 42%),
    linear-gradient(180deg,rgba(0,0,0,.08),rgba(0,0,0,.24));
}

.shell{
  position:relative!important;
  z-index:2!important;
  background:transparent!important;
}


.main,
.sidebar{
  background:transparent!important;
}


.sidebar,
.topbar,
.stat-card,
.acc-card,
.acc-header,
.stats-row,
.gc-row,
.info-row,
.last-action,
.log-panel,
.empty,
.mini-panel,
.modal,
.form-section,
.gc-picker,
.gc-item,
.btn,
.search,
.system-pill{
  background:rgba(10,14,20,.28)!important;
  border-color:rgba(255,255,255,.16)!important;
  box-shadow:
    0 18px 55px rgba(0,0,0,.25),
    inset 0 1px 0 rgba(255,255,255,.14),
    inset 0 -1px 0 rgba(255,255,255,.035)!important;
  backdrop-filter:blur(10px) saturate(125%)!important;
  -webkit-backdrop-filter:blur(10px) saturate(125%)!important;
}

.sidebar{
  background:rgba(5,8,13,.34)!important;
  border-right-color:rgba(255,255,255,.13)!important;
}

.topbar{
  background:rgba(8,10,16,.22)!important;
}

.stat-card,
.acc-card,
.mini-panel,
.modal{
  border-radius:18px!important;
}

.acc-header{
  background:rgba(255,255,255,.055)!important;
}

.stats-row,
.gc-row,
.info-row,
.last-action,
.log-panel{
  background:rgba(0,0,0,.13)!important;
}

.empty{
  background:rgba(0,0,0,.13)!important;
}

input,textarea,select,.search{
  background:rgba(0,0,0,.20)!important;
  border-color:rgba(255,255,255,.15)!important;
  backdrop-filter:blur(8px)!important;
  -webkit-backdrop-filter:blur(8px)!important;
}

.btn{
  background:rgba(255,255,255,.055)!important;
}
.btn:hover{
  background:rgba(255,255,255,.11)!important;
  border-color:rgba(255,255,255,.35)!important;
}
.btn-add,.btn-save{
  background:linear-gradient(135deg,rgba(255,255,255,.20),rgba(255,255,255,.07))!important;
  border-color:rgba(255,255,255,.40)!important;
}
.nav-item.active,.nav-item:hover{
  background:rgba(255,255,255,.09)!important;
  border-color:rgba(255,255,255,.16)!important;
}

.modal-overlay{
  background:rgba(0,0,0,.38)!important;
  backdrop-filter:blur(6px)!important;
  -webkit-backdrop-filter:blur(6px)!important;
}

</style>
</head>
<body>
<canvas id="atc-panel-background" aria-hidden="true"></canvas>
<div id="atc-panel-overlay" aria-hidden="true"></div>
<div class="shell">
<aside class="sidebar">
  <div class="brand"><div><div class="brand-name">DAKSH SX7</div><div class="brand-sub">PANEL</div></div></div>
  <nav class="nav">
    <a class="nav-item active" href="/"><span class="nav-icon"><img src="https://cdn.21st.dev/assets/mirror/99/9963f31f43cd77b0c28981ba7bac04db749a5749019f554d1afb75225a3e9151.png" alt="" aria-hidden="true"></span><span class="nav-label">Home</span></a>
    <a class="nav-item" href="/instagram"><span class="nav-icon"><img src="https://cdn.21st.dev/assets/mirror/d5/d558230225bb0dd1897db6c7cf0d03b29506eef8078fe25313c48cd8f72d05ad.png" alt="" aria-hidden="true"></span><span class="nav-label">Instagram</span></a>
    <a class="nav-item" href="/contact"><span class="nav-icon"><img src="https://cdn.21st.dev/assets/mirror/7b/7bb8671183d2a2bbb8a3858b1971cc5699ba0103673b011590d22f0fa309bb87.png" alt="" aria-hidden="true"></span><span class="nav-label">Contact</span></a>
    <a class="nav-item" href="/gc-creator"><span class="nav-icon gc-creator-icon">＋</span><span class="nav-label">GC Creator</span></a>
  </nav>
  <div class="side-bottom"><div class="side-owner"><strong>DAKSH SX7</strong>PANEL • v2.0</div></div>
</aside>
<main class="main" id="dashboard">
  <div class="topbar panel-top">
    <div class="panel-brand">
      <h1>DAKSH <span>SX7</span></h1>
      <div class="logged-user">YOUR USERNAME • <b>{{ login_username }}</b></div>
    </div>
    <div class="top-actions">
      <button class="btn" onclick="loadAccounts()">↻ REFRESH</button>
    </div>
  </div>
  <section class="stats">
    <div class="stat-card"><div><div class="stat-label">Total IDs</div><div class="stat-number" id="h-accounts">0</div></div></div>
    <div class="stat-card"><div><div class="stat-label">Active IDs</div><div class="stat-number" id="h-running">0</div></div></div>
    <div class="stat-card"><div><div class="stat-label">Uptime</div><div class="stat-number" id="h-uptime">00:00:00</div></div></div>
    <div class="stat-card"><div><div class="stat-label">VERSION</div><div class="stat-number username-stat">INSTAGRAM</div></div></div>
  </section>
  <section id="accounts">
    <div class="panel-head"><div><h2>Instagram IDs</h2><p>{% if login_role == 'admin' %}ADMIN VIEW • ALL USERS' IDS ARE SHOWN HERE.{% else %}YOUR IDS ARE SHOWN HERE{% endif %}</p></div><div class="panel-tools"><input id="accountSearch" class="search" placeholder="Search ID..." oninput="filterCards(this.value)"/><button class="btn btn-add" onclick="openAddModal()">＋ ADD ID</button></div></div>
    <div id="accounts-wrap"></div>
  </section>
</main>
</div>


<div class="modal-overlay" id="gc-creator">
  <div class="modal gc-creator-modal">
    <div class="modal-title">GC CREATOR</div>
    <div class="form-section">
      <div class="form-section-title">Instagram ID</div>
      <div class="form-grid">
        <div class="form-group full">
          <label>SELECT ID</label>
          <select id="gc-account"></select>
          <div class="hint">The selected saved Instagram ID supplies the session.</div>
        </div>
        <div class="form-group">
          <label>GCs TO CREATE</label>
          <input id="gc-count-input" type="number" min="1" max="50" value="1"/>
        </div>
        <div class="form-group">
          <label>REMOVE USERNAME</label>
          <input id="gc-remove-user" type="text" placeholder="username"/>
        </div>
        <div class="form-group full">
          <label>USERNAMES</label>
          <textarea id="gc-users" rows="4" placeholder="user1, user2, user3"></textarea>
          <div class="hint">Separate usernames with commas. Minimum 2 users.</div>
        </div>
      </div>
    </div>
    <div class="gc-job-status" id="gc-job-status"></div>
    <div class="gc-job-log" id="gc-job-log"></div>
    <div class="modal-footer">
      <button class="btn-cancel" onclick="closeGCCreator()">CANCEL</button>
      <button class="btn-save" id="gc-start-btn" onclick="startGCCreator()">CREATE GCs</button>
    </div>
  </div>
</div>
<div class="modal-overlay" id="modal">
<div class="modal">
  <div class="modal-title" id="modal-title">Add Account</div>

  
  <div class="form-section">
    <div class="form-section-title">Account</div>
    <div class="form-grid">
      <div class="form-group"><label>ID USERNAME</label><input type="text" id="f-name" placeholder="ID USERNAME"/></div>
      <div class="form-group"><label>SCRIPT</label><select id="f-method" onchange="handleMethodChange()"><option value="INSTAGRAPI">INSTAGRAPI</option><option value="PUPPETEER">PUPPETEER</option><option value="PLAYWRIGHT">PLAYWRIGHT</option><option value="AYAN MULTI GC">AYAN MULTI GC</option><option value="RAVAN MULTI GC">RAVAN MULTI GC</option><option value="RAVAN">RAVAN</option></select><div class="hint">CHOOSE 1</div></div>
      <div class="form-group"><label>SESSIONID</label><input type="text" id="f-sid" placeholder="sessionid" autocomplete="off"/></div>
      <div class="form-group"><label>CSRFT TOKEN<span style="opacity:.5;font-weight:400">(optional)</span></label><input type="text" id="f-csrf" placeholder="csrftoken" autocomplete="off"/></div>
      <div class="form-group full"><label>PROXY<span style="opacity:.5;font-weight:400">(optional)</span></label><input type="text" id="f-proxy" placeholder="http://user:pass@ip:port"/></div>
    </div>
  </div>

  
  <div class="form-section">
    <div class="form-section-title" id="groups-section-title">Group Chats (Max 5)</div>
    <div class="fetch-row">
      <div class="form-group" style="flex:1">
        <label>Session ID for Fetch</label>
      </div>
      <button class="btn-fetch" onclick="fetchGroups()">⚡ FETCH GCs</button>
    </div>
    <div id="fetch-status"></div>
    <div class="gc-picker" id="gc-picker">
      <div class="gc-picker-title" id="gc-picker-title">Select up to 5 GCs</div>
      <div id="gc-select-all-wrap" style="display:none;justify-content:flex-end;margin:8px 0;">
        <button type="button" class="btn-fetch" id="gc-select-all-btn" onclick="toggleSelectAllGCs()">SELECT ALL</button>
      </div>
      <div class="gc-list" id="gc-list"></div>
      <div class="gc-count" id="gc-count">0 / 5 selected</div>
    </div>
    
    <textarea id="f-groups" style="display:none"></textarea>
  </div>

  
  <div class="form-section">
    <div class="form-section-title">NC TITLES</div>
    <div class="form-grid">
      <div class="form-group full">
        <label>Titles (comma separated)</label>
        <input type="text" id="f-titles" placeholder="Title1, Title2, Title3"/>
        <div class="hint">NC will rotate through these titles every round</div>
      </div>
    </div>
  </div>

  
  <div class="form-section">
    <div class="form-section-title">Messages</div>
    <div class="form-grid">
      <div class="form-group full">
        <label>Message Type</label>
        <select id="f-message-mode" onchange="toggleMessageMode()">
          <option value="DAKSH">DAKSH SX7 TEXT</option>
          <option value="CUSTOM">CUSTOM MESSAGE</option>
        </select>
      </div>
      <div class="form-group full" id="target-name-wrap">
        <label>Target Name</label>
        <input type="text" id="f-target-name" placeholder="Target name"/>
        <div class="hint">OG DAKSH TEXT</div>
      </div>
    </div>
    <div id="custom-message-wrap" style="display:none;margin-top:10px">
      <div class="msgs-wrap" id="msgs-wrap"></div>
      <button class="btn-add-msg" onclick="addMsgField()">+ ADD MESSAGE</button>
    </div>
  </div>

  
  <div class="form-section" id="delay-section">
    <div class="form-section-title">Delays</div>
    <div class="form-grid">
      <div class="form-group">
        <label>Min Delay Between Messages (s)</label>
        <input type="number" id="f-msg-min" value="2" min="0" step="0.5"/>
      </div>
      <div class="form-group">
        <label>Max Delay Between Messages (s)</label>
        <input type="number" id="f-msg-max" value="5" min="0" step="0.5"/>
      </div>
      <div class="form-group">
        <label>NC After N Messages</label>
        <input type="number" id="f-nc-every-msgs" value="0" min="0"/>
        <div class="hint">0 = only at start</div>
      </div>
      <div class="form-group">
        <label>Cooldown After N Messages</label>
        <input type="number" id="f-cooldown-after" value="0" min="0"/>
        <div class="hint">0 = disabled</div>
      </div>
      <div class="form-group">
        <label>Cooldown Duration (minutes)</label>
        <input type="number" id="f-cooldown-dur" value="5" min="1"/>
      </div>
    </div>
  </div>

  <div class="modal-footer">
    <button class="btn-cancel" onclick="closeModal()">CANCEL</button>
    <button class="btn-save" onclick="saveAccount()">SAVE</button>
  </div>
</div>
</div>

<script>
let accounts = {};
let editingId = null;
const USER_REGISTERED_AT = Number({{ user_created_at_epoch|default(0)|tojson }});
let fetchedGroups = [];
let selectedGCs = [];

async function fetchGroups() {
  const sid = document.getElementById('f-sid').value.trim();
  if (!sid) { alert('Enter Session ID first'); return; }
  const proxy = document.getElementById('f-proxy').value.trim();
  const statusEl = document.getElementById('fetch-status');
  statusEl.textContent = '⚡ Fetching...';
  statusEl.style.color = '#f97316';
  try {
    const r = await fetch('/api/fetch-groups', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({session_id: sid, acc_id: editingId || 'fetch_temp', proxy: proxy, method: document.getElementById('f-method').value})
    });
    const d = await r.json();
    if (d.groups && d.groups.length > 0) {
      fetchedGroups = d.groups;
      statusEl.textContent = `✅ ${d.groups.length} GCs found`;
      statusEl.style.color = '#00cc44';
      renderGCPicker();
    } else {
      statusEl.textContent = '⚠️ No GCs found';
      statusEl.style.color = '#f97316';
    }
  } catch(e) {
    statusEl.textContent = `❌ Error: ${e.message}`;
    statusEl.style.color = '#ef4444';
  }
}

function isMultiMethod() {
  const m = document.getElementById('f-method').value;
  return m === 'AYAN MULTI GC' || m === 'RAVAN MULTI GC';
}

function getGroupSelectionLimit() {
  const m = document.getElementById('f-method').value;
  if (isMultiMethod()) return 50;
  return m === 'RAVAN' ? 1 : 5;
}

function handleMethodChange() {
  const method = document.getElementById('f-method').value;
  const limit = getGroupSelectionLimit();
  const title = document.getElementById('groups-section-title');
  const pickerTitle = document.getElementById('gc-picker-title');
  const selectAllWrap = document.getElementById('gc-select-all-wrap');
  const delaySection = document.getElementById('delay-section');

  if (isMultiMethod()) {
    title.textContent = method === 'AYAN MULTI GC' ? 'Group Chats (AYAN MULTI GC)' : 'Group Chats (RAVAN MULTI GC)';
    pickerTitle.textContent = 'Select GCs (up to 50)';
    selectAllWrap.style.display = 'flex';
    delaySection.style.display = 'none';
  } else if (method === 'RAVAN') {
    title.textContent = 'Group Chat (RAVAN)';
    pickerTitle.textContent = 'Select 1 GC';
    selectAllWrap.style.display = 'none';
    delaySection.style.display = '';
    if (selectedGCs.length > 1) selectedGCs = selectedGCs.slice(0, 1);
  } else {
    title.textContent = 'Group Chats (Max 5)';
    pickerTitle.textContent = 'Select up to 5 GCs';
    selectAllWrap.style.display = 'none';
    delaySection.style.display = '';
    if (selectedGCs.length > limit) selectedGCs = selectedGCs.slice(0, limit);
  }

  renderGCPicker();
  syncGroupsField();
}

function renderGCPicker() {
  const picker = document.getElementById('gc-picker');
  const list = document.getElementById('gc-list');
  picker.style.display = 'block';
  list.innerHTML = '';
  fetchedGroups.forEach(g => {
    const isSelected = selectedGCs.some(s => s.id === g.id);
    const item = document.createElement('div');
    item.className = 'gc-item' + (isSelected ? ' selected' : '');
    item.innerHTML = `
      <input type="checkbox" ${isSelected ? 'checked' : ''} data-id="${g.id}" data-name="${g.name}"/>
      <span class="gc-item-name">${g.name}</span>
    `;
    const cb = item.querySelector('input');
    cb.addEventListener('change', () => toggleGC(
      (document.getElementById('f-method').value === 'RAVAN' || document.getElementById('f-method').value === 'RAVAN MULTI GC') && g.web_thread_id ? g.web_thread_id : g.id,
      g.name, cb, item
    ));
    list.appendChild(item);
  });
  document.getElementById('gc-select-all-wrap').style.display = isMultiMethod() ? 'flex' : 'none';
  updateGCCount();
  updateSelectAllButton();
}

function toggleGC(id, name, cb, item) {
  const limit = getGroupSelectionLimit();
  if (cb.checked) {
    if (selectedGCs.length >= limit) {
      cb.checked = false;
      alert(limit === 1 ? 'RAVAN allows only 1 selected GC' : 'Max 50 GCs allowed');
      return;
    }
    if (!selectedGCs.some(s => s.id === id)) selectedGCs.push({id, name});
    item.classList.add('selected');
  } else {
    selectedGCs = selectedGCs.filter(s => s.id !== id);
    item.classList.remove('selected');
  }
  updateGCCount();
  syncGroupsField();
}

function selectAllGCs() {
  if (!isMultiMethod()) return;
  const method = document.getElementById('f-method').value;
  selectedGCs = fetchedGroups.slice(0, 50).map(g => ({
    id: ((method === 'RAVAN' || method === 'RAVAN MULTI GC') && g.web_thread_id) ? g.web_thread_id : g.id,
    name: g.name
  }));
  renderGCPicker();
  syncGroupsField();
  updateSelectAllButton();
}

function clearAllGCs() {
  selectedGCs = [];
  renderGCPicker();
  syncGroupsField();
  updateSelectAllButton();
}

function updateSelectAllButton() {
  const btn = document.getElementById('gc-select-all-btn');
  if (!btn || !isMultiMethod()) return;
  const total = Math.min(fetchedGroups.length, 50);
  const selected = selectedGCs.length;
  btn.textContent = total > 0 && selected === total ? 'UNSELECT ALL' : 'SELECT ALL';
}

function toggleSelectAllGCs() {
  if (!isMultiMethod()) return;
  const total = Math.min(fetchedGroups.length, 50);
  if (total > 0 && selectedGCs.length === total) {
    clearAllGCs();
  } else {
    selectAllGCs();
  }
}

function updateGCCount() {
  const limit = getGroupSelectionLimit();
  document.getElementById('gc-count').textContent = `${selectedGCs.length} / ${limit} selected`;
}

function syncGroupsField() {
  document.getElementById('f-groups').value = selectedGCs.map(s => s.id).join('\n');
}

function addMsgField(val = '') {
  const wrap = document.getElementById('msgs-wrap');
  const row = document.createElement('div');
  row.className = 'msg-row';
  row.innerHTML = `
    <textarea placeholder="Message text..." rows="3">${val}</textarea>
    <button class="btn-icon" onclick="this.parentElement.remove()">✕</button>
  `;
  wrap.appendChild(row);
}

function getMsgs() {
  return [...document.querySelectorAll('#msgs-wrap textarea')]
    .map(t => t.value.trim()).filter(Boolean);
}

function setMsgs(raw) {
  document.getElementById('msgs-wrap').innerHTML = '';
  const parts = raw.split('---MSG---').map(s => s.trim()).filter(Boolean);
  if (parts.length === 0) { addMsgField(); return; }
  parts.forEach(p => addMsgField(p));
}

function openAddModal() {
  editingId = null;
  fetchedGroups = [];
  selectedGCs = [];
  document.getElementById('modal-title').textContent = 'Add Instagram ID';
  document.getElementById('f-name').value = '';
  document.getElementById('f-method').value = 'INSTAGRAPI';
  document.getElementById('f-message-mode').value = 'DAKSH';
  document.getElementById('f-target-name').value = '';
  document.getElementById('f-sid').value = '';
  document.getElementById('f-csrf').value = '';
  document.getElementById('f-proxy').value = '';
    document.getElementById('f-msg-min').value = '2';
  document.getElementById('f-msg-max').value = '5';
  document.getElementById('f-nc-every-msgs').value = '0';
  document.getElementById('f-cooldown-after').value = '0';
  document.getElementById('f-cooldown-dur').value = '5';
  document.getElementById('f-groups').value = '';
  document.getElementById('gc-picker').style.display = 'none';
  document.getElementById('gc-list').innerHTML = '';
  document.getElementById('gc-count').textContent = '0 / 5 selected';
  document.getElementById('gc-select-all-btn').textContent = 'SELECT ALL';
  document.getElementById('fetch-status').textContent = '';
  setMsgs('');
  toggleMessageMode();
  document.getElementById('modal').classList.add('open');
}

function openEditModal(id) {
  editingId = id;
  fetchedGroups = [];
  const acc = accounts[id];

  selectedGCs = [];
  const savedGroups = acc.groups ? acc.groups.split('\n').filter(Boolean) : [];
  const savedNames  = acc.group_names ? acc.group_names.split('\n').filter(Boolean) : [];
  savedGroups.forEach((gid, i) => {
    selectedGCs.push({id: gid.trim(), name: savedNames[i] || gid.trim()});
  });

  document.getElementById('modal-title').textContent = 'Edit Instagram ID';
  document.getElementById('f-name').value = acc.name || '';
  document.getElementById('f-method').value = acc.method || 'INSTAGRAPI';
  handleMethodChange();
  document.getElementById('f-message-mode').value = acc.message_mode || 'DAKSH';
  document.getElementById('f-target-name').value = acc.target_name || '';
  document.getElementById('f-sid').value = '';
  document.getElementById('f-sid').placeholder = acc.session_id_set ? 'Session ID already saved — leave blank to keep it' : 'Session ID';
  document.getElementById('f-csrf').value = '';
  document.getElementById('f-csrf').placeholder = acc.csrf_token_set ? 'CSRF token already saved — leave blank to keep it' : 'csrftoken';
  document.getElementById('f-proxy').value = acc.proxy || '';
    document.getElementById('f-msg-min').value = acc.msg_delay_min || '2';
  document.getElementById('f-msg-max').value = acc.msg_delay_max || '5';
  document.getElementById('f-nc-every-msgs').value = acc.nc_every_msgs || '0';
  document.getElementById('f-cooldown-after').value = acc.cooldown_after || '0';
  document.getElementById('f-cooldown-dur').value = acc.cooldown_dur || '5';
  document.getElementById('f-groups').value = savedGroups.join('\n');
  document.getElementById('fetch-status').textContent = '';

  if (selectedGCs.length > 0) {
    fetchedGroups = selectedGCs.map(s => ({id: s.id, name: s.name}));
    renderGCPicker();
  } else {
    document.getElementById('gc-picker').style.display = 'none';
  }

  setMsgs(acc.messages || acc.message || '');
  toggleMessageMode();
  document.getElementById('modal').classList.add('open');
}

function closeModal() {
  document.getElementById('modal').classList.remove('open');
  editingId = null;
}

function toggleMessageMode() {
  const mode = document.getElementById('f-message-mode').value;
  const targetWrap = document.getElementById('target-name-wrap');
  const customWrap = document.getElementById('custom-message-wrap');
  targetWrap.style.display = mode === 'DAKSH' ? 'block' : 'none';
  customWrap.style.display = mode === 'CUSTOM' ? 'block' : 'none';
}

async function saveAccount() {
  const messageMode = document.getElementById('f-message-mode').value;
  const msgs = getMsgs();
  const targetName = document.getElementById('f-target-name').value.trim();
  if (messageMode === 'DAKSH' && !targetName) { alert('Enter Target Name'); return; }
  if (messageMode === 'CUSTOM' && !msgs.length) { alert('Add at least one message'); return; }

  const body = {
    name:            document.getElementById('f-name').value.trim(),
    method:          document.getElementById('f-method').value,
    message_mode:   messageMode,
    target_name:    targetName,
    session_id:     document.getElementById('f-sid').value.trim(),
    csrf_token:     document.getElementById('f-csrf').value.trim(),
    proxy:           document.getElementById('f-proxy').value.trim(),
    groups:          selectedGCs.map(s => s.id).join('\n'),
    group_names:     selectedGCs.map(s => s.name).join('\n'),
    nc_titles:       document.getElementById('f-titles').value.trim(),
    messages:        msgs.join('---MSG---'),
  };

  // Normal methods keep their existing UI timing inputs.
  // AYAN/RAVAN MULTI GC use hardcoded timing in their workers.
  if (!isMultiMethod()) {
    body.msg_delay_min  = document.getElementById('f-msg-min').value;
    body.msg_delay_max  = document.getElementById('f-msg-max').value;
    body.nc_every_msgs  = document.getElementById('f-nc-every-msgs').value;
    body.cooldown_after = document.getElementById('f-cooldown-after').value;
    body.cooldown_dur   = document.getElementById('f-cooldown-dur').value;
  }

  if (!body.name) { alert('Enter ID name'); return; }
  if (isMultiMethod() && selectedGCs.length === 0) { alert('Select at least one GC'); return; }
  if (editingId && !body.session_id) delete body.session_id;
  if (editingId && !body.csrf_token) delete body.csrf_token;

  const url    = editingId ? `/api/accounts/${editingId}` : '/api/accounts';
  const method = editingId ? 'PUT' : 'POST';
  const r = await fetch(url, {method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const d = await r.json();
  if (d.success) {
    closeModal();
    loadAccounts();
  } else {
    alert(d.error || 'Save failed');
  }
}

let gcJobPoll = null;

function openGCCreator() {
  const select = document.getElementById('gc-account');
  select.innerHTML = '';
  Object.entries(accounts).forEach(([id, acc]) => {
    const option = document.createElement('option');
    option.value = id;
    option.textContent = acc.name || id;
    select.appendChild(option);
  });

  document.getElementById('gc-job-status').textContent = '';
  document.getElementById('gc-job-log').textContent = '';
  document.getElementById('gc-count-input').value = '1';
  document.getElementById('gc-users').value = '';
  document.getElementById('gc-remove-user').value = '';
  document.getElementById('gc-start-btn').disabled = false;
  document.getElementById('gc-creator').classList.add('open');
}

function closeGCCreator() {
  document.getElementById('gc-creator').classList.remove('open');
  if (gcJobPoll) {
    clearInterval(gcJobPoll);
    gcJobPoll = null;
  }
}

async function startGCCreator() {
  const accountId = document.getElementById('gc-account').value;
  const count = Number(document.getElementById('gc-count-input').value);
  const users = document.getElementById('gc-users').value
    .split(',')
    .map(x => x.trim().replace(/^@/, ''))
    .filter(Boolean);
  const removeUsername = document.getElementById('gc-remove-user').value.trim().replace(/^@/, '');
  const status = document.getElementById('gc-job-status');
  const logBox = document.getElementById('gc-job-log');
  const button = document.getElementById('gc-start-btn');

  if (!accountId) {
    status.textContent = 'Add an Instagram ID first.';
    return;
  }
  if (!Number.isInteger(count) || count < 1 || count > 50) {
    status.textContent = 'GC count must be between 1 and 50.';
    return;
  }
  if (users.length < 2) {
    status.textContent = 'Enter at least 2 usernames.';
    return;
  }
  if (!removeUsername) {
    status.textContent = 'Enter the username to remove.';
    return;
  }
  if (!users.includes(removeUsername)) {
    status.textContent = 'Remove username must be one of the entered members.';
    return;
  }

  button.disabled = true;
  status.textContent = 'Starting...';
  logBox.textContent = '';

  try {
    const response = await fetch('/api/gc-creator/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        acc_id: accountId,
        group_count: count,
        usernames: users,
        remove_username: removeUsername
      })
    });

    const data = await response.json();

    if (!data.success) {
      status.textContent = data.error || 'Could not start GC Creator.';
      button.disabled = false;
      return;
    }

    status.textContent = 'Running...';
    pollGCJob(data.job_id);
  } catch (e) {
    status.textContent = 'Network error.';
    button.disabled = false;
  }
}

function pollGCJob(jobId) {
  if (gcJobPoll) clearInterval(gcJobPoll);

  const poll = async () => {
    try {
      const response = await fetch(`/api/gc-creator/status/${jobId}`);
      const data = await response.json();

      if (!data.success) {
        document.getElementById('gc-job-status').textContent =
          data.error || 'Could not read job status.';
        return;
      }

      document.getElementById('gc-job-status').textContent =
        data.running ? `Running • ${data.done}/${data.total}` :
        data.error ? `Failed • ${data.done}/${data.total}` :
        `Completed • ${data.done}/${data.total}`;

      document.getElementById('gc-job-log').textContent =
        (data.logs || []).join('\n');

      if (!data.running) {
        clearInterval(gcJobPoll);
        gcJobPoll = null;
        document.getElementById('gc-start-btn').disabled = false;
        loadAccounts();
      }
    } catch (e) {}
  };

  poll();
  gcJobPoll = setInterval(poll, 1500);
}

document.getElementById('gc-creator').addEventListener('click', function(e) {
  if (e.target === this) closeGCCreator();
});

async function startBot(id) {
  const r = await fetch(`/api/accounts/${id}/start`, {method:'POST'});
  const d = await r.json();
  if (!d.success) alert(d.error || 'Start failed');
}

async function stopBot(id) {
  await fetch(`/api/accounts/${id}/stop`, {method:'POST'});
}

async function deleteAcc(id) {
  if (!confirm('Delete this account?')) return;
  await fetch(`/api/accounts/${id}`, {method:'DELETE'});
  loadAccounts();
}

function toggleLogs(id) {
  const el = document.getElementById(`log-panel-${id}`);
  if (el) el.classList.toggle('open');
}

function toggleCollapse(id) {
  const el = document.getElementById(`body-${id}`);
  if (el) el.style.display = el.style.display === 'none' ? '' : 'none';
}

function filterCards(q) { const cards=[...document.querySelectorAll('#accounts-wrap .acc-card')]; q=(q||'').toLowerCase(); cards.forEach(c=>c.style.display=c.innerText.toLowerCase().includes(q)?'':'none'); }

function fmtTime(secs) {
  if (!secs || secs < 0) return '--:--:--';
  const h = Math.floor(secs/3600);
  const m = Math.floor((secs%3600)/60);
  const s = Math.floor(secs%60);
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

function renderAccounts(data) {
  const wrap = document.getElementById('accounts-wrap');
  const ids = Object.keys(data);

  if (ids.length === 0) {
    wrap.innerHTML = `<div class="empty"><div class="empty-text">NO IDS ADDED YET</div></div>`;
    return;
  }

  let totalRunning = 0;
  ids.forEach(id => {
    const st = data[id].status || {};
    if (st.running) totalRunning++;
  });
  document.getElementById('h-accounts').textContent = ids.length;
  document.getElementById('h-running').textContent  = totalRunning;
  const uptime = USER_REGISTERED_AT > 0
    ? Math.max(0, Math.floor(Date.now() / 1000 - USER_REGISTERED_AT))
    : 0;
  document.getElementById('h-uptime').textContent = USER_REGISTERED_AT > 0 ? fmtTime(uptime) : '--:--:--';

  ids.forEach(id => {
    const acc = data[id];
    const st  = acc.status || {};
    const isRunning = st.running;
    const isCooldown = st.cooldown;
    const runtime = st.runtime_secs ? fmtTime(st.runtime_secs) : '--:--:--';
    const cooldownStr = st.cooldown && st.cooldown_remaining > 0
      ? ` 😴 ${fmtTime(st.cooldown_remaining)}`
      : (isCooldown ? ' 😴 COOLDOWN' : '');

    const dotCls = isCooldown ? 'dot-cooldown' : (isRunning ? 'dot-on' : 'dot-off');
    const gcNames = acc.group_names ? String(acc.group_names).split(/\\n|\n/).filter(Boolean) : [];
    const gcIds = acc.groups ? String(acc.groups).split(/\\n|\n/).filter(Boolean) : [];
    const normalizedMethod = String(acc.method || '').trim().toUpperCase();
    const isMultiGC = normalizedMethod === 'AYAN MULTI GC' || normalizedMethod === 'RAVAN MULTI GC';
    const selectedGCCount = gcIds.length || gcNames.length;

    let existing = document.getElementById(`card-${id}`);
    if (!existing) {
      existing = document.createElement('div');
      existing.className = 'acc-card';
      existing.id = `card-${id}`;
      wrap.appendChild(existing);
    }

    const existingLogPanel = document.getElementById(`log-panel-${id}`);
    const logOpen = existingLogPanel ? existingLogPanel.classList.contains('open') : false;

    existing.innerHTML = `
      <div class="acc-header">
        <div class="status-dot ${dotCls}"></div>
        <div class="acc-name">${acc.name || 'Instagram ID'}${cooldownStr ? `<span style="color:var(--amber);font-size:11px;margin-left:10px">${cooldownStr}</span>` : ''}</div>
        <div class="acc-runtime">${runtime}</div>
        <div class="acc-btns">
          ${isRunning
            ? `<button class="btn btn-stop" onclick="stopBot('${id}')">■ STOP</button>`
            : `<button class="btn btn-start" onclick="startBot('${id}')">▶ START</button>`}
          <button class="btn btn-logs" onclick="toggleLogs('${id}')">LOGS</button>
          <button class="btn btn-edit" onclick="openEditModal('${id}')">EDIT</button>
          <button class="btn btn-del" onclick="deleteAcc('${id}')">✕</button>
          <button class="btn-collapse" onclick="toggleCollapse('${id}')">▲</button>
        </div>
      </div>
      <div id="body-${id}">
        <div class="stats-row">
          <div class="stat"><div class="stat-val c-green">${st.sent||0}</div><div class="stat-lbl">Sent</div></div>
          <div class="stat"><div class="stat-val c-red">${st.failed||0}</div><div class="stat-lbl">Failed</div></div>
          <div class="stat"><div class="stat-val c-purple">${st.nc_done||0}</div><div class="stat-lbl">NC Done</div></div>
          <div class="stat"><div class="stat-val c-red">${st.nc_failed||0}</div><div class="stat-lbl">NC Fail</div></div>
          
          <div class="stat"><div class="stat-val c-amber">${st.gcs_done||0}<span style="color:var(--muted);font-size:12px"> / ${st.total_gcs||0}</span></div><div class="stat-lbl">GCs</div></div>
        </div>
        ${isMultiGC ? `
        <div class="gc-row">
          <span class="gc-label">GCs</span>
          <span class="gc-pill">${selectedGCCount}</span>
        </div>` : (gcNames.length ? `
        <div class="gc-row">
          <span class="gc-label">GCs</span>
          ${gcNames.map(n=>`<span class="gc-pill">${n}</span>`).join('')}
        </div>` : '')}
        <div class="info-row">
          <div class="info-item"><span class="info-key">Delay</span><span class="info-val">${(acc.method==='AYAN MULTI GC'||acc.method==='RAVAN MULTI GC') ? 'Send 40s • Rename 180s' : `${acc.msg_delay_min||2}s – ${acc.msg_delay_max||5}s`}</span></div>
          ${acc.cooldown_after > 0 ? `<div class="info-item"><span class="info-key">Cooldown</span><span class="info-val">After ${acc.cooldown_after} msgs → ${acc.cooldown_dur} min pause</span></div>` : ''}
          ${acc.nc_titles ? `<div class="info-item"><span class="info-key">NC</span><span class="info-val">${acc.nc_titles.split(',').length} titles</span></div>` : ''}
        </div>
        <div class="last-action">▸ <span>${st.last_action||'Idle'}</span></div>
        <div class="log-panel ${logOpen ? 'open' : ''}" id="log-panel-${id}">
          <div class="log-header">
            <span class="log-title">📟 CONSOLE LOG</span>
            <span class="log-live">● LIVE</span>
          </div>
          <div class="log-box" id="log-box-${id}"></div>
        </div>
      </div>
    `;
  });

  wrap.querySelectorAll('.acc-card').forEach(el => {
    if (!data[el.id.replace('card-','')]) el.remove();
  });
}

function colorLog(line) {
  if (line.includes('✅') || line.includes('✓')) return 'ok';
  if (line.includes('❌') || line.includes('failed') || line.includes('Failed')) return 'err';
  if (line.includes('⚠️')) return 'warn';
  if (line.includes('🔄') || line.includes('Round')) return 'round';
  if (line.includes('💤') || line.includes('⏭') || line.includes('😴')) return 'info';
  return '';
}

async function loadAccounts() {
  const r = await fetch('/api/accounts');
  accounts = await r.json();
  renderAccounts(accounts);
}

async function pollLogs() {
  const openPanels = document.querySelectorAll('.log-panel.open');
  for (const panel of openPanels) {
    const id = panel.id.replace('log-panel-','');
    try {
      const r = await fetch(`/api/accounts/${id}/logs`);
      const d = await r.json();
      const box = document.getElementById(`log-box-${id}`);
      if (box && d.logs) {
        const currentCount = box.querySelectorAll('.log-line').length;
        if (currentCount === 0) {

          box.innerHTML = d.logs.map(l => `<div class="log-line ${colorLog(l)}">${l}</div>`).join('');
          box.scrollTop = box.scrollHeight;
        } else if (d.logs.length > currentCount) {

          const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
          const newLines = d.logs.slice(currentCount);
          newLines.forEach(l => {
            const div = document.createElement('div');
            div.className = `log-line ${colorLog(l)}`;
            div.textContent = l;
            box.appendChild(div);
          });
          if (atBottom) box.scrollTop = box.scrollHeight;
        } else if (d.logs.length < currentCount) {

          box.innerHTML = d.logs.map(l => `<div class="log-line ${colorLog(l)}">${l}</div>`).join('');
          box.scrollTop = box.scrollHeight;
        }
      }
    } catch(e) {}
  }
}

async function pollStatus() {
  try {
    const r = await fetch('/api/status');
    const st = await r.json();
    Object.keys(st).forEach(id => {
      if (accounts[id]) accounts[id].status = st[id];
    });
    renderAccounts(accounts);
  } catch(e) {}
}

loadAccounts();
setInterval(pollStatus, 2000);
setInterval(() => { const el=document.getElementById('h-uptime'); if(el && USER_REGISTERED_AT > 0) el.textContent=fmtTime(Math.max(0, Math.floor(Date.now()/1000-USER_REGISTERED_AT))); }, 1000);
setInterval(pollLogs, 1500);

document.getElementById('modal').addEventListener('click', function(e) {
  if (e.target === this) closeModal();
});
</script>

<script>

(function(){
  const canvas=document.getElementById('atc-panel-background');
  if(!canvas)return;

  const gl=canvas.getContext('webgl2',{
    premultipliedAlpha:false,
    antialias:false
  });
  if(!gl)return;

  const vertSrc=`#version 300 es
  precision highp float;
  layout(location=0) in vec2 a_pos;
  void main(){ gl_Position=vec4(a_pos,0.0,1.0); }`;

  const fragSrc=`#version 300 es
  precision highp float;
  out vec4 fragColor;

  uniform vec2 u_res;
  uniform float u_time;

  float tanh1(float x){
    float e=exp(2.0*x);
    return(e-1.0)/(e+1.0);
  }
  vec4 tanh4(vec4 v){
    return vec4(tanh1(v.x),tanh1(v.y),tanh1(v.z),tanh1(v.w));
  }

  void main(){
    vec3 FC=vec3(gl_FragCoord.xy,0.0);
    vec3 r=vec3(u_res,max(u_res.x,u_res.y));
    float t=u_time;

    vec4 o=vec4(0.0);
    vec3 p=vec3(0.0);
    vec3 v=vec3(1.0,2.0,6.0);
    float i=0.0,z=1.0,d=1.0,f=1.0;

    for(;i++<28.0;
      o.rgb+=(cos((p.x+z+v)*0.1)+1.0)/d/f/z)
    {
      p=z*normalize(FC*2.0-r.xyy);

      vec4 m=cos(
        (p+sin(p)).y*0.4+
        vec4(0.0,33.0,11.0,0.0)
      );

      p.xz=mat2(m)*p.xz;
      p.x+=t/0.55;

      z+=(d=length(cos(p/v)*v+v.zxx/7.0)/
        (f=2.0+d/exp(p.y*0.2)));
    }

    o=tanh4(0.2*o);
    o.a=1.0;
    fragColor=o;
  }`;

  function compile(type,src){
    const sh=gl.createShader(type);
    gl.shaderSource(sh,src);
    gl.compileShader(sh);
    if(!gl.getShaderParameter(sh,gl.COMPILE_STATUS)){
      console.error(gl.getShaderInfoLog(sh)||'ATC shader compile error');
      return null;
    }
    return sh;
  }

  const vs=compile(gl.VERTEX_SHADER,vertSrc);
  const fs=compile(gl.FRAGMENT_SHADER,fragSrc);
  if(!vs||!fs)return;

  const prog=gl.createProgram();
  gl.attachShader(prog,vs);
  gl.attachShader(prog,fs);
  gl.linkProgram(prog);

  if(!gl.getProgramParameter(prog,gl.LINK_STATUS)){
    console.error(gl.getProgramInfoLog(prog)||'ATC shader link error');
    return;
  }

  gl.useProgram(prog);

  const buf=gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER,buf);
  gl.bufferData(
    gl.ARRAY_BUFFER,
    new Float32Array([
      -1,-1, 1,-1, -1,1,
      -1,1, 1,-1, 1,1
    ]),
    gl.STATIC_DRAW
  );

  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0,2,gl.FLOAT,false,0,0);

  const uRes=gl.getUniformLocation(prog,'u_res');
  const uTime=gl.getUniformLocation(prog,'u_time');

  function resize(){
    const dpr=Math.max(1,Math.min(2,window.devicePixelRatio||1));
    const w=Math.max(1,Math.floor(window.innerWidth*dpr));
    const h=Math.max(1,Math.floor(window.innerHeight*dpr));

    if(canvas.width!==w||canvas.height!==h){
      canvas.width=w;
      canvas.height=h;
    }

    gl.viewport(0,0,w,h);
    gl.uniform2f(uRes,w,h);
  }

  window.addEventListener('resize',resize,{passive:true});
  resize();

  let raf=0;
  const t0=performance.now();

  let lastFrame=0;
  const frameInterval=1000/30;

  function draw(now=performance.now()){
    if(now-lastFrame >= frameInterval){
      lastFrame=now;
      gl.uniform1f(uTime,(now-t0)/1000);
      gl.clearColor(0,0,0,1);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLES,0,6);
    }
    raf=requestAnimationFrame(draw);
  }

  draw();

  document.addEventListener('visibilitychange',function(){
    if(document.hidden){
      cancelAnimationFrame(raf);
      raf=0;
    }else if(!raf){
      draw();
    }
  });
})();
</script>


<script>
(function(){
  const nativeFetch = window.fetch;
  window.fetch = function(input, init){
    init = init || {};
    const method = String(init.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const h = new Headers(init.headers || {});
      h.set('X-Requested-With', 'XMLHttpRequest');
      init.headers = h;
    }
    return nativeFetch.call(this, input, init);
  };
})();
</script>
</body>
</html>"""

                                                              

def render_login(error=""):
    return LOGIN_HTML.replace("{{ error }}", str(error))


def send_registration_otp(email, username, otp):
                                                       
    return send_otp_email(email, username, otp)

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("panel_logged_in"):
        return redirect(url_for("home_page"))

    error = ""
    if request.method == "POST":
        mode = (request.form.get("mode") or "user").strip().lower()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if mode == "admin":
            if username == PANEL_USERNAME and check_password_hash(PANEL_PASSWORD_HASH, password):
                session.clear()
                session["panel_logged_in"] = True
                session["login_role"] = "admin"
                session["login_username"] = PANEL_USERNAME
                return redirect(url_for("home_page"))
            error = "Invalid admin username or password"
        else:
            with data_lock:
                d = load_data()
                user = d.get("users", {}).get(username)
            if user and check_password_hash(user.get("password_hash", ""), password):
                session.clear()
                session["panel_logged_in"] = True
                session["login_role"] = "user"
                session["login_username"] = username
                return redirect(url_for("home_page"))
            error = "Invalid username or password"
    return render_login(error)


@app.route("/register/request-otp", methods=["POST"])
def request_registration_otp():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    email = str(payload.get("email") or "").strip().lower()

    if not username or not password or not email:
        return jsonify({"success": False, "error": "Username, password and email are required"}), 400
    if len(username) < 3 or len(username) > 32:
        return jsonify({"success": False, "error": "Username must be 3–32 characters"}), 400
    if len(password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters"}), 400
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        return jsonify({"success": False, "error": "Enter a valid email address"}), 400

    with data_lock:
        d = load_data()
        if username in d.get("users", {}):
            return jsonify({"success": False, "error": "Username already exists"}), 409
        if any(u.get("email", "").lower() == email for u in d.get("users", {}).values()):
            return jsonify({"success": False, "error": "Email is already registered"}), 409

    session_key = session.get("_registration_key")
    if not session_key:
        session_key = secrets.token_urlsafe(24)
        session["_registration_key"] = session_key

    now = time.time()
    with otp_lock:
        previous = pending_registrations.get(session_key)
        if previous and now - previous.get("sent_at", 0) < OTP_RESEND_SECONDS:
            wait = int(OTP_RESEND_SECONDS - (now - previous.get("sent_at", 0)))
            return jsonify({"success": False, "error": f"Please wait {max(1, wait)} seconds before requesting another OTP"}), 429
        otp = f"{secrets.randbelow(1000000):06d}"
        pending_registrations[session_key] = {
            "username": username, "password_hash": generate_password_hash(password), "email": email,
            "otp": otp, "sent_at": now, "expires_at": now + OTP_EXPIRY_SECONDS, "attempts": 0
        }

    try:
        send_registration_otp(email, username, otp)
    except Exception as e:
        with otp_lock:
            pending_registrations.pop(session_key, None)
        return jsonify({"success": False, "error": "Could not send OTP. Please try again later."}), 502

    return jsonify({"success": True, "message": "OTP sent to your email"})


@app.route("/register/verify-otp", methods=["POST"])
def verify_registration_otp():
    payload = request.get_json(silent=True) or {}
    otp = str(payload.get("otp") or "").strip()
    if not otp.isdigit() or len(otp) != 6:
        return jsonify({"success": False, "error": "Enter the 6-digit OTP"}), 400

    session_key = session.get("_registration_key")
    with otp_lock:
        pending = pending_registrations.get(session_key) if session_key else None

    if not pending:
        return jsonify({"success": False, "error": "No active OTP. Request a new OTP."}), 400
    if time.time() > pending["expires_at"]:
        with otp_lock:
            pending_registrations.pop(session_key, None)
        return jsonify({"success": False, "error": "OTP expired. Request a new OTP."}), 400
    with otp_lock:
        pending = pending_registrations.get(session_key)
        if pending:
            pending["attempts"] = int(pending.get("attempts", 0)) + 1
            attempts = pending["attempts"]
        else:
            attempts = 0
    if attempts > 5:
        with otp_lock:
            pending_registrations.pop(session_key, None)
        return jsonify({"success": False, "error": "Too many invalid OTP attempts. Request a new OTP."}), 429
    if not secrets.compare_digest(otp, pending["otp"]):
        return jsonify({"success": False, "error": "Invalid OTP"}), 400

    username, password_hash, email = pending["username"], pending["password_hash"], pending["email"]
    registered_now = time.time()
    with data_lock:
        d = load_data()
        d.setdefault("users", {})
        if username in d["users"]:
            return jsonify({"success": False, "error": "Username already exists"}), 409
        if any(u.get("email", "").lower() == email for u in d["users"].values()):
            return jsonify({"success": False, "error": "Email is already registered"}), 409
        d["users"][username] = {
            "password_hash": password_hash,
            "email": email,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(registered_now)),
            "created_at_epoch": registered_now
        }
        save_data(d)

    with otp_lock:
        pending_registrations.pop(session_key, None)
    session.pop("_registration_key", None)
    return jsonify({"success": True, "message": "Registration successful — you can now log in"})


@app.route("/api/admin/users/<path:username>", methods=["DELETE"])
@admin_required
def admin_delete_user(username):
    username = urllib.parse.unquote(username).strip()
    if not username: return jsonify({"success": False, "error": "Invalid username"}), 400
    if username == PANEL_USERNAME: return jsonify({"success": False, "error": "Admin account cannot be deleted"}), 400
    with data_lock:
        d = load_data()
        users = d.setdefault("users", {})
        if username not in users: return jsonify({"success": False, "error": "User not found"}), 404
        for acc_id, acc in list(d.get("accounts", {}).items()):
            if acc.get("owner") == username:
                if acc_id in bot_stop: bot_stop[acc_id].set()
                ig_clients.pop(acc_id, None); bot_threads.pop(acc_id, None); bot_status.pop(acc_id, None); bot_logs.pop(acc_id, None)
                d["accounts"].pop(acc_id, None)
        users.pop(username, None)
        save_data(d)
    return jsonify({"success": True})


@app.route("/api/admin/users/<path:username>/delete", methods=["POST"])
@admin_required
def admin_delete_user_form(username):
    result = admin_delete_user(username)
    if isinstance(result, tuple):
        response, status = result
        if status != 200:
            return response, status
    else:
        response = result
    return redirect(url_for("home_page"))


@app.route("/api/admin/users/<path:username>/reset", methods=["POST"])
@admin_required
def admin_reset_user(username):
    username = urllib.parse.unquote(username).strip()
    if not username:
        return jsonify({"success": False, "error": "Invalid username"}), 400
    if username == PANEL_USERNAME:
        return jsonify({"success": False, "error": "Admin account cannot be reset"}), 400

    with data_lock:
        d = load_data()
        if username not in d.get("users", {}):
            return jsonify({"success": False, "error": "User not found"}), 404

        removed_ids = []
        for acc_id, acc in list(d.get("accounts", {}).items()):
            if acc.get("owner") == username:
                removed_ids.append(acc_id)
                if acc_id in bot_stop:
                    bot_stop[acc_id].set()
                ig_clients.pop(acc_id, None)
                bot_threads.pop(acc_id, None)
                bot_status.pop(acc_id, None)
                bot_logs.pop(acc_id, None)
                d["accounts"].pop(acc_id, None)

        save_data(d)

    return jsonify({"success": True, "removed_ids": len(removed_ids)})

@app.route("/api/admin/users/<path:username>/reset-form", methods=["POST"])
@admin_required
def admin_reset_user_form(username):
    username = urllib.parse.unquote(username).strip()
    if username and username != PANEL_USERNAME:
        with data_lock:
            d = load_data()
            if username in d.get("users", {}):
                for acc_id, acc in list(d.get("accounts", {}).items()):
                    if acc.get("owner") == username:
                        if acc_id in bot_stop: bot_stop[acc_id].set()
                        ig_clients.pop(acc_id, None)
                        bot_threads.pop(acc_id, None)
                        bot_status.pop(acc_id, None)
                        bot_logs.pop(acc_id, None)
                        d["accounts"].pop(acc_id, None)
                save_data(d)
    return redirect(url_for("home_page"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

HOME_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>DAKSH SX7 • Home</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Instrument+Serif:ital@0;1&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:100%;min-height:100%;background:#09090b;color:#fff;font-family:Inter,system-ui,sans-serif}
body{overflow-x:hidden}
.hero-page{position:relative;min-height:100vh;overflow:hidden;background:#09090b}
.hero-bg{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;object-position:center;filter:saturate(.8) brightness(.72)}
.hero-page:after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,rgba(0,0,0,.22),rgba(0,0,0,.18) 42%,rgba(0,0,0,.72)),radial-gradient(circle at 50% 42%,transparent 0%,rgba(0,0,0,.35) 75%);pointer-events:none}
.content{position:relative;z-index:2;min-height:100vh}
.header{position:relative;padding:16px 24px;z-index:10}
.header-inner{max-width:1450px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:20px}
.brand{width:100px;height:40px;display:flex;align-items:center;justify-content:center;text-decoration:none;color:#fff;font:800 13px 'Share Tech Mono';letter-spacing:1.5px;border-radius:8px;background:rgba(0,0,0,.22);border:1px solid rgba(255,255,255,.14);backdrop-filter:blur(8px)}
.desktop-nav{display:flex;align-items:center;gap:2px;padding:4px;border-radius:999px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);backdrop-filter:blur(16px)}
.desktop-nav a{color:rgba(255,255,255,.78);text-decoration:none;padding:9px 13px;border-radius:999px;font-size:12px;font-weight:600;transition:.2s}
.desktop-nav a:hover,.desktop-nav a.active{color:#fff;background:rgba(255,255,255,.08)}
.cta{display:inline-flex;align-items:center;gap:8px;border:0;border-radius:999px;background:#fff;color:#111;padding:10px 15px;text-decoration:none;font-size:12px;font-weight:700;transition:.2s;white-space:nowrap}
.cta:hover{background:#eee;transform:translateY(-1px)}
.mobile-toggle{display:none;width:42px;height:42px;border-radius:50%;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.1);color:#fff;backdrop-filter:blur(10px);cursor:pointer}
.mobile-menu{display:none;position:absolute;right:18px;top:68px;width:220px;padding:8px;border-radius:16px;background:rgba(12,12,15,.92);border:1px solid rgba(255,255,255,.14);backdrop-filter:blur(18px);box-shadow:0 25px 80px #000b}
.mobile-menu.open{display:flex;flex-direction:column}
.mobile-menu a{padding:12px 13px;color:#ddd;text-decoration:none;border-radius:10px;font-size:12px}
.mobile-menu a:hover{background:#ffffff12;color:#fff}
.main{max-width:1280px;margin:auto;padding:108px 24px 54px}
.hero-copy{text-align:center;max-width:850px;margin:auto}
.badge{display:inline-flex;align-items:center;gap:10px;padding:7px 9px;border-radius:999px;background:rgba(255,255,255,.09);border:1px solid rgba(255,255,255,.14);backdrop-filter:blur(12px);animation:fadeUp .7s ease both}
.badge-label{background:rgba(255,255,255,.92);color:#171717;border-radius:999px;padding:3px 9px;font-size:10px;font-weight:700}
.badge-text{font-size:12px;font-weight:600;color:rgba(255,255,255,.88);padding-right:5px}
h1{margin-top:20px;font:400 clamp(52px,8vw,96px)/.94 'Instrument Serif',Georgia,serif;letter-spacing:-2px;color:#fff;animation:fadeUp .7s .08s ease both;text-shadow:0 4px 35px rgba(0,0,0,.4)}
h1 em{font-style:italic;color:#fff}
.description{max-width:690px;margin:24px auto 0;color:rgba(255,255,255,.78);font-size:14px;line-height:1.75;animation:fadeUp .7s .16s ease both}
.actions{display:flex;align-items:center;justify-content:center;gap:16px;margin-top:32px;animation:fadeUp .7s .24s ease both}
.primary,.secondary{display:inline-flex;align-items:center;gap:9px;text-decoration:none;border-radius:999px;font-size:12px;font-weight:700;transition:.2s}
.primary{padding:13px 18px;color:#fff;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);backdrop-filter:blur(10px)}
.primary:hover{background:rgba(255,255,255,.17);transform:translateY(-1px)}
.secondary{padding:13px 5px;color:rgba(255,255,255,.82)}
.secondary:hover{color:#fff}
.icon{width:16px;height:16px;display:inline-grid;place-items:center}
.session{margin:20px auto 0;display:inline-flex;align-items:center;gap:8px;padding:7px 12px;border-radius:999px;color:rgba(255,255,255,.65);background:rgba(0,0,0,.18);border:1px solid rgba(255,255,255,.1);backdrop-filter:blur(8px);font:9px 'Share Tech Mono';letter-spacing:1px;animation:fadeUp .7s .3s ease both}
.session b{color:#fff}
.dot{width:6px;height:6px;border-radius:50%;background:#6ee7b7;box-shadow:0 0 10px #6ee7b7}
.lower{max-width:1050px;margin:95px auto 0;text-align:center;animation:fadeUp .8s .35s ease both}
.lower-title{font-size:12px;color:rgba(255,255,255,.62);letter-spacing:.2px}
.user-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}
.user-card{padding:16px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.2);border-radius:16px;backdrop-filter:blur(12px);text-align:left;display:flex;align-items:center;gap:12px}
.avatar{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.15);font-weight:800;font-size:12px}
.uname{font-size:12px;font-weight:700}.urole{font:8px 'Share Tech Mono';color:#9b9b9b;letter-spacing:1px;margin-top:4px}
.manage{margin-left:auto;display:flex;gap:5px}.manage button{border-radius:999px;padding:7px 9px;background:#ffffff0d;color:#ddd;border:1px solid #ffffff18;font:8px 'Share Tech Mono';cursor:pointer}.manage .delete{color:#ff9a9a;border-color:#ff777733}
.owner-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}
.owner-card{padding:18px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.18);border-radius:16px;backdrop-filter:blur(10px)}
.owner-mark{font-size:20px;margin-bottom:7px}.owner-name{font-size:13px;font-weight:700}.owner-role{font:8px 'Share Tech Mono';color:#999;margin-top:4px;letter-spacing:1.5px}
.empty{padding:22px;color:#aaa;border:1px dashed rgba(255,255,255,.18);border-radius:15px;font:9px 'Share Tech Mono';letter-spacing:1px;margin-top:18px}
.footer-nav{display:flex;justify-content:center;gap:20px;margin:38px auto 0;padding-bottom:28px}
.footer-nav a{color:rgba(255,255,255,.58);text-decoration:none;font:9px 'Share Tech Mono';letter-spacing:1px}
.footer-nav a:hover{color:#fff}
@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:760px){
 .header{padding:13px 15px}.desktop-nav,.header .cta{display:none}.mobile-toggle{display:grid;place-items:center}
 .main{padding:72px 16px 38px}.hero-copy{max-width:520px}
 h1{font-size:57px;letter-spacing:-1px}.description{font-size:13px;margin-top:20px}
 .actions{flex-direction:column;gap:4px;margin-top:27px}.primary{padding:12px 17px}
 .lower{margin-top:70px}.user-grid,.owner-grid{grid-template-columns:1fr}
 .user-card{padding:14px}.manage{margin-left:auto}
}
@media(min-width:761px) and (max-width:1050px){.main{padding-top:85px}.user-grid,.owner-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<section class="hero-page">
<img class="hero-bg" src="https://cdn.21st.dev/assets/mirror/a8/a8cf38f65f7315f95eba8c803c4a80a9d78cb2ea36fbfee49828396e4a0b9737.jpg" alt="">
<div class="content">
<header class="header">
 <div class="header-inner">
  <a class="brand" href="/">SX⁷</a>
  <nav class="desktop-nav">
   <a class="active" href="/">HOME</a>
   <a href="/instagram">INSTAGRAM</a>
   <a href="/contact">CONTACT</a>
  </nav>
  <a class="cta" href="/logout">LOG OUT ↗</a>
  <button class="mobile-toggle" onclick="toggleMenu()" aria-label="Open menu">☰</button>
  <div id="mobileMenu" class="mobile-menu">
   <a href="/">HOME</a>
   <a href="/instagram">INSTAGRAM</a>
   <a href="/contact">CONTACT</a>
   <a href="/logout">LOG OUT</a>
  </div>
 </div>
</header>

<main class="main">
 <div class="hero-copy">
  <div class="badge"><span class="badge-label">{% if login_role == 'admin' %}ADMIN{% else %}PRIVATE{% endif %}</span><span class="badge-text">DAKSH SX⁷ CONTROL CENTER</span></div>
  <h1>Welcome to<br><em>DAKSH SX⁷</em></h1>
  <p class="description">{% if login_role == 'admin' %}Full administrative control in one place. Manage registered users, access and your connected automation workspace.{% else %}Your private workspace for managing connected Instagram automation. Open your panel and control everything from one place.{% endif %}</p>
  <div class="actions">
   <a class="primary" href="/instagram">◎ OPEN INSTAGRAM PANEL <span class="icon">↗</span></a>
   <a class="secondary" href="/contact">CONTACT <span class="icon">→</span></a>
  </div>
  <div class="session"><span class="dot"></span> SESSION ACTIVE • <b>{{ login_username }}</b> • {{ login_role|upper }}</div>
 </div>

 {% if login_role == 'admin' %}
 <section class="lower">
  <div class="lower-title">Registered users • Account management</div>
  {% if users %}
  <div class="user-grid">
   {% for u in users %}
   <div class="user-card">
    <div class="avatar">{{ u.name[:1]|upper }}</div>
    <div>
     <div class="uname">{{ u.name }}</div>
     <div class="urole">REGISTERED USER</div>
    </div>
    <div class="manage">
     <form method="POST" action="/api/admin/users/{{ u.name|urlencode }}/reset-form" onsubmit="return confirm('Reset user &quot;{{ u.name|e }}&quot;? This removes all Instagram IDs owned by this user but keeps the account.');">
      <button type="submit">RESET</button>
     </form>
     <form method="POST" action="/api/admin/users/{{ u.name|urlencode }}/delete" onsubmit="return confirm('Delete user &quot;{{ u.name|e }}&quot;? This also removes their Instagram IDs.');">
      <button class="delete" type="submit">DELETE</button>
     </form>
    </div>
   </div>
   {% endfor %}
  </div>
  {% else %}
  <div class="empty">NO REGISTERED USERS YET</div>
  {% endif %}
 </section>
 {% else %}
 <section class="lower">
  <div class="lower-title">Workspace • Your available tools</div>
  <div class="owner-grid">
   {% for name in owners %}
   <div class="owner-card"><div class="owner-mark">✦</div><div class="owner-name">{{ name }}</div><div class="owner-role">OFFICIAL OWNER</div></div>
   {% endfor %}
  </div>
 </section>
 {% endif %}

 <div class="footer-nav">
  <a href="/">⌂ HOME</a>
  <a href="/instagram">◎ INSTAGRAM</a>
  <a href="/contact">✉ CONTACT</a>
 </div>
</main>
</div>
</section>
<script>
function toggleMenu(){document.getElementById('mobileMenu').classList.toggle('open')}
document.addEventListener('click',function(e){
 const menu=document.getElementById('mobileMenu'),btn=document.querySelector('.mobile-toggle');
 if(menu.classList.contains('open') && !menu.contains(e.target) && !btn.contains(e.target)) menu.classList.remove('open');
});
</script>

<script>
(function(){
  const nativeFetch = window.fetch;
  window.fetch = function(input, init){
    init = init || {};
    const method = String(init.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const h = new Headers(init.headers || {});
      h.set('X-Requested-With', 'XMLHttpRequest');
      init.headers = h;
    }
    return nativeFetch.call(this, input, init);
  };
})();
</script>
</body>
</html>"""



PARALLAX_INSTAGRAM_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>DAKSH SX7 • Instagram</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Instrument+Serif:ital@0;1&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:auto;background:#050608}
body{min-height:100%;background:#050608;color:#f4efe5;font-family:Inter,system-ui,sans-serif;overflow-x:hidden}
a{color:inherit}
.parallax{position:relative;background:#050608}
.parallax__header{height:100svh;min-height:680px;position:relative;overflow:hidden}
.parallax__visuals{position:absolute;inset:0;overflow:hidden;background:#050608}
.parallax__black-line-overflow{position:absolute;inset:0;background:linear-gradient(180deg,rgba(0,0,0,.12),rgba(0,0,0,.2) 45%,rgba(0,0,0,.8));z-index:8;pointer-events:none}
.parallax__layers{position:absolute;inset:-12%;overflow:hidden}
.parallax__layer-img{position:absolute;width:100%;height:100%;object-fit:cover;object-position:center;will-change:transform;user-select:none}
.parallax__layer-img:nth-child(1){filter:saturate(.75) brightness(.7);transform:scale(1.08)}
.parallax__layer-img:nth-child(2){filter:saturate(.7) brightness(.78);mix-blend-mode:screen;opacity:.55}
.parallax__layer-title{position:absolute;inset:0;display:grid;place-items:center;z-index:4;will-change:transform}
.parallax__title{font:400 clamp(64px,12vw,170px)/.85 'Instrument Serif',Georgia,serif;letter-spacing:-5px;color:#fff;text-shadow:0 8px 50px #000;will-change:transform}
.parallax__layer-img[data-parallax-layer="4"]{filter:saturate(.8) brightness(.65);z-index:5}
.parallax__fade{position:absolute;left:0;right:0;bottom:0;height:34%;z-index:9;background:linear-gradient(transparent,#050608);pointer-events:none}
.parallax__topbar{position:absolute;top:0;left:0;right:0;z-index:20;padding:18px 22px}
.parallax__topbar-inner{max-width:1400px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:16px}
.parallax__logo{font:800 13px 'Share Tech Mono';letter-spacing:2px;text-decoration:none;border:1px solid #ffffff22;background:#0005;backdrop-filter:blur(12px);border-radius:10px;padding:11px 14px}
.parallax__nav{display:flex;gap:6px;padding:5px;border:1px solid #ffffff1c;background:#0005;backdrop-filter:blur(14px);border-radius:999px}
.parallax__nav a{padding:8px 12px;border-radius:999px;text-decoration:none;color:#bbb;font:10px 'Share Tech Mono';letter-spacing:1px}
.parallax__nav a:hover,.parallax__nav a.active{background:#fff1;color:#fff}
.parallax__logout{font:10px 'Share Tech Mono';letter-spacing:1px;text-decoration:none;padding:10px 13px;border:1px solid #ffffff2a;border-radius:999px;background:#ffffff0c}
.parallax__hero-copy{position:absolute;z-index:15;left:50%;top:54%;transform:translate(-50%,-50%);width:min(900px,90vw);text-align:center}
.parallax__eyebrow{font:10px 'Share Tech Mono';letter-spacing:5px;color:#d6bb7b;margin-bottom:17px}
.parallax__hero-copy h1{font:400 clamp(48px,8vw,100px)/.92 'Instrument Serif',Georgia,serif;letter-spacing:-2px}
.parallax__hero-copy h1 em{font-style:italic;color:#d9bf83}
.parallax__hero-copy p{max-width:650px;margin:20px auto 0;color:#c1c1c1;font-size:13px;line-height:1.8}
.parallax__actions{display:flex;justify-content:center;gap:10px;margin-top:28px;flex-wrap:wrap}
.parallax__btn{display:inline-flex;align-items:center;gap:8px;text-decoration:none;border-radius:999px;padding:12px 17px;font-size:11px;font-weight:700;letter-spacing:.5px;transition:.2s}
.parallax__btn.primary{background:#fff;color:#111}
.parallax__btn.secondary{background:#ffffff0c;border:1px solid #ffffff25;color:#eee}
.parallax__btn:hover{transform:translateY(-2px)}
.parallax__scroll{position:absolute;bottom:28px;left:50%;transform:translateX(-50%);z-index:20;color:#aaa;text-align:center;font:9px 'Share Tech Mono';letter-spacing:3px}
.parallax__scroll span{display:block;margin-top:9px;font-size:18px;animation:bob 1.7s ease-in-out infinite}
@keyframes bob{50%{transform:translateY(5px)}}
.parallax__content{min-height:100vh;padding:120px 22px 100px;position:relative;background:
radial-gradient(700px 420px at 50% 0,#7b173018,transparent 70%),
linear-gradient(180deg,#050608,#0a0b0e)}
.portal{max-width:1100px;margin:auto}
.portal-head{text-align:center;margin-bottom:48px}
.portal-kicker{font:10px 'Share Tech Mono';letter-spacing:4px;color:#c5a868}
.portal-head h2{margin-top:12px;font:400 clamp(40px,6vw,72px)/1 'Instrument Serif',Georgia,serif}
.portal-head p{margin:14px auto 0;max-width:620px;color:#92979d;font-size:12px;line-height:1.8}
.portal-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.portal-card{position:relative;min-height:280px;padding:28px;border:1px solid #ffffff18;border-radius:22px;background:linear-gradient(145deg,#17191d,#0b0d11);box-shadow:0 25px 70px #0008;overflow:hidden;transition:.25s}
.portal-card:hover{transform:translateY(-4px);border-color:#b9975b66}
.portal-card:before{content:"";position:absolute;width:220px;height:220px;right:-80px;top:-80px;border:1px solid #b9975b22;border-radius:50%;box-shadow:0 0 0 35px #b9975b08,0 0 0 70px #b9975b04}
.portal-icon{font-size:28px;color:#d7bc7b;margin-bottom:24px}
.portal-card h3{font:400 34px 'Instrument Serif',Georgia,serif}
.portal-card p{margin-top:10px;color:#8f959c;font-size:11px;line-height:1.7;max-width:430px}
.portal-link{display:inline-flex;margin-top:25px;padding:10px 14px;border-radius:999px;border:1px solid #ffffff20;background:#ffffff08;text-decoration:none;font:10px 'Share Tech Mono';letter-spacing:1px}
.portal-link:hover{background:#ffffff12}
.portal-footer{text-align:center;margin-top:50px;color:#666d73;font:9px 'Share Tech Mono';letter-spacing:2px}
@media(max-width:700px){
 .parallax__nav{display:none}.parallax__topbar{padding:13px 15px}
 .parallax__hero-copy{top:51%}.parallax__hero-copy p{font-size:12px}
 .parallax__title{font-size:78px}.parallax__scroll{bottom:20px}
 .parallax__content{padding:85px 15px 70px}.portal-grid{grid-template-columns:1fr}
 .portal-card{min-height:240px;padding:24px}
}
</style>
</head>
<body>
<div class="parallax" id="parallax-root">
<section class="parallax__header">
  <div class="parallax__visuals">
    <div class="parallax__layers" data-parallax-layers>
      <img src="https://cdn.21st.dev/assets/mirror/a4/a43f4eae3459c461345ee676f12d6e1ddca65e8a5279a5af00d475b17ff83aea.webp" loading="eager" data-parallax-layer="1" alt="" class="parallax__layer-img"/>
      <img src="https://cdn.21st.dev/assets/mirror/50/50ca6a0d36d2780bfcb469d6db7eaec0be7e0d2961ba69a63d2a1473b040338d.webp" loading="eager" data-parallax-layer="2" alt="" class="parallax__layer-img"/>
      <div data-parallax-layer="3" class="parallax__layer-title"><h2 class="parallax__title">DAKSH</h2></div>
      <img src="https://cdn.21st.dev/assets/mirror/e1/e1c8137b5f971c3b3ec1a0f9e79b9c17018767005f844a10082b890472afecfb.webp" loading="eager" data-parallax-layer="4" alt="" class="parallax__layer-img"/>
    </div>
    <div class="parallax__black-line-overflow"></div>
    <div class="parallax__fade"></div>
  </div>

  <header class="parallax__topbar">
    <div class="parallax__topbar-inner">
      <a class="parallax__logo" href="/">SX⁷</a>
      <nav class="parallax__nav">
        <a href="/">HOME</a>
        <a href="#portal" class="active">INSTAGRAM</a>
        <a href="#contact-card">CONTACT</a>
      </nav>
      <a class="parallax__logout" href="/logout">LOG OUT ↗</a>
    </div>
  </header>

  <div class="parallax__hero-copy">
    <div class="parallax__eyebrow">DAKSH SX⁷ • INSTAGRAM WORKSPACE</div>
    <h1>Enter the <em>Instagram</em> workspace.</h1>
    <div class="parallax__actions">
      <a class="parallax__btn primary" href="/panel">◎ OPEN PANEL ↗</a>
      <a class="parallax__btn secondary" href="#portal">SCROLL TO CONTINUE ↓</a>
    </div>
  </div>
  <div class="parallax__scroll">SCROLL DOWN<span>↓</span></div>
</section>

<section class="parallax__content" id="portal">
  <div class="portal">
    <div class="portal-head">
      <div class="portal-kicker">NEXT</div>
      <h2>Your workspace</h2>
    </div>
    <div class="portal-grid">
      <article class="portal-card">
        <div class="portal-icon">◎</div>
        <h3>Instagram Panel</h3>
        <p>Go to the instagram panel </p>
        <a class="portal-link" href="/panel">OPEN INSTAGRAM PANEL ↗</a>
      </article>
      <article class="portal-card" id="contact-card">
        <div class="portal-icon">✉</div>
        <h3>Contact</h3>
        <p>Need help or want to reach DAKSH SX7? Continue to the existing contact page.</p>
        <a class="portal-link" href="/contact">OPEN CONTACT ↗</a>
      </article>
    </div>
    <div class="portal-footer">DAKSH SX⁷ • {{ login_username|e }} • {{ login_role|upper }}</div>
  </div>
</section>
</div>

<script src="https://cdn.jsdelivr.net/npm/gsap@3.12.5/dist/gsap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/gsap@3.12.5/dist/ScrollTrigger.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@studio-freight/lenis@1.0.42/bundled/lenis.min.js"></script>
<script>
(function(){
  const root=document.getElementById('parallax-root');
  if(!root || !window.gsap) return;
  gsap.registerPlugin(ScrollTrigger);

  const trigger=root.querySelector('[data-parallax-layers]');
  if(trigger){
    const tl=gsap.timeline({
      scrollTrigger:{trigger:trigger,start:"0% 0%",end:"100% 0%",scrub:0}
    });
    [
      {layer:"1",yPercent:70},
      {layer:"2",yPercent:55},
      {layer:"3",yPercent:40},
      {layer:"4",yPercent:10}
    ].forEach((obj,i)=>{
      tl.to(trigger.querySelectorAll('[data-parallax-layer="'+obj.layer+'"]'),
        {yPercent:obj.yPercent,ease:"none"},i===0?undefined:"<");
    });
  }

  if(window.Lenis){
    const lenis=new Lenis({smoothWheel:true});
    lenis.on('scroll',ScrollTrigger.update);
    gsap.ticker.add(time=>lenis.raf(time*1000));
    gsap.ticker.lagSmoothing(0);
    window.addEventListener('beforeunload',()=>lenis.destroy());
  }
})();
</script>

<script>
(function(){
  const nativeFetch = window.fetch;
  window.fetch = function(input, init){
    init = init || {};
    const method = String(init.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const h = new Headers(init.headers || {});
      h.set('X-Requested-With', 'XMLHttpRequest');
      init.headers = h;
    }
    return nativeFetch.call(this, input, init);
  };
})();
</script>
</body>
</html>"""


CONTACT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DAKSH SX7 • Contact</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Playfair+Display:wght@600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}body{min-height:100vh;background:radial-gradient(circle at 15% 0,#8b123522,transparent 32%),radial-gradient(circle at 90% 100%,#c6a66718,transparent 35%),linear-gradient(135deg,#07080b,#111217 55%,#08090c);color:#eee7da;font-family:Inter,Arial,sans-serif;padding:30px 22px 120px}.page{max-width:1120px;margin:auto}.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}.logo{font:700 23px 'Playfair Display',serif;letter-spacing:2px}.logo span{color:#d0ae67}.logout{color:#d2bc8b;text-decoration:none;border:1px solid #514a40;padding:9px 14px;border-radius:10px;font-size:10px;letter-spacing:1px;background:#101115}.hero{position:relative;overflow:hidden;border:1px solid #4b4541;border-radius:28px;padding:48px;background:linear-gradient(145deg,#17191f,#0d0f13 70%);box-shadow:0 35px 100px #000b}.hero:after{content:"";position:absolute;right:-80px;top:-120px;width:330px;height:330px;border:1px solid #c6a66722;border-radius:50%;box-shadow:0 0 0 35px #c6a66708,0 0 0 70px #c6a66705}.eyebrow{font-size:9px;color:#c9aa6b;letter-spacing:4px;margin-bottom:14px}.hero h1{font:700 clamp(44px,8vw,72px) 'Playfair Display',serif;line-height:.95}.hero h1 span{color:#b9975b}.hero p{max-width:690px;margin-top:20px;color:#949aa2;line-height:1.8;font-size:12px}.section{margin-top:20px;border:1px solid #3d4147;border-radius:22px;background:linear-gradient(145deg,#14161b,#0b0d11);padding:26px;box-shadow:0 20px 70px #0007}.section-head{margin-bottom:18px}.section h2{font:600 25px 'Playfair Display',serif}.section-head small{display:block;margin-top:5px;color:#858b92;font-size:9px;letter-spacing:1.5px}.contact-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.contact{display:flex;align-items:center;gap:14px;border:1px solid #34383e;background:linear-gradient(145deg,#0b0d10,#111318);border-radius:15px;padding:18px;text-decoration:none;color:#eee7da;transition:.2s}.contact:hover{transform:translateY(-2px);border-color:#8d7141;box-shadow:0 14px 35px #0008}.icon{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;background:linear-gradient(145deg,#74142f,#211419);border:1px solid #a9874e;color:#e4ce98;font-size:20px;flex:none}.label{font-size:8px;color:#747b83;letter-spacing:1.5px;text-transform:uppercase}.value{margin-top:5px;font-weight:700;font-size:12px;word-break:break-word}.nav{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);width:min(600px,calc(100vw - 30px));display:grid;grid-template-columns:repeat(3,1fr);gap:5px;padding:8px;border:1px solid #4b4743;border-radius:17px;background:#111318f2;backdrop-filter:blur(18px);box-shadow:0 18px 60px #000c}.nav a{padding:12px 8px;text-align:center;text-decoration:none;color:#aeb3b8;border-radius:11px;font-size:10px;font-weight:700;letter-spacing:1px}.nav a:hover,.nav a.active{background:linear-gradient(135deg,#77152f30,#b9975b12);color:#ecd8a7}.sym{display:block;font-size:20px;margin-bottom:3px;color:#c6a667}@media(max-width:650px){.hero{padding:32px 24px}.contact-grid{grid-template-columns:1fr}.section{padding:20px}}
</style>
</head>
<body>
<div class="page">
  <div class="top"><div class="logo">⚡ DAKSH <span>SX7</span></div><a class="logout" href="/logout">LOG OUT</a></div>
  <section class="hero">
    <div class="eyebrow">DIRECT CONTACT</div>
    <h1>GET IN <span>TOUCH</span></h1>
    <p>Use any of the contact options below to reach DAKSH SX7.</p>
  </section>
  <section class="section">
    <div class="section-head"><h2>Contact Details</h2><small>OFFICIAL CONTACT CHANNELS</small></div>
    <div class="contact-grid">
      <a class="contact" href="mailto:aahhyankhan@gmail.com"><div class="icon">✉</div><div><div class="label">Email</div><div class="value">aahhyankhan@gmail.com</div></div></a>
      <a class="contact" href="tel:+919864232893"><div class="icon">☎</div><div><div class="label">Phone</div><div class="value">+91 98642 32893</div></div></a>
      <a class="contact" href="https://t.me/ayansx7" target="_blank" rel="noopener"><div class="icon">✈</div><div><div class="label">Telegram</div><div class="value">@ayansx7</div></div></a>
      <a class="contact" href="https://www.instagram.com/ayansx7/" target="_blank" rel="noopener"><div class="icon">◎</div><div><div class="label">Instagram</div><div class="value">@ayansx7</div></div></a>
    </div>
  </section>
</div>
<nav class="nav"><a href="/"><span class="sym">⌂</span>HOME</a><a href="/instagram"><span class="sym">◎</span>INSTAGRAM</a><a class="active" href="/contact"><span class="sym">✉</span>CONTACT</a></nav>

<script>
(function(){
  const nativeFetch = window.fetch;
  window.fetch = function(input, init){
    init = init || {};
    const method = String(init.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const h = new Headers(init.headers || {});
      h.set('X-Requested-With', 'XMLHttpRequest');
      init.headers = h;
    }
    return nativeFetch.call(this, input, init);
  };
})();
</script>
</body>
</html>"""

GC_CREATOR_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>DAKSH SX7 • GC Creator</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Playfair+Display:wght@600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%;background:transparent!important}
body{min-height:100vh;overflow-x:hidden;color:#eef2ff;font-family:Inter,Arial,sans-serif}
button,input,textarea{font:inherit}
#atc-panel-background{position:fixed!important;inset:0!important;width:100vw!important;height:100vh!important;display:block!important;z-index:0!important;background:#000!important;pointer-events:none}
#atc-panel-overlay{position:fixed!important;inset:0!important;z-index:1!important;pointer-events:none;background:radial-gradient(circle at 50% 0%,rgba(255,255,255,.055),transparent 42%),linear-gradient(180deg,rgba(0,0,0,.08),rgba(0,0,0,.24))}
.shell{position:relative!important;z-index:2!important;display:flex;min-height:100vh;background:transparent!important}
.sidebar{width:190px;flex:none;position:fixed;left:0;top:0;bottom:0;padding:18px 12px;background:linear-gradient(180deg,#080b14f2,#090c15f8);border-right:1px solid #193238;z-index:100;display:flex;flex-direction:column}
 .brand{display:flex;align-items:center;gap:10px;padding:8px 10px 22px}
 .brand-mark{display:none}
 .brand-name{font:700 20px 'Share Tech Mono';letter-spacing:2px;color:#99f6e4}
 .brand-sub{font-size:8px;letter-spacing:3px;color:#94a3b8;margin-top:2px}
 .nav{display:flex;flex-direction:column;gap:5px}
 .nav-item{display:flex;align-items:center;gap:10px;padding:10px 11px;border-radius:9px;color:#9aa5bd;font-size:12px;text-decoration:none;border:1px solid transparent}
 .nav-item:hover,.nav-item.active{color:#fff;background:linear-gradient(90deg,#14b8a61e,#22d3ee08);border-color:#0f766e44}
 .nav-icon{width:20px;text-align:center;color:#2dd4bf;font-size:15px}
 .nav-icon img{width:18px;height:18px;display:block;object-fit:contain;margin:auto}
 .side-bottom{margin-top:auto;border-top:1px solid #193238;padding-top:14px;position:static;text-align:center;color:#64748b;font-size:10px;font-family:Inter,Arial,sans-serif;letter-spacing:2px}
 .side-bottom strong{display:block;color:#67e8f9;font-size:15px;letter-spacing:1px;margin-bottom:3px}
 .main{margin-left:190px;width:calc(100% - 190px);padding:20px 24px 34px;max-width:1500px;background:transparent!important}
 .topbar{display:flex;align-items:center;justify-content:center;text-align:center;padding:14px 0 18px;border-bottom:1px solid rgba(255,255,255,.16);background:rgba(8,10,16,.22);border-radius:0 0 18px 18px}
.topbar h1{font:700 28px 'Playfair Display';color:#e2e5ea;letter-spacing:3px}
.topbar h1 span{color:#bfc5ce}
.topbar p{font-size:9px;color:#909aa2;letter-spacing:2px;margin-top:6px}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin:20px 0 12px}
.toolbar h2{font:600 22px 'Playfair Display';color:#eef2ff}
.btn{border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.055);color:#eee;padding:10px 14px;border-radius:8px;cursor:pointer;font:10px 'Share Tech Mono';letter-spacing:1px;transition:.18s;box-shadow:0 18px 55px rgba(0,0,0,.25),inset 0 1px 0 rgba(255,255,255,.14);backdrop-filter:blur(10px) saturate(125%);-webkit-backdrop-filter:blur(10px) saturate(125%)}
.btn:hover{background:rgba(255,255,255,.11);border-color:rgba(255,255,255,.35);box-shadow:0 0 18px rgba(255,255,255,.08)}
.btn:disabled{opacity:.45;cursor:not-allowed;transform:none}
.btn-add,.btn-save{background:linear-gradient(135deg,rgba(255,255,255,.20),rgba(255,255,255,.07));border-color:rgba(255,255,255,.40)}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.card{background:rgba(10,14,20,.28);border:1px solid rgba(255,255,255,.16);border-radius:18px;box-shadow:0 18px 55px rgba(0,0,0,.25),inset 0 1px 0 rgba(255,255,255,.14),inset 0 -1px 0 rgba(255,255,255,.035);backdrop-filter:blur(10px) saturate(125%);-webkit-backdrop-filter:blur(10px) saturate(125%);overflow:hidden;transition:.18s}
.card:hover{transform:translateY(-2px);border-color:rgba(255,255,255,.30)}
.card-head{padding:16px;border-bottom:1px solid rgba(255,255,255,.12);display:flex;align-items:center;gap:10px;background:rgba(255,255,255,.055)}
.dot{width:9px;height:9px;border-radius:50%;background:#d7dce3;box-shadow:0 0 10px rgba(255,255,255,.35)}
.name{font-weight:800;color:#f1f3f6;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.body{padding:15px}
.meta{font:9px 'Share Tech Mono';color:#9aa3ad;word-break:break-all;line-height:1.7}
.actions{display:flex;gap:7px;margin-top:14px}
.actions .btn{flex:1}
.empty{text-align:center;padding:80px 20px;border:1px dashed rgba(255,255,255,.18);border-radius:18px;color:#89939d;font:10px 'Share Tech Mono';grid-column:1/-1;background:rgba(0,0,0,.13)}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.38);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);z-index:50;align-items:center;justify-content:center;padding:20px}
.overlay.open{display:flex}
.modal{width:680px;max-width:94vw;max-height:92vh;overflow:auto;background:rgba(10,14,20,.82);border:1px solid rgba(255,255,255,.16);border-radius:18px;padding:22px;box-shadow:0 30px 100px rgba(0,0,0,.65),inset 0 1px 0 rgba(255,255,255,.14);backdrop-filter:blur(18px) saturate(125%);-webkit-backdrop-filter:blur(18px)}
.title{font:18px 'Share Tech Mono';color:#eef2f7;letter-spacing:2px;margin-bottom:16px}
.fields{display:grid;grid-template-columns:1fr 1fr;gap:11px}
.full{grid-column:1/-1}
.group{display:flex;flex-direction:column;gap:6px}
.group label{font:9px 'Share Tech Mono';color:#a2aab4;letter-spacing:1px;text-transform:uppercase}
.group input,.group textarea{width:100%;background:rgba(0,0,0,.20);border:1px solid rgba(255,255,255,.15);color:#eef2ff;border-radius:10px;padding:11px;font:11px 'Share Tech Mono';outline:none;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);transition:.18s}
.group input:focus,.group textarea:focus{border-color:rgba(255,255,255,.55);box-shadow:0 0 0 3px rgba(255,255,255,.06)}
.group textarea{min-height:95px;resize:vertical}
.hint{font:9px 'Share Tech Mono';color:#89939d;line-height:1.5}
.status{margin-top:12px;color:#d5dae0;font:10px 'Share Tech Mono';min-height:20px}
.log{margin-top:10px;height:170px;overflow:auto;background:rgba(0,0,0,.18);border:1px solid rgba(255,255,255,.12);border-radius:10px;padding:10px;white-space:pre-wrap;font:9px/1.7 'Share Tech Mono';color:#b5bec8}
.footer{display:flex;justify-content:flex-end;gap:8px;margin-top:16px;padding-top:14px;border-top:1px solid rgba(255,255,255,.12)}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:650px){
.sidebar{width:58px;padding:10px 7px}.brand{justify-content:center;padding:7px 0 18px}.brand-name,.brand-sub,.nav-label,.side-bottom{display:none}.nav-item{justify-content:center;padding:10px 0}.main{margin-left:58px;width:calc(100% - 58px);padding:16px 12px 28px}.grid{grid-template-columns:1fr}.fields{grid-template-columns:1fr}.full{grid-column:auto}.toolbar{align-items:flex-start;gap:10px}.toolbar h2{font-size:18px}
}
</style>
</head>
<body>
<canvas id="atc-panel-background" aria-hidden="true"></canvas>
<div id="atc-panel-overlay" aria-hidden="true"></div>

<div class="shell">
<aside class="sidebar">
  <div class="brand"><div><div class="brand-name">DAKSH SX7</div><div class="brand-sub">PANEL</div></div></div>
  <nav class="nav">
    <a class="nav-item" href="/"><span class="nav-icon"><img src="https://cdn.21st.dev/assets/mirror/99/9963f31f43cd77b0c28981ba7bac04db749a5749019f554d1afb75225a3e9151.png" alt="" aria-hidden="true"></span><span class="nav-label">Home</span></a>
    <a class="nav-item" href="/instagram"><span class="nav-icon"><img src="https://cdn.21st.dev/assets/mirror/d5/d558230225bb0dd1897db6c7cf0d03b29506eef8078fe25313c48cd8f72d05ad.png" alt="" aria-hidden="true"></span><span class="nav-label">Instagram</span></a>
    <a class="nav-item" href="/contact"><span class="nav-icon"><img src="https://cdn.21st.dev/assets/mirror/7b/7bb8671183d2a2bbb8a3858b1971cc5699ba0103673b011590d22f0fa309bb87.png" alt="" aria-hidden="true"></span><span class="nav-label">Contact</span></a>
    <a class="nav-item active" href="/gc-creator"><span class="nav-icon gc-creator-icon">＋</span><span class="nav-label">GC Creator</span></a>
  </nav>
  <div class="side-bottom"><div class="side-owner"><strong>DAKSH SX7</strong>PANEL • v2.0</div></div>
</aside>

<main class="main">
  <div class="topbar">
    <div><h1>DAKSH <span>SX7</span></h1><p>GC CREATOR • {{ login_username|e }}</p></div>
  </div>

  <div class="toolbar">
    <h2>GC Creator IDs</h2>
    <div style="display:flex;gap:8px">
      <button class="btn" type="button" onclick="loadIds()">↻ REFRESH</button>
      <button class="btn btn-add" type="button" onclick="openIdModal()">＋ ADD GC ID</button>
    </div>
  </div>

  <div id="ids" class="grid"></div>
</main>
</div>

<div class="overlay" id="idModal">
  <div class="modal">
    <div class="title" id="idTitle">ADD GC CREATOR ID</div>
    <div class="fields">
      <div class="group"><label>ID NAME</label><input id="idName" placeholder="GC ID name" autocomplete="off"></div>
      <div class="group"><label>PROXY (OPTIONAL)</label><input id="idProxy" placeholder="http://user:pass@ip:port" autocomplete="off"></div>
      <div class="group full"><label>SESSION ID</label><input id="idSession" type="password" autocomplete="off" placeholder="Paste sessionid"></div>
    </div>
    <div class="hint" style="margin-top:9px">The session is stored only for the GC Creator ID and is separate from Instagram IDs.</div>
    <div class="status" id="idStatus"></div>
    <div class="footer">
      <button class="btn" type="button" onclick="closeIdModal()">CANCEL</button>
      <button class="btn btn-save" type="button" id="saveIdBtn" onclick="saveId()">SAVE ID</button>
    </div>
  </div>
</div>

<div class="overlay" id="gcModal">
  <div class="modal">
    <div class="title">CREATE GROUP CHATS</div>
    <div class="hint" id="selectedIdHint"></div>
    <div class="fields" style="margin-top:14px">
      <div class="group"><label>GCs TO CREATE</label><input id="gcCount" type="number" min="1" max="50" value="1"></div>
      <div class="group"><label>REMOVE USERNAME</label><input id="removeUser" placeholder="username" autocomplete="off"></div>
      <div class="group full"><label>USERNAMES</label><textarea id="users" placeholder="user1, user2, user3"></textarea><div class="hint">Comma separated. Minimum 2 users.</div></div>
      <div class="group full"><label>TEXT TO SEND AFTER CREATION (OPTIONAL)</label><textarea id="gcMessage" placeholder="Enter the message to send in each newly created group..."></textarea><div class="hint">The text is sent to the newly created group after the selected user is removed.</div></div>
    </div>
    <div class="status" id="gcStatus"></div>
    <div class="log" id="gcLog"></div>
    <div class="footer">
      <button class="btn" type="button" onclick="closeGCModal()">CANCEL</button>
      <button class="btn btn-save" type="button" id="createBtn" onclick="createGCs()">CREATE GCs</button>
    </div>
  </div>
</div>

<script>
let ids={};
let editingId=null;
let selectedId=null;
let poller=null;

function esc(s){
  return String(s ?? '').replace(/[&<>"']/g,m=>({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[m]));
}

async function apiJSON(url, options={}){
  const r=await fetch(url,options);
  let d={};
  try{d=await r.json()}catch(_){}
  if(!r.ok && !d.error) d.error=`Request failed (${r.status})`;
  return d;
}

async function loadIds(){
  const el=document.getElementById('ids');
  try{
    const d=await apiJSON('/api/gc-creator/ids');
    if(d && !Array.isArray(d) && typeof d==='object' && !d.error){
      ids=d;
      renderIds();
    }else{
      el.innerHTML='<div class="empty">COULD NOT LOAD GC CREATOR IDS</div>';
    }
  }catch(e){
    el.innerHTML='<div class="empty">NETWORK ERROR WHILE LOADING IDS</div>';
  }
}

function renderIds(){
  const el=document.getElementById('ids');
  const keys=Object.keys(ids||{});
  if(!keys.length){
    el.innerHTML='<div class="empty">NO GC CREATOR IDS ADDED YET</div>';
    return;
  }
  el.innerHTML=keys.map(id=>{
    const x=ids[id]||{};
    return `<article class="card">
      <div class="card-head"><span class="dot"></span><div class="name">${esc(x.name||id)}</div></div>
      <div class="body">
        <div class="meta">SESSION SAVED •••••••••••••••<br>${x.proxy?`PROXY • ${esc(x.proxy)}`:'DIRECT CONNECTION'}</div>
        <div class="actions">
          <button class="btn btn-save" type="button" data-action="start" data-id="${esc(id)}">START</button>
          <button class="btn" type="button" data-action="edit" data-id="${esc(id)}">EDIT</button>
          <button class="btn" type="button" data-action="remove" data-id="${esc(id)}">REMOVE</button>
        </div>
      </div>
    </article>`;
  }).join('');
}

function openIdModal(){
  editingId=null;
  document.getElementById('idTitle').textContent='ADD GC CREATOR ID';
  document.getElementById('idName').value='';
  document.getElementById('idSession').value='';
  document.getElementById('idProxy').value='';
  document.getElementById('idStatus').textContent='';
  document.getElementById('saveIdBtn').disabled=false;
  document.getElementById('idModal').classList.add('open');
  setTimeout(()=>document.getElementById('idName').focus(),50);
}

function openEditModal(id){
  const x=ids[id];
  if(!x){alert('GC Creator ID not found');return}
  editingId=id;
  document.getElementById('idTitle').textContent='EDIT GC CREATOR ID';
  document.getElementById('idName').value=x.name||'';
  document.getElementById('idSession').value='';
  document.getElementById('idSession').placeholder=x.session_id_set?'Session ID already saved — leave blank to keep it':'Session ID';
  document.getElementById('idProxy').value=x.proxy||'';
  document.getElementById('idStatus').textContent='';
  document.getElementById('saveIdBtn').disabled=false;
  document.getElementById('idModal').classList.add('open');
  setTimeout(()=>document.getElementById('idName').focus(),50);
}

function closeIdModal(){
  document.getElementById('idModal').classList.remove('open');
  editingId=null;
}

async function saveId(){
  const body={
    name:document.getElementById('idName').value.trim(),
    session_id:document.getElementById('idSession').value.trim(),
    proxy:document.getElementById('idProxy').value.trim()
  };
  const status=document.getElementById('idStatus');
  const btn=document.getElementById('saveIdBtn');

  if(!body.name){status.textContent='ID name is required.';return}
  if(!body.session_id){status.textContent='Session ID is required.';return}

  btn.disabled=true;
  status.textContent='Saving...';

  try{
    const url=editingId?`/api/gc-creator/ids/${encodeURIComponent(editingId)}`:'/api/gc-creator/ids';
    const method=editingId?'PUT':'POST';
    const d=await apiJSON(url,{
      method,
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)
    });
    if(!d.success){
      status.textContent=d.error||'Save failed.';
      btn.disabled=false;
      return;
    }
    closeIdModal();
    await loadIds();
  }catch(e){
    status.textContent='Network error. Please try again.';
    btn.disabled=false;
  }
}

async function deleteId(id){
  if(!ids[id])return;
  if(!confirm(`Delete "${ids[id].name||id}"?`))return;
  try{
    const d=await apiJSON(`/api/gc-creator/ids/${encodeURIComponent(id)}`,{method:'DELETE'});
    if(!d.success){alert(d.error||'Delete failed');return}
    if(selectedId===id)closeGCModal();
    await loadIds();
  }catch(e){
    alert('Network error while deleting.');
  }
}

function openGCModal(id){
  if(!ids[id]){alert('GC Creator ID not found');return}
  selectedId=id;
  document.getElementById('selectedIdHint').textContent='Using saved session: '+(ids[id]?.name||id);
  document.getElementById('gcCount').value=1;
  document.getElementById('removeUser').value='';
  document.getElementById('users').value='';
  document.getElementById('gcMessage').value='';
  document.getElementById('gcStatus').textContent='';
  document.getElementById('gcLog').textContent='';
  document.getElementById('createBtn').disabled=false;
  document.getElementById('gcModal').classList.add('open');
  setTimeout(()=>document.getElementById('users').focus(),50);
}

function closeGCModal(){
  document.getElementById('gcModal').classList.remove('open');
  if(poller){clearInterval(poller);poller=null}
  document.getElementById('createBtn').disabled=false;
}

async function createGCs(){
  const count=Number(document.getElementById('gcCount').value);
  const users=document.getElementById('users').value.split(',').map(x=>x.trim().replace(/^@/,'')).filter(Boolean);
  const remove=document.getElementById('removeUser').value.trim().replace(/^@/,'');
  const message=document.getElementById('gcMessage').value;
  const status=document.getElementById('gcStatus');
  const button=document.getElementById('createBtn');

  if(!selectedId){status.textContent='Select a GC Creator ID first.';return}
  if(!Number.isInteger(count)||count<1||count>50){status.textContent='GC count must be between 1 and 50.';return}
  if(users.length<2){status.textContent='Enter at least 2 usernames.';return}
  if(!remove){status.textContent='Enter the username to remove.';return}
  if(!users.includes(remove)){status.textContent='Remove username must be one of the entered members.';return}

  button.disabled=true;
  status.textContent='Starting...';
  document.getElementById('gcLog').textContent='';

  try{
    const d=await apiJSON('/api/gc-creator/start',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        gc_id:selectedId,
        group_count:count,
        usernames:users,
        remove_username:remove,
        message:message
      })
    });

    if(!d.success){
      status.textContent=d.error||'Could not start.';
      button.disabled=false;
      return;
    }
    pollJob(d.job_id);
  }catch(e){
    status.textContent='Network error.';
    button.disabled=false;
  }
}

function pollJob(job){
  if(poller)clearInterval(poller);

  const poll=async()=>{
    try{
      const d=await apiJSON(`/api/gc-creator/status/${encodeURIComponent(job)}`);
      if(!d.success){
        document.getElementById('gcStatus').textContent=d.error||'Could not read job status.';
        return;
      }

      document.getElementById('gcStatus').textContent=
        d.running?`Running • ${d.done}/${d.total}`:
        d.error?`Failed • ${d.done}/${d.total}`:
        `Completed • ${d.done}/${d.total}`;

      document.getElementById('gcLog').textContent=(d.logs||[]).join('\n');

      if(!d.running){
        clearInterval(poller);
        poller=null;
        document.getElementById('createBtn').disabled=false;
      }
    }catch(e){
      document.getElementById('gcStatus').textContent='Network error while checking job.';
    }
  };

  poll();
  poller=setInterval(poll,1500);
}

document.getElementById('idModal').addEventListener('click',e=>{
  if(e.target===e.currentTarget)closeIdModal();
});
document.getElementById('gcModal').addEventListener('click',e=>{
  if(e.target===e.currentTarget)closeGCModal();
});
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    if(document.getElementById('idModal').classList.contains('open'))closeIdModal();
    if(document.getElementById('gcModal').classList.contains('open'))closeGCModal();
  }
});

document.getElementById('ids').addEventListener('click',function(e){
  const button=e.target.closest('button[data-action]');
  if(!button)return;
  const id=button.dataset.id;
  if(!id)return;
  const action=button.dataset.action;
  if(action==='start')openGCModal(id);
  else if(action==='edit')openEditModal(id);
  else if(action==='remove')deleteId(id);
});

loadIds();
</script>

<script>
(function(){
  const canvas=document.getElementById('atc-panel-background');
  if(!canvas)return;

  const gl=canvas.getContext('webgl2',{premultipliedAlpha:false,antialias:false});
  if(!gl)return;

  const vertSrc=`#version 300 es
  precision highp float;
  layout(location=0) in vec2 a_pos;
  void main(){ gl_Position=vec4(a_pos,0.0,1.0); }`;

  const fragSrc=`#version 300 es
  precision highp float;
  out vec4 fragColor;
  uniform vec2 u_res;
  uniform float u_time;

  float tanh1(float x){
    float e=exp(2.0*x);
    return(e-1.0)/(e+1.0);
  }
  vec4 tanh4(vec4 v){
    return vec4(tanh1(v.x),tanh1(v.y),tanh1(v.z),tanh1(v.w));
  }

  void main(){
    vec3 FC=vec3(gl_FragCoord.xy,0.0);
    vec3 r=vec3(u_res,max(u_res.x,u_res.y));
    float t=u_time;
    vec4 o=vec4(0.0);
    vec3 p=vec3(0.0);
    vec3 v=vec3(1.0,2.0,6.0);
    float i=0.0,z=1.0,d=1.0,f=1.0;

    for(;i++<28.0;o.rgb+=(cos((p.x+z+v)*0.1)+1.0)/d/f/z){
      p=z*normalize(FC*2.0-r.xyy);
      vec4 m=cos((p+sin(p)).y*0.4+vec4(0.0,33.0,11.0,0.0));
      p.xz=mat2(m)*p.xz;
      p.x+=t/0.55;
      z+=(d=length(cos(p/v)*v+v.zxx/7.0)/(f=2.0+d/exp(p.y*0.2)));
    }

    o=tanh4(0.2*o);
    o.a=1.0;
    fragColor=o;
  }`;

  function compile(type,src){
    const sh=gl.createShader(type);
    gl.shaderSource(sh,src);
    gl.compileShader(sh);
    if(!gl.getShaderParameter(sh,gl.COMPILE_STATUS)){
      console.error(gl.getShaderInfoLog(sh)||'ATC shader compile error');
      return null;
    }
    return sh;
  }

  const vs=compile(gl.VERTEX_SHADER,vertSrc);
  const fs=compile(gl.FRAGMENT_SHADER,fragSrc);
  if(!vs||!fs)return;

  const prog=gl.createProgram();
  gl.attachShader(prog,vs);
  gl.attachShader(prog,fs);
  gl.linkProgram(prog);
  if(!gl.getProgramParameter(prog,gl.LINK_STATUS)){
    console.error(gl.getProgramInfoLog(prog)||'ATC shader link error');
    return;
  }

  gl.useProgram(prog);

  const buf=gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER,buf);
  gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([
    -1,-1,1,-1,-1,1,
    -1,1,1,-1,1,1
  ]),gl.STATIC_DRAW);

  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0,2,gl.FLOAT,false,0,0);

  const uRes=gl.getUniformLocation(prog,'u_res');
  const uTime=gl.getUniformLocation(prog,'u_time');

  function resize(){
    const dpr=Math.max(1,Math.min(2,window.devicePixelRatio||1));
    const w=Math.max(1,Math.floor(window.innerWidth*dpr));
    const h=Math.max(1,Math.floor(window.innerHeight*dpr));
    if(canvas.width!==w||canvas.height!==h){
      canvas.width=w;
      canvas.height=h;
    }
    gl.viewport(0,0,w,h);
    gl.uniform2f(uRes,w,h);
  }

  addEventListener('resize',resize,{passive:true});
  resize();

  let raf=0,t0=performance.now(),lastFrame=0;
  const frameInterval=1000/30;

  function draw(now=performance.now()){
    if(document.hidden){raf=0;return}
    if(now-lastFrame>=frameInterval){
      lastFrame=now;
      gl.uniform1f(uTime,(now-t0)/1000);
      gl.drawArrays(gl.TRIANGLES,0,6);
    }
    raf=requestAnimationFrame(draw);
  }

  draw();
  document.addEventListener('visibilitychange',()=>{
    if(!document.hidden&&!raf)draw();
  });
  addEventListener('beforeunload',()=>cancelAnimationFrame(raf));
})();
</script>

<script>
(function(){
  const nativeFetch = window.fetch;
  window.fetch = function(input, init){
    init = init || {};
    const method = String(init.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const h = new Headers(init.headers || {});
      h.set('X-Requested-With', 'XMLHttpRequest');
      init.headers = h;
    }
    return nativeFetch.call(this, input, init);
  };
})();
</script>
</body>
</html>"""


@app.route("/data")
@admin_required
def data_page():
    # Never expose stored Instagram credentials/session settings through this endpoint.
    with data_lock:
        d = load_data()
        safe = {"users": {}, "accounts": {}, "gc_creator_ids": {}}
        for u, item in d.get("users", {}).items():
            safe["users"][u] = {"email": item.get("email", ""), "created_at": item.get("created_at", "")}
        for aid, item in d.get("accounts", {}).items():
            safe["accounts"][aid] = {k: item.get(k, "") for k in ("name", "method", "owner", "groups", "group_names")}
            safe["accounts"][aid]["session_id_set"] = bool(item.get("session_id"))
        for gid, item in d.get("gc_creator_ids", {}).items():
            safe["gc_creator_ids"][gid] = {"name": item.get("name", ""), "owner": item.get("owner", ""), "proxy": item.get("proxy", "")}
            safe["gc_creator_ids"][gid]["session_id_set"] = bool(item.get("session_id"))
    return jsonify(safe)


@app.route("/gc-creator")
@login_required
def gc_creator_page():
    return render_template_string(GC_CREATOR_HTML, login_username=session.get("login_username", ""))

@app.route("/contact")
@login_required
def contact_page():
    return render_template_string(CONTACT_HTML)

@app.route("/")
@login_required
def home_page():
    with data_lock:
        d = load_data()
        users = [
            {
                "name": name,
                                                                             
                                                   
                "created_at_epoch": float(
                    user.get("created_at_epoch", 0) or 0
                )
            }
            for name, user in d.get("users", {}).items()
        ]
        users.sort(key=lambda u: u["name"].lower())
    owners = ["DAKSH", "AYAN", "ARYAN", "SCAR", "PREDATOR"]
    visible_users = users if session.get("login_role") == "admin" else []
    return render_template_string(HOME_HTML, users=visible_users, user_count=len(visible_users),
                                  owners=owners,
                                  login_username=session.get("login_username", ""),
                                  login_role=session.get("login_role", "user"))

@app.route("/home")
def home_alias():
    return redirect(url_for("home_page"))

@app.route("/panel")
@login_required
def panel_page():
                                                                      
                                                                           
                                                                          
                                        
    login_username = session.get("login_username", "")
    login_role = session.get("login_role", "user")
    user_created_at_epoch = 0
    if login_role == "user":
        with data_lock:
            d = load_data()
            user = d.get("users", {}).get(login_username, {})
            user_created_at_epoch = float(user.get("created_at_epoch", 0) or 0)
    return render_template_string(
        HTML,
        login_username=login_username,
        login_role=login_role,
        user_created_at_epoch=user_created_at_epoch
    )

@app.route("/instagram")
@login_required
def instagram_panel():
    return render_template_string(
        PARALLAX_INSTAGRAM_HTML,
        login_username=session.get("login_username", ""),
        login_role=session.get("login_role", "user")
    )

@app.route("/api/accounts")
@login_required
def get_accounts():
    with data_lock:
        d = load_data()
    result = {}
    for acc_id, acc in visible_accounts(d).items():
        st = bot_status.get(acc_id, {"running": False})
        result[acc_id] = {
            "name":           acc.get("name", ""),
            "method":         acc.get("method", "INSTAGRAPI"),
            "message_mode":   acc.get("message_mode", "DAKSH"),
            "target_name":    acc.get("target_name", ""),
            "session_id_set": bool(acc.get("session_id")),
            "csrf_token_set": bool(acc.get("csrf_token")),
            "proxy":          acc.get("proxy", ""),
            "groups":         acc.get("groups", ""),
            "group_names":    acc.get("group_names", ""),
            "nc_titles":      acc.get("nc_titles", ""),
            "messages":       acc.get("messages", ""),
            "msg_delay_min":  acc.get("msg_delay_min", 2),
            "msg_delay_max":  acc.get("msg_delay_max", 5),
            "nc_every_msgs":  acc.get("nc_every_msgs", 0),
            "cooldown_after": acc.get("cooldown_after", 0),
            "cooldown_dur":   acc.get("cooldown_dur", 5),
            "status": st
        }
    return jsonify(result)

@app.route("/api/admin/users")
@admin_required
def admin_users_summary():
    with data_lock:
        d = load_data()
        users = d.get("users", {})
        accounts = d.get("accounts", {})

        result = []
        for username, user in users.items():
            owned_ids = [
                {
                    "id": acc_id,
                    "name": acc.get("name", "")
                }
                for acc_id, acc in accounts.items()
                if acc.get("owner") == username
            ]
            result.append({
                "username": username,
                "created_at": user.get("created_at", ""),
                "created_at_epoch": float(user.get("created_at_epoch", 0) or 0),
                "ids": owned_ids
            })

    result.sort(key=lambda x: x["username"].lower())
    return jsonify({"success": True, "users": result})


@app.route("/api/accounts", methods=["POST"])
@login_required
def add_account():
    body = request.json
    session_id = (body.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"success": False, "error": "Session ID required"}), 400

    acc_id = str(int(time.time() * 1000))
    entry = {
        "name":           body.get("name", ""),
        "method":         body.get("method", "INSTAGRAPI"),
        "message_mode":   body.get("message_mode", "DAKSH"),
        "target_name":    body.get("target_name", ""),
        "owner":          current_owner(),
        "session_id":     session_id,
        "csrf_token":     body.get("csrf_token", ""),
        "proxy":          body.get("proxy", ""),
        "groups":         body.get("groups", ""),
        "group_names":    body.get("group_names", ""),
        "nc_titles":      body.get("nc_titles", ""),
        "messages":       body.get("messages", ""),
        "msg_delay_min":  body.get("msg_delay_min", 2),
        "msg_delay_max":  body.get("msg_delay_max", 5),
        "nc_every_msgs":  body.get("nc_every_msgs", 0),
        "cooldown_after": body.get("cooldown_after", 0),
        "cooldown_dur":   body.get("cooldown_dur", 5),
    }
                                                                           
                                                                   
    try:
        temp_cl = ig_clients.get("fetch_temp")
        if temp_cl:
            entry["session_settings"] = temp_cl.get_settings()
    except Exception:
        pass
    with data_lock:
        d = load_data()
        d["accounts"][acc_id] = entry
        save_data(d)
    return jsonify({"success": True, "id": acc_id})

@app.route("/api/accounts/<acc_id>", methods=["PUT"])
@login_required
def update_account(acc_id):
    body = request.json
    with data_lock:
        d = load_data()
        if not can_access_account(acc_id, d):
            return jsonify({"success": False, "error": "Not found"}), 404
        acc = d["accounts"][acc_id]
        for k in ["name", "method", "message_mode", "target_name", "proxy", "csrf_token", "groups", "group_names", "nc_titles",
                  "messages", "msg_delay_min", "msg_delay_max", "nc_every_msgs", "cooldown_after", "cooldown_dur"]:
            if k in body: acc[k] = body[k]
        if body.get("session_id"):
            acc["session_id"] = body["session_id"]
                                                                     
                                                                       
            acc.pop("session_settings", None)
            ig_clients.pop(acc_id, None)
        save_data(d)
    return jsonify({"success": True})

@app.route("/api/accounts/<acc_id>", methods=["DELETE"])
@login_required
def delete_account(acc_id):
    with data_lock:
        d = load_data()
        if not can_access_account(acc_id, d):
            return jsonify({"success": False, "error": "Not found"}), 404
        if acc_id in bot_stop: bot_stop[acc_id].set()
        ig_clients.pop(acc_id, None)
        d["accounts"].pop(acc_id, None)
        save_data(d)
    return jsonify({"success": True})

@app.route("/api/accounts/<acc_id>/start", methods=["POST"])
@login_required
def start_bot(acc_id):
    with data_lock:
        d = load_data()
        acc = d["accounts"].get(acc_id)
        if not can_access_account(acc_id, d):
            acc = None
    if not acc: return jsonify({"success": False, "error": "Not found"}), 404
                                                
    if acc_id in bot_threads and bot_threads[acc_id].is_alive():
        if acc_id in bot_stop: bot_stop[acc_id].set()
        bot_threads[acc_id].join(timeout=5)
        if bot_threads[acc_id].is_alive():
            return jsonify({"success": False, "error": "Bot did not stop in time, please wait a moment"})
    stop_event = threading.Event()
    bot_stop[acc_id] = stop_event
    method = acc.get("method", "INSTAGRAPI")
    if method == "AYAN MULTI GC":
        worker = ayaan_multi_gc_worker
    elif method == "RAVAN MULTI GC":
        worker = ravan_multi_gc_worker
    else:
        worker = ravan_worker if method == "RAVAN" else bot_worker
    # Run every account through its own supervisor. This prevents an
    # unexpected exception in one account from killing that account permanently.
    t = threading.Thread(
        target=supervised_account_worker,
        args=(acc_id, acc, stop_event),
        daemon=True,
        name=f"ig-worker-{acc_id}",
    )
    bot_threads[acc_id] = t
    t.start()
    return jsonify({"success": True})

@app.route("/api/accounts/<acc_id>/stop", methods=["POST"])
@login_required
def stop_bot(acc_id):
    with data_lock:
        d = load_data()
        if not can_access_account(acc_id, d):
            return jsonify({"success": False, "error": "Not found"}), 404
    if acc_id in bot_stop: bot_stop[acc_id].set()
    if acc_id in bot_status:
        bot_status[acc_id]["running"] = False
        bot_status[acc_id]["last_action"] = "Stopped"
    return jsonify({"success": True})

@app.route("/api/accounts/<acc_id>/logs")
@login_required
def get_logs(acc_id):
    with data_lock:
        d = load_data()
        if not can_access_account(acc_id, d):
            return jsonify({"logs": []}), 404
    logs = list(bot_logs.get(acc_id, []))
    return jsonify({"logs": logs})

@app.route("/api/status")
@login_required
def all_status():
    result = {}
    with data_lock:
        d = load_data()
        allowed_ids = set(visible_accounts(d).keys())
    for acc_id, st in bot_status.items():
        if acc_id not in allowed_ids:
            continue
        s = dict(st)
        if s.get("started_at") and s.get("running"):
            s["runtime_secs"] = int(time.time() - s["started_at"])
        else:
            s["runtime_secs"] = 0
        if s.get("cooldown") and s.get("cooldown_end", 0) > 0:
            s["cooldown_remaining"] = max(0, int(s["cooldown_end"] - time.time()))
        else:
            s["cooldown_remaining"] = 0
        result[acc_id] = s
    return jsonify(result)


@app.route("/api/gc-creator/ids", methods=["GET"])
@login_required
def get_gc_creator_ids():
    with data_lock:
        d = load_data()
        ids = d.get("gc_creator_ids", {})
        if session.get("login_role") == "admin":
            visible = ids
        else:
            owner = current_owner()
            visible = {k: v for k, v in ids.items() if v.get("owner") == owner}
    return jsonify({k: {"name": v.get("name", ""), "session_id_set": bool(v.get("session_id")), "proxy": v.get("proxy", "")} for k, v in visible.items()})

@app.route("/api/gc-creator/ids", methods=["POST"])
@login_required
def add_gc_creator_id():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    session_id = str(body.get("session_id") or "").strip()
    proxy = str(body.get("proxy") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "ID name is required"}), 400
    if not session_id:
        return jsonify({"success": False, "error": "Session ID is required"}), 400
    gc_id = str(uuid.uuid4().hex)
    with data_lock:
        d = load_data()
        d.setdefault("gc_creator_ids", {})[gc_id] = {
            "name": name, "owner": current_owner(), "session_id": session_id, "proxy": proxy
        }
        save_data(d)
    return jsonify({"success": True, "id": gc_id})

@app.route("/api/gc-creator/ids/<gc_id>", methods=["PUT"])
@login_required
def update_gc_creator_id(gc_id):
    body = request.get_json(silent=True) or {}
    with data_lock:
        d = load_data()
        item = d.get("gc_creator_ids", {}).get(gc_id)
        if not item or (session.get("login_role") != "admin" and item.get("owner") != current_owner()):
            return jsonify({"success": False, "error": "Not found"}), 404
        if "name" in body and str(body["name"]).strip(): item["name"] = str(body["name"]).strip()
        if "proxy" in body: item["proxy"] = str(body.get("proxy") or "").strip()
        if "session_id" in body and str(body["session_id"]).strip():
            item["session_id"] = str(body["session_id"]).strip()
            item.pop("session_settings", None)
            ig_clients.pop(f"gc:{gc_id}", None)
        save_data(d)
    return jsonify({"success": True})

@app.route("/api/gc-creator/ids/<gc_id>", methods=["DELETE"])
@login_required
def delete_gc_creator_id(gc_id):
    with data_lock:
        d = load_data()
        item = d.get("gc_creator_ids", {}).get(gc_id)
        if not item or (session.get("login_role") != "admin" and item.get("owner") != current_owner()):
            return jsonify({"success": False, "error": "Not found"}), 404
        d["gc_creator_ids"].pop(gc_id, None)
        save_data(d)
    ig_clients.pop(f"gc:{gc_id}", None)
    return jsonify({"success": True})

@app.route("/api/gc-creator/start", methods=["POST"])
@login_required
def start_gc_creator():
    body = request.get_json(silent=True) or {}
    gc_id = str(body.get("gc_id") or "").strip()
    try:
        group_count = int(body.get("group_count") or 0)
    except Exception:
        group_count = 0
    usernames = body.get("usernames") or []
    if not isinstance(usernames, list): usernames = []
    usernames = [str(x).strip().lstrip("@") for x in usernames if str(x).strip()]
    remove_username = str(body.get("remove_username") or "").strip().lstrip("@")
    message_text = str(body.get("message") or "")
    with data_lock:
        d = load_data()
        item = d.get("gc_creator_ids", {}).get(gc_id)
        if not item or (session.get("login_role") != "admin" and item.get("owner") != current_owner()):
            return jsonify({"success": False, "error": "GC Creator ID not found"}), 404
    if group_count < 1 or group_count > 50:
        return jsonify({"success": False, "error": "GC count must be between 1 and 50"}), 400
    if len(usernames) < 2:
        return jsonify({"success": False, "error": "Minimum 2 usernames required"}), 400
    if not remove_username:
        return jsonify({"success": False, "error": "Remove username is required"}), 400
    if remove_username not in usernames:
        return jsonify({"success": False, "error": "Remove username must be one of the entered members"}), 400
    with gc_creator_lock:
        for job in gc_creator_jobs.values():
            if job.get("running") and job.get("gc_id") == gc_id:
                return jsonify({"success": False, "error": "GC Creator is already running for this ID"}), 409
        job_id = uuid.uuid4().hex
        gc_creator_jobs[job_id] = {"running": True, "done": 0, "total": group_count, "logs": [], "error": "", "gc_id": gc_id}
    threading.Thread(
        target=gc_creator_worker,
        args=(job_id, gc_id, group_count, usernames, remove_username, message_text),
        daemon=True
    ).start()
    return jsonify({"success": True, "job_id": job_id})

@app.route("/api/gc-creator/status/<job_id>")
@login_required
def gc_creator_status(job_id):
    with gc_creator_lock:
        job = gc_creator_jobs.get(job_id)
        if not job: return jsonify({"success": False, "error": "Job not found"}), 404
        gc_id = job.get("gc_id")
    with data_lock:
        d = load_data()
        item = d.get("gc_creator_ids", {}).get(gc_id)
        if not item or (session.get("login_role") != "admin" and item.get("owner") != current_owner()):
            return jsonify({"success": False, "error": "Access denied"}), 403
    with gc_creator_lock:
        job = dict(gc_creator_jobs.get(job_id, {}))
    return jsonify({"success": True, "running": bool(job.get("running")), "done": int(job.get("done", 0)), "total": int(job.get("total", 0)), "logs": list(job.get("logs", [])), "error": job.get("error", "")})

@app.route("/api/fetch-groups", methods=["POST"])
@login_required
def fetch_groups():
    body = request.json or {}

    session_id = (body.get("session_id") or "").strip()
    acc_id = (body.get("acc_id") or "fetch_temp").strip()
    proxy = (body.get("proxy") or "").strip() or None

    if not session_id:
        return jsonify({
            "success": False,
            "error": "Session ID required"
        }), 400

    try:
        # RAVAN uses the same working fetch implementation supplied by the user.
        if body.get("method") in ("RAVAN", "RAVAN MULTI GC"):
            groups = ravan_fetch_groups(session_id, proxy)
        else:
            # FETCH must always use the session ID entered in the form.
            # Do not reuse the shared "fetch_temp" client because that client
            # may belong to a previously fetched account.
            if acc_id == "fetch_temp":
                ig_clients.pop("fetch_temp", None)
            else:
                # If the session ID was changed while editing an account,
                # invalidate the cached client so the new session is used.
                ig_clients.pop(acc_id, None)

            cl = Client()
            if proxy:
                cl.set_proxy(proxy)

            cl.login_by_sessionid(decode_session(session_id))
            ig_clients[acc_id] = cl

            threads = cl.direct_threads(amount=50)
            groups = []

            for t in threads:
                if t.is_group:
                    groups.append({
                        "id": str(t.id),
                        "name": t.thread_title or str(t.id)
                    })

            if acc_id != "fetch_temp":
                try:
                    persist_client_settings(acc_id, cl)
                except Exception:
                    pass

        return jsonify({
            "success": True,
            "groups": groups
        })

    except Exception as e:
        if acc_id == "fetch_temp":
            ig_clients.pop("fetch_temp", None)
        else:
            ig_clients.pop(acc_id, None)

        return jsonify({
            "success": False,
            "error": "Could not fetch groups. Check the credentials and try again."
        }), 400



SELF_URL = (os.getenv("SELF_URL") or os.getenv("PUBLIC_URL") or "").strip()
SELF_PING_INTERVAL = 120

def self_ping_worker():
    while True:
        try:
            if SELF_URL:
                req = urllib.request.Request(
                    SELF_URL,
                    headers={"User-Agent": "SelfPing/1.0"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    resp.read(1)
                    if 200 <= resp.status < 400:
                        print("✅ SELF PING SUCCESSFUL", flush=True)
        except Exception:
            pass
        time.sleep(max(30, SELF_PING_INTERVAL))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    if SELF_URL:
        threading.Thread(target=self_ping_worker, daemon=True).start()
    logging.getLogger("werkzeug").disabled = True
    logging.getLogger("gunicorn.access").disabled = True
    app.run(host="0.0.0.0", port=port, debug=False)  