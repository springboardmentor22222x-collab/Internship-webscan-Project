# app.py  -- full replacement (creates templates/static if missing, ML or heuristic detector)
import os
import joblib
import re
from flask import Flask, render_template, request, redirect, url_for, flash

# ---------- Project paths ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
STATIC_CSS_DIR = os.path.join(STATIC_DIR, "css")
MODEL_PATH = os.path.join(BASE_DIR, "models", "xss_detector.joblib")

# ---------- Ensure folders and minimal files exist ----------
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_CSS_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "models"), exist_ok=True)  # models folder exists even if empty

# Create a minimal base.html if missing
base_html_path = os.path.join(TEMPLATES_DIR, "base.html")
if not os.path.exists(base_html_path):
    with open(base_html_path, "w", encoding="utf-8") as f:
        f.write("""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>XSS + ML Demo</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
  <nav>
    <a href="{{ url_for('index') }}">Home</a> |
    <a href="{{ url_for('stored_xss') }}">Stored XSS</a> |
    <a href="{{ url_for('reflected_xss') }}">Reflected XSS</a>
  </nav>

  <div class="flash">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <ul>
        {% for category, msg in messages %}
          <li class="{{ category }}">{{ msg }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
  </div>

  <div class="content">
    {% block content %}{% endblock %}
  </div>
</body>
</html>
""")

# Create index.html if missing
index_html_path = os.path.join(TEMPLATES_DIR, "index.html")
if not os.path.exists(index_html_path):
    with open(index_html_path, "w", encoding="utf-8") as f:
        f.write("""{% extends "base.html" %}
{% block content %}
  <h1>XSS Lab + ML</h1>
  <p>Quick demo: try Stored and Reflected pages.</p>
{% endblock %}""")

# Create stored.html if missing
stored_html_path = os.path.join(TEMPLATES_DIR, "stored.html")
if not os.path.exists(stored_html_path):
    with open(stored_html_path, "w", encoding="utf-8") as f:
        f.write("""{% extends "base.html" %}
{% block content %}
<h2>Stored XSS Demo</h2>
<form method="post">
  Name:<br>
  <input type="text" name="name" /><br><br>
  Message:<br>
  <textarea name="message" rows="4" cols="50"></textarea><br><br>
  <button type="submit">Post</button>
</form>

<hr>
<h3>Posts</h3>
{% for p in messages %}
  <div class="post">
    <strong>{{ p.name|safe }}</strong>: <span>{{ p.message|safe }}</span>
  </div>
{% else %}
  <p>No posts yet.</p>
{% endfor %}
{% endblock %}""")

# Create reflected.html if missing
reflected_html_path = os.path.join(TEMPLATES_DIR, "reflected.html")
if not os.path.exists(reflected_html_path):
    with open(reflected_html_path, "w", encoding="utf-8") as f:
        f.write("""{% extends "base.html" %}
{% block content %}
<h2>Reflected XSS Demo</h2>
<form method="post">
  Query: <input type="text" name="q" />
  <button type="submit">Search</button>
</form>

<hr>
{% if q %}
  <p>Result: {{ q|safe }}</p>
{% endif %}
{% endblock %}""")

# Create a minimal CSS if missing
css_path = os.path.join(STATIC_CSS_DIR, "style.css")
if not os.path.exists(css_path):
    with open(css_path, "w", encoding="utf-8") as f:
        f.write("""body { font-family: Arial, sans-serif; margin: 20px; }
nav { margin-bottom: 15px; }
.flash ul { list-style: none; padding: 0; }
.flash li.success { color: green; }
.flash li.danger { color: red; }
.post { border: 1px solid #ddd; padding: 8px; margin-bottom: 6px; border-radius: 4px; }""")

# ---------- Create the Flask app with explicit template/static folders ----------
app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.secret_key = 'dev-secret-key'  # change in production

# ---------- Debug prints so you can see what the app is using ----------
print("APP BASE DIR         :", BASE_DIR)
print("TEMPLATES DIR        :", TEMPLATES_DIR)
print("STATIC DIR           :", STATIC_DIR)
print("STATIC CSS DIR       :", STATIC_CSS_DIR)
print("MODEL PATH           :", MODEL_PATH)
try:
    print("Templates listing     :", os.listdir(TEMPLATES_DIR))
except Exception as e:
    print("Cannot list templates:", e)

# ---------- ML model loader (tries to load joblib model) ----------
model = None
vectorizer = None
if os.path.exists(MODEL_PATH):
    try:
        data = joblib.load(MODEL_PATH)
        model = data.get("model")
        vectorizer = data.get("vectorizer")
        print("Loaded ML model from:", MODEL_PATH)
    except Exception as e:
        print("Failed loading ML model:", e)

# ---------- Fallback heuristic detector (simple rule-based) ----------
SUSPICIOUS_TOKENS = [
    "<script", "onerror", "onload", "javascript:", "<img", "<svg", "<iframe", "alert(", "<body", "document.cookie"
]
def is_suspicious_heuristic(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    for tok in SUSPICIOUS_TOKENS:
        if tok in t:
            return True
    special_chars = sum(1 for ch in t if ch in "<>\"'")
    if special_chars >= 4:
        return True
    if re.search(r"<\s*script\b|on\w+\s*=|javascript\s*:", t):
        return True
    return False

def ml_score(text: str):
    """Return score 0..1 if ML available, else None."""
    if model is None or vectorizer is None:
        return None
    try:
        X = vectorizer.transform([text])
        return float(model.predict_proba(X)[0,1])
    except Exception as e:
        print("ML scoring error:", e)
        return None

# ---------- In-memory storage (demo only) ----------
stored_messages = []

# ---------- Routes ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stored', methods=['GET', 'POST'])
def stored_xss():
    if request.method == 'POST':
        name = request.form.get('name', '')
        message = request.form.get('message', '')
        combined = (name + ' ' + message).strip()

        # 1) Try ML model if available
        score = ml_score(combined)
        if score is not None:
            threshold = 0.5
            if score >= threshold:
                flash(f"Input blocked by ML (suspicious score={score:.2f})", 'danger')
                return redirect(url_for('stored_xss'))

        # 2) If ML not available, use heuristic detector
        else:
            if is_suspicious_heuristic(combined):
                flash("Input blocked by heuristic detector (likely XSS).", "danger")
                return redirect(url_for('stored_xss'))

        # Save (vulnerable demonstration; templates use |safe intentionally)
        stored_messages.append({'name': name, 'message': message})
        flash('Posted successfully.', 'success')
        return redirect(url_for('stored_xss'))

    return render_template('stored.html', messages=stored_messages)

@app.route('/reflected', methods=['GET', 'POST'])
def reflected_xss():
    q = None
    if request.method == 'POST':
        q = request.form.get('q', '')

        score = ml_score(q)
        if score is not None:
            if score >= 0.5:
                flash(f"Input blocked by ML (suspicious score={score:.2f})", 'danger')
                return redirect(url_for('reflected_xss'))
        else:
            if is_suspicious_heuristic(q):
                flash("Input blocked by heuristic detector (likely XSS).", "danger")
                return redirect(url_for('reflected_xss'))

    return render_template('reflected.html', q=q)

# Simple plain route for testing without templates
@app.route('/plain')
def plain():
    return "<h1>Plain route OK</h1>"

# ---------- Run ----------
if __name__ == '__main__':
    app.run(debug=True)
