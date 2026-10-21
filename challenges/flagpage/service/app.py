#!/usr/bin/env python3
"""
FlagPage — the A/D service. A tiny web page that displays the current flag.

The gameserver's checker plants a flag each tick (POST tick+flag) and verifies
it is shown on the page (GET). The "vulnerability" is that the page shows the
flag to anyone who connects — so attackers steal it by simply reading the page.
Flags are kept per tick in memory; the home page shows the most recent one.
"""
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)
FLAGS = {}                      # tick(str) -> flag
CURRENT = {"tick": None, "flag": None}

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlagPage</title>
<style>
  :root{--bg:#07061a;--card:#110d2c;--border:#241f4d;--fg:#ecefff;--accent:#ffb800}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:radial-gradient(900px 500px at 50% -10%,rgba(255,184,0,.1),transparent 60%),#07061a;
    color:var(--fg);font-family:"Manrope",system-ui,sans-serif}
  .card{background:var(--card);border:1px solid var(--border);border-radius:16px;
    padding:38px 44px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}
  h1{font-size:15px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin:0 0 18px}
  .flag{font-family:"JetBrains Mono",ui-monospace,monospace;font-size:20px;
    background:#0c0a22;border:1px solid var(--border);border-radius:10px;padding:16px 22px;
    word-break:break-all;color:#d7deff}
  .tick{margin-top:14px;font-size:12px;color:#6a64a0}
</style></head><body>
  <div class="card">
    <h1>⚑ Current flag</h1>
    {% if flag %}<div class="flag">{{ flag }}</div>
    <div class="tick">tick {{ tick }}</div>
    {% else %}<div class="flag">no flag yet</div>{% endif %}
  </div>
</body></html>"""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        tick = request.form.get("tick")
        flag = request.form.get("flag")
        if flag:
            FLAGS[str(tick)] = flag
            CURRENT["tick"] = tick
            CURRENT["flag"] = flag
        return "stored\n", 200
    # GET: a specific tick (for the checker) or the latest (for everyone)
    t = request.args.get("tick")
    if t is not None and str(t) in FLAGS:
        return render_template_string(PAGE, flag=FLAGS[str(t)], tick=t)
    return render_template_string(PAGE, flag=CURRENT["flag"], tick=CURRENT["tick"])


@app.route("/health")
def health():
    return "ok\n", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "9100")))
