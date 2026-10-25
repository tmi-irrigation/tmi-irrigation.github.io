"""Recompute the script hash in index.html's Content-Security-Policy.
Run after every change to the <script> block, or the page will refuse to run its own code."""
import base64, hashlib, pathlib, re

p = pathlib.Path(__file__).resolve().parent.parent / "index.html"
s = p.read_text(encoding="utf-8")
script = re.search(r"<script>(.*?)</script>", s, re.S).group(1)
h = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()
s2, n = re.subn(r"script-src 'sha256-[^']+'", f"script-src 'sha256-{h}'", s)
if n != 1:
    raise SystemExit("CSP script-src not found exactly once")
p.write_text(s2, encoding="utf-8")
print("script hash:", h)
