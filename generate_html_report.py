from pathlib import Path
import html

src = Path("reports/threat_hunting_review.md")
out = Path("reports/threat_hunting_review.html")
text = src.read_text(encoding="utf-8")
page = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Threat Hunting Review</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      margin: 0;
      padding: 24px;
    }}
    .container {{
      max-width: 1100px;
      margin: 0 auto;
      background: #111827;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 24px;
    }}
    pre {{
      white-space: pre-wrap;
      word-wrap: break-word;
      background: #020817;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 18px;
      color: #e2e8f0;
    }}
  </style>
</head>
<body>
  <div class=\"container\">
    <h1>Threat Hunting Review</h1>
    <pre>{html.escape(text)}</pre>
  </div>
</body>
</html>
"""
out.write_text(page, encoding="utf-8")
print(f"HTML written: {out} ({out.stat().st_size} bytes)")
