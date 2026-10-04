---
title: ScamShield
sdk: docker
app_port: 7860
---

# 🛡️ ScamShield

ScamShield is an agent-based scam investigation app. The main feature is **file/photo upload**:
drop or browse for screenshots, PDFs, `.eml` email files, or `.txt` files, or paste a message.

The backend uses FastAPI + a Gemini-powered LangChain agent. The agent has 10 specialised tools:
message analysis, URL analysis, URL reputation, RDAP domain age, sender checks,
known-scam similarity, evidence extraction, deterministic risk calculation,
action planning, and report generation. Scoring and numbers stay in deterministic Python;
the model explains the findings rather than inventing a score.

## Run locally (Windows / VS Code)

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
$env:GOOGLE_API_KEY="YOUR_GEMINI_KEY"
# Optional:
# $env:SAFE_BROWSING_API_KEY="YOUR_SAFE_BROWSING_KEY"

uvicorn server:app --reload --port 8000
```

Open http://localhost:8000

The API endpoints are:
- `GET /api/health`
- `POST /api/analyze` as multipart form data with optional `text` and up to 4 files.

## Deploy

### Hugging Face Docker Space
Create a Docker Space and upload the files in this folder. Add `GOOGLE_API_KEY`
under **Settings → Secrets**. `SAFE_BROWSING_API_KEY` is optional.

The container listens on `$PORT` and defaults to 7860, so it works with Hugging Face
and can also be used on Render.

### Separate frontend
If you later host `index.html` separately (for example on Vercel), set:

```html
<script>window.SCAMSHIELD_API="https://your-backend-url"</script>
```

before the main script, and configure:

```text
ALLOWED_ORIGINS=https://your-frontend-domain
```

on the backend.

## Safety behaviour

- A missing external lookup is shown as **not checked**, never silently treated as safe.
- The URL analyser does not open links.
- Risk scores are heuristic estimates, not guarantees.
- The UI explicitly warns users to crop/blur OTPs, passwords and card numbers before uploading.

## Main demo flow

1. Drop a scam screenshot.
2. Gemini vision extracts the visible content.
3. The agent runs the specialised investigation tools.
4. Deterministic Python calculates the risk score.
5. The UI shows the risk gauge, red flags, evidence, actions, investigation trace, and a copyable report.
