# Automotive Cybersecurity TARA Assistant (Case Study 3)

An AI-assisted Threat Analysis and Risk Assessment (ISO/SAE 21434) tool built from the CS3 reference solution and the technical report.
It helps a cybersecurity engineer go from an architecture description to a cited, reviewable, traceable TARA draft.
**All output is advisory: nothing is final until an authorised engineer approves it.**

## What it does (report sections 3 to 7)

| Step | What happens | How |
|---|---|---|
| Dashboard | Current project totals, stored recommendation review statuses, and risk distribution | Streamlit, values read from the API |
| 1. Ingest | PDF / DOCX / XLSX / CSV / JSON / MD / TXT documents are cleaned, chunked, embedded, and recorded as background jobs with success/failure status | `app/knowledge.py`, ChromaDB and SQLite job records |
| 2. Assets | Candidate assets and trust boundaries from the asset catalogue, communication matrix and architecture text, each with citations; search, filter and authorized editing are available | retrieval + rules, SQLite review history |
| 3. Attack surface | Interface-to-attack-vector mapping (CAN, Ethernet, diagnostics, OTA, backend, hardware), linked to assets and trust boundaries; taxonomy entries are explicitly labeled as inferences, not confirmed exposures | `app/taxonomy.py` rules + cited evidence |
| 4. Threats | Filtered top-k retrieval from the approved threat library and prior TARA; every scenario cites its library entry; unsupported questions are flagged, not guessed | RAG, `app/agent.py` |
| 5. Risk | Impact (S/F/O/P) and attack-potential factors are proposed with rationale; **the risk value is always computed by the deterministic, versioned pilot matrix**, and saved ratings can be recalculated | `app/risk.py` |
| 6. Mitigations | Controls and requirement drafts only from the approved control catalogue, with test links | RAG + catalogue |
| 7. Review | Approve / reject / request changes per asset, threat, rating and mitigation; edits to candidates, ratings and draft requirements are persisted and return the item to pending review | SQLite `reviews` + `audit_log` |
| 8. Traceability | Asset -> threat -> risk -> control -> test table, project/document/asset/surface inventories, review statuses, evidence and coverage gaps, PDF and CSV export | `app/reports.py` |

Out of scope and enforced (`app/guard.py`): writing exploits / active exploitation, and autonomous acceptance. Such requests are declined and mitigation guidance is offered instead.

## Quick start

```bash
pip install -r requirements.txt
./scripts/run_local.sh            # API on :8000, UI on http://localhost:8501
```

On Windows PowerShell, use `.\scripts\run_local.ps1` to launch both services in separate processes (ports 8000 and 8501 must be free). `.env.example` lists supported local settings; set them in the shell before launching if needed.

In the UI: managers can select the **Cybersecurity manager** role to create a project from the sidebar. Review the **Dashboard** for current stored metrics, then use **Architecture input -> Load sample TCU-Gen2 documents -> Run full TARA workflow** and walk through the pages from the sidebar to review items.
Or follow your own path: ask *"Suggest threat scenarios for the OTA update channel of the telematics unit"* on **Threat scenarios**.

Manual start: `python -m uvicorn app.api:app --host 127.0.0.1 --port 8000` and, in a second shell, set `$env:TARA_API_URL="http://127.0.0.1:8000"` then run `python -m streamlit run ui/streamlit_app.py --server.address 127.0.0.1 --server.port 8501` (PowerShell).
API docs: http://localhost:8000/docs.

Docker: `docker compose up --build` (add `--profile llm` for a private Ollama container). The API and LLM live on an internal network without internet access; only the UI is published, on localhost.

## Engines: what runs where

The report specifies a privately hosted open-weight LLM and BGE embeddings. Both are pluggable and detected at start-up; the header of every result shows what was used.

| Component | Preferred | Automatic fallback |
|---|---|---|
| LLM | Local Ollama (`TARA_LLM_BASE_URL`, `TARA_LLM_MODEL`, e.g. Llama / Mistral / Qwen) or any OpenAI-compatible local server (vLLM, llama.cpp) | `offline-rules`: deterministic, library-grounded output (same schemas, no generation) |
| Embeddings | BGE via Sentence Transformers (`pip install -r requirements-bge.txt`) | local hashing embedder (no model download) |
| Vector store | ChromaDB, persistent | n/a |

With an LLM available it is used for: selecting and justifying threats from retrieved entries, proposing ratings, and wording requirements. Its output is validated: unknown ids are dropped, invalid ratings fall back to library defaults, and a risk value claimed by the model is ignored (see `tests/test_agent.py`). No external API is ever called.

## Configuration (environment variables)

`TARA_DATA_DIR` (default `data/runtime`), `TARA_UPLOAD_MAX_BYTES` (default 25 MiB), `TARA_LLM_BACKEND` (auto | ollama | openai | offline), `TARA_LLM_BASE_URL`, `TARA_LLM_MODEL`, `TARA_LLM_TEMPERATURE` (0.1), `TARA_EMBED_BACKEND` (auto | bge | hash), `TARA_EMBED_MODEL`, `TARA_TOP_K`, `TARA_CHUNK_MAX_TOKENS`, `TARA_CHUNK_OVERLAP`, `TARA_RISK_MATRIX_VERSION`, `TARA_API_URL` (UI).

`TARA_RISK_MATRIX` may override the matrix with JSON mapping each impact level to four integer scores (1–5), ordered as feasibility `Very low`, `Low`, `Medium`, `High`. Set a new `TARA_RISK_MATRIX_VERSION` whenever rules change, restart the API, then use **Risk assessment -> Recalculate stored ratings with current matrix**. The bundled scales and matrix are illustrative pilot rules, not an official ISO/SAE 21434 scoring formula; expert validation is required before operational use.

Uploads from the UI are submitted to `POST /ingestion/upload`; poll `GET /ingestion/status/{job_id}` for persisted `pending`, `running`, `completed`, or `failed` status and any parsing error. The original project-scoped upload endpoint remains available. API aliases also include `/analyze-assets`, `/attack-surfaces`, `/threats/generate`, `/risk/assess`, `/mitigations/generate`, and `/reports/traceability`.

## Using your own data

Upload files on **Architecture input**. Detection:
* `.md/.txt/.pdf/.docx`: architecture description (headings such as `## Interface: OTA` set the interface metadata)
* `.csv/.xlsx` with an `asset_id` column: asset catalogue (columns: asset_id, name, tag, type, interface, properties, description, owner, version, review_date); otherwise communication matrix (message, msg_id, bus, protocol, sender, receiver, security, signals, interface)
* `.json`: approved knowledge with `doc_type` of `threat_library`, `prior_tara` or `controls` (see `data/sample/` for the schema). Rebuilt on re-upload.

The bundled threat library, control catalogue and TCU-Gen2 files are **illustrative sample data written for this pilot**, not an approved library. Replace them with your organisation's reviewed material before real use.

## Security and governance

* Role permissions: engineer (run, review), manager (adds project creation), auditor (read-only). The UI role selector is a development convenience, not authentication. The pilot accepts the `X-User` header; do not expose it beyond localhost or use it for production authorization. Put the API behind verified SSO / an API gateway for real use.
* Every run, decision, rationale, decline and export is written to the audit trail (SQLite). Review history records the actor, timestamp, previous status, new status and rationale. Edits to assets, threats and mitigation drafts return the item to pending review.
* Ingestion jobs and errors are stored in SQLite. Uploaded files are processed in memory; no upload is written to a user-controlled path.
* Retrieved text is treated as data in prompts, but prompt injection through uploaded documents is not fully solved; keep ingestion restricted to approved sources.
* Not yet implemented: PostgreSQL, enterprise UI, SSO, requirements/test tool integrations (the report's phases 3 to 4).

## Tests and evaluation

```bash
pip install -r requirements-dev.txt
pytest                         # 51 tests: risk matrix, guard, chunking, workflow, RBAC, ingestion jobs, edits, reports, LLM validation
python scripts/evaluate.py     # runs the 5 scenarios + metrics -> docs/evaluation_results.md
```

`docs/evaluation_results.md` has the measured results for report section 5. The coverage numbers are measured against an illustrative baseline for the sample data; they are not evidence of real-world coverage.

## Layout

```
app/        config, taxonomy, risk, guard, knowledge (ingest), embeddings, vectorstore, llm, db, agent, reports, api
ui/         Streamlit pilot UI
data/sample sample architecture, comm matrix, asset catalogue, threat library v1.2, prior TARA, control catalogue
tests/      pytest suite          scripts/  run_local.sh, evaluate.py          docs/  evaluation results
```
