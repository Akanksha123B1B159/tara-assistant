"""FastAPI service layer. Identity is taken from the X-User header (pilot); role-based access is enforced per endpoint.
For enterprise use put this behind SSO / an API gateway that sets the header."""
import re
import uuid
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, Header, HTTPException, Response, UploadFile
from pydantic import BaseModel, Field

from . import config, db, reports
from .agent import AgentError, TaraAgent

_agent: TaraAgent | None = None


def agent() -> TaraAgent:
    global _agent
    if _agent is None:
        _agent = TaraAgent()
    return _agent


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    agent().ensure_global_knowledge()
    if not db.list_projects():  # pilot convenience: a sample project is always available
        db.create_project("TCU-Gen2", "TCU-Gen2 (sample)", "Sample telematics control unit used for the pilot (illustrative data).", "system")
    yield


app = FastAPI(title="Automotive Cybersecurity TARA Assistant", version="1.0.0", lifespan=lifespan,
              description="AI-assisted ISO/SAE 21434 TARA support. All output is advisory and requires engineer approval.")


def user_with(perm: str):
    def dep(x_user: str = Header(default="engineer1")):
        u = db.get_user(x_user)
        if not u:
            raise HTTPException(401, "Unknown user")
        if not db.allowed(u["role"], perm):
            raise HTTPException(403, f"Role '{u['role']}' may not perform this action")
        return u
    return dep


@app.exception_handler(AgentError)
async def agent_error(_, exc: AgentError):
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": str(exc)}, status_code=exc.code)


def project_or_404(pid: str):
    p = db.get_project(pid)
    if not p:
        raise HTTPException(404, "Unknown project")
    return p


class ProjectIn(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{2,40}$")
    name: str
    description: str = ""


class ThreatQuery(BaseModel):
    query: str = Field(min_length=3, max_length=1000)
    interfaces: list[str] | None = None
    top_k: int | None = Field(default=None, ge=1, le=20)


class ReviewIn(BaseModel):
    decision: str = Field(pattern="^(approve|reject|needs_change)$")
    rationale: str = ""


class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=1000)


class ThreatRefIn(BaseModel):
    threat_ref: str = Field(min_length=1, max_length=100)


class AssetEditIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    type: str | None = Field(default=None, min_length=1, max_length=100)
    interface: str | None = Field(default=None, min_length=1, max_length=100)
    properties: str | None = Field(default=None, max_length=2000)
    owner: str | None = Field(default=None, max_length=200)
    rationale: str = Field(min_length=3, max_length=1000)

    model_config = {"extra": "forbid"}


class RecommendationEditIn(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    rationale: str | None = Field(default=None, max_length=4000)
    requirement: str | None = Field(default=None, min_length=1, max_length=4000)
    assumptions: list[str] | None = Field(default=None, max_length=20)
    alternatives: list[str] | None = Field(default=None, max_length=20)
    impact: dict[str, str] | None = None
    factors: dict[str, str] | None = None
    edit_rationale: str = Field(min_length=3, max_length=1000)

    model_config = {"extra": "forbid"}


def _process_ingestion_job(job_id, project_id, filename, data, doc_type, username):
    db.update_ingestion_job(job_id, "running")
    try:
        result = agent().ingest_bytes(project_id, filename, data, doc_type, username)
        db.update_ingestion_job(job_id, "completed", result=result)
    except Exception as exc:
        db.update_ingestion_job(job_id, "failed", error=f"{type(exc).__name__}: {exc}"[:1000])
        db.audit(username, project_id, "ingest_document_failed", filename, {"job_id": job_id, "error_type": type(exc).__name__})


# ------------------------------------------------------------------ system
@app.get("/health")
def health():
    a = agent()
    return {"status": "ok", "llm_engine": a.llm.engine, "embedder": a.embedder.name,
            "global_chunks": a.store.count(project=config.GLOBAL_SCOPE), "advisory_only": True}


@app.get("/risk/matrix")
def risk_matrix(u=Depends(user_with("read"))):
    from . import risk
    return {
        "version": risk.MATRIX_VERSION,
        "is_official_iso_formula": False,
        "rows": risk.RISK_MATRIX,
        "impact_levels": risk.IMPACT_LEVELS,
        "feasibility_levels": risk.FEASIBILITY_LEVELS,
        "factor_options": {name: list(options) for name, options in risk.FACTORS.items()},
        "labels": risk.RISK_LABELS,
    }


@app.get("/users")
def users():
    with db.conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM users")]


# ------------------------------------------------------------------ projects & documents
@app.get("/projects")
def projects(u=Depends(user_with("read"))):
    return db.list_projects()


@app.post("/projects", status_code=201)
def create_project(p: ProjectIn, u=Depends(user_with("project"))):
    if db.get_project(p.id):
        raise HTTPException(409, "Project already exists")
    db.create_project(p.id, p.name, p.description, u["username"])
    db.audit(u["username"], p.id, "create_project", p.id)
    return db.get_project(p.id)


@app.post("/projects/{pid}/documents")
async def upload_document(pid: str, file: UploadFile = File(...), doc_type: str | None = Form(default=None), u=Depends(user_with("ingest"))):
    project_or_404(pid)
    data = await file.read()
    if not data:
        raise HTTPException(422, "Uploaded file is empty")
    if len(data) > config.UPLOAD_MAX_BYTES:
        raise HTTPException(413, f"File too large ({config.UPLOAD_MAX_BYTES} byte limit)")
    safe = re.sub(r"[^\w.\-]", "_", file.filename or "upload")
    try:
        return agent().ingest_bytes(pid, safe, data, doc_type, u["username"])
    except (ValueError, KeyError) as exc:
        raise HTTPException(422, f"Could not parse document: {exc}")


@app.post("/ingestion/upload", status_code=202)
async def start_ingestion(
    background_tasks: BackgroundTasks,
    project_id: str = Form(...),
    file: UploadFile = File(...),
    doc_type: str | None = Form(default=None),
    u=Depends(user_with("ingest")),
):
    project_or_404(project_id)
    data = await file.read()
    if not data:
        raise HTTPException(422, "Uploaded file is empty")
    if len(data) > config.UPLOAD_MAX_BYTES:
        raise HTTPException(413, f"File too large ({config.UPLOAD_MAX_BYTES} byte limit)")
    filename = re.sub(r"[^\w.\-]", "_", file.filename or "upload")
    job_id = str(uuid.uuid4())
    db.create_ingestion_job(job_id, project_id, filename, u["username"])
    background_tasks.add_task(_process_ingestion_job, job_id, project_id, filename, data, doc_type, u["username"])
    db.audit(u["username"], project_id, "ingestion_job_created", filename, {"job_id": job_id})
    return {"job_id": job_id, "project_id": project_id, "filename": filename, "status": "pending"}


@app.get("/ingestion/status/{job_id}")
def ingestion_status(job_id: str, u=Depends(user_with("read"))):
    job = db.get_ingestion_job(job_id)
    if not job:
        raise HTTPException(404, "Unknown ingestion job")
    project_or_404(job["project_id"])
    return job


@app.post("/projects/{pid}/documents/sample")
def load_sample(pid: str, u=Depends(user_with("ingest"))):
    project_or_404(pid)
    return agent().load_sample_project(pid, u["username"])


@app.get("/projects/{pid}/documents")
def documents(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.list_documents(pid)


# ------------------------------------------------------------------ workflow steps
@app.post("/projects/{pid}/analyze-assets")
@app.post("/projects/{pid}/assets/identify")
def identify(pid: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().identify_assets(pid, u["username"])


@app.get("/projects/{pid}/assets")
def assets(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return {"assets": db.get_items(pid, "asset"), "boundaries": db.get_items(pid, "boundary")}


@app.post("/projects/{pid}/assets/{item_id}/edit")
def edit_asset(pid: str, item_id: int, edit: AssetEditIn, u=Depends(user_with("review"))):
    project_or_404(pid)
    fields = edit.model_dump(exclude_unset=True)
    rationale = fields.pop("rationale")
    if not fields:
        raise HTTPException(422, "Provide at least one asset field to edit")
    if any(value is None for value in fields.values()) or not rationale.strip():
        raise HTTPException(422, "Edited fields must not be null and an edit rationale is required")
    item = db.get_item_by_id(pid, item_id)
    if not item or item["kind"] != "asset":
        raise HTTPException(404, "Unknown asset")
    data = {**item["data"], **fields}
    updated = db.edit_item(pid, item_id, u["username"], data, rationale)
    changed = sorted(fields)
    db.audit(u["username"], pid, "edit_asset", item["ref"], {
        "changed_fields": changed, "rationale": rationale,
        "previous_status": item["status"], "new_status": "pending",
    })
    return updated


@app.post("/projects/{pid}/items/{item_id}/edit")
def edit_recommendation(pid: str, item_id: int, edit: RecommendationEditIn, u=Depends(user_with("review"))):
    project_or_404(pid)
    item = db.get_item_by_id(pid, item_id)
    if not item or item["kind"] not in ("threat", "rating", "mitigation"):
        raise HTTPException(404, "Unknown editable recommendation")
    values = edit.model_dump(exclude_unset=True)
    edit_rationale = values.pop("edit_rationale")
    allowed_fields = {
        "threat": {"title", "description", "rationale", "assumptions", "alternatives"},
        "mitigation": {"title", "requirement", "assumptions"},
        "rating": {"impact", "factors", "rationale"},
    }[item["kind"]]
    changed = set(values)
    if not changed:
        raise HTTPException(422, "Provide at least one recommendation field to edit")
    if changed - allowed_fields or any(value is None for value in values.values()) or not edit_rationale.strip():
        raise HTTPException(422, "Edited fields are not valid for this item or are empty")
    data = {**item["data"], **values}
    if item["kind"] == "rating":
        from . import risk
        if set(data["impact"]) != set(risk.IMPACT_CATEGORIES) or set(data["factors"]) != set(risk.FACTORS):
            raise HTTPException(422, "Rating edits must include all impact categories and attack-potential factors")
        try:
            data.update(risk.compute(data["impact"], data["factors"]))
        except risk.RiskInputError as exc:
            raise HTTPException(422, str(exc)) from exc
        data["matrix_version"] = risk.MATRIX_VERSION
        data["rating_source"] = "Engineer-edited proposal"
        data["approval_state"] = "Pending human approval"
    updated = db.edit_item(pid, item_id, u["username"], data, edit_rationale.strip())
    db.audit(u["username"], pid, "edit_recommendation", f"{item['kind']}:{item['ref']}",
             {"changed_fields": sorted(changed), "rationale": edit_rationale.strip(),
              "previous_status": item["status"], "new_status": "pending"})
    return updated


@app.post("/projects/{pid}/attack-surface/map")
def map_surface(pid: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().map_attack_surface(pid, user=u["username"])


@app.get("/projects/{pid}/attack-surfaces")
@app.get("/projects/{pid}/attack-surface")
def surface(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_items(pid, "surface")


@app.post("/projects/{pid}/threats/generate")
@app.post("/projects/{pid}/threats/recommend")
def recommend(pid: str, q: ThreatQuery, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().recommend_threats(pid, q.query, q.interfaces, q.top_k, u["username"])


@app.get("/projects/{pid}/threats")
def threats(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_items(pid, "threat")


@app.post("/projects/{pid}/threats/{ref}/assess")
def assess(pid: str, ref: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().assess_risk(pid, ref, u["username"])


@app.post("/projects/{pid}/risk/assess")
def assess_risk_compat(pid: str, body: ThreatRefIn, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().assess_risk(pid, body.threat_ref, u["username"])


@app.post("/projects/{pid}/risk/recalculate")
@app.post("/projects/{pid}/ratings/recalculate")
def recalculate_risk(pid: str, body: ThreatRefIn, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().recalculate_risk(pid, body.threat_ref, u["username"])


@app.get("/projects/{pid}/ratings")
def ratings(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_items(pid, "rating")


@app.post("/projects/{pid}/threats/{ref}/mitigations")
def mitigations(pid: str, ref: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().recommend_mitigations(pid, ref, u["username"])


@app.post("/projects/{pid}/mitigations/generate")
def generate_mitigations_compat(pid: str, body: ThreatRefIn, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().recommend_mitigations(pid, body.threat_ref, u["username"])


@app.get("/projects/{pid}/mitigations")
def list_mitigations(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_items(pid, "mitigation")


@app.post("/projects/{pid}/workflow/run")
def run_workflow(pid: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().run_workflow(pid, u["username"])


@app.post("/projects/{pid}/ask")
def ask(pid: str, q: AskIn, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().ask(pid, q.question, u["username"])


# ------------------------------------------------------------------ review / audit
@app.post("/projects/{pid}/items/{item_id}/review")
def review(pid: str, item_id: int, r: ReviewIn, u=Depends(user_with("review"))):
    project_or_404(pid)
    item = agent().review_item(pid, item_id, u["username"], r.decision, r.rationale)
    item["reviews"] = db.get_reviews(item_id)
    return item


@app.post("/projects/{pid}/reviews/{item_id}/decision")
def review_compat(pid: str, item_id: int, r: ReviewIn, u=Depends(user_with("review"))):
    return review(pid, item_id, r, u)


@app.get("/projects/{pid}/items/{item_id}/reviews")
def item_reviews(pid: str, item_id: int, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_reviews(item_id)


@app.post("/projects/{pid}/items/{item_id}/regenerate")
def regenerate(pid: str, item_id: int, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().regenerate(pid, item_id, u["username"])


@app.get("/projects/{pid}/audit")
def audit(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.audit_trail(pid)


@app.get("/projects/{pid}/metrics")
def metrics(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.run_stats(pid)


# ------------------------------------------------------------------ traceability
@app.get("/projects/{pid}/reports/traceability")
@app.get("/projects/{pid}/traceability")
def traceability(pid: str, include_rejected: bool = False, u=Depends(user_with("read"))):
    project_or_404(pid)
    return agent().traceability(pid, include_rejected)


@app.get("/projects/{pid}/traceability.csv")
def trace_csv(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    db.audit(u["username"], pid, "export_csv")
    return Response(reports.to_csv(agent().traceability(pid)), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="traceability_{pid}.csv"'})


@app.get("/projects/{pid}/traceability.pdf")
def trace_pdf(pid: str, u=Depends(user_with("read"))):
    p = project_or_404(pid)
    db.audit(u["username"], pid, "export_pdf")
    return Response(reports.to_pdf(agent().traceability(pid), p["name"]), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="traceability_{pid}.pdf"'})
