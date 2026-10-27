"""Streamlit pilot UI for the Automotive Cybersecurity TARA Assistant (talks to the FastAPI service layer)."""
import html
import os
import time

import httpx
import pandas as pd
import streamlit as st

API = os.getenv("TARA_API_URL", "http://localhost:8000")
NAVY = "#1F3864"
CYAN = "#18B6C9"
INK = "#172B4D"
MUTED = "#63758B"
PAGES = ["Dashboard", "Architecture input", "Assets", "Attack surface", "Threat scenarios", "Risk assessment", "Mitigations", "Traceability report", "Audit trail"]
ROLES = {"engineer1": "Cybersecurity engineer", "manager1": "Cybersecurity manager", "auditor1": "Compliance / audit"}
ROLE_PERMISSIONS = {
    "engineer1": {"read", "run", "review", "ingest"},
    "manager1": {"read", "run", "review", "ingest", "project"},
    "auditor1": {"read"},
}
RISK_BG = {"Critical": "#F4B6B6", "High": "#F9CBAA", "Medium": "#FFE699", "Low": "#D5E8D4", "Very low": "#E2F0D9"}
STATUS_BG = {"pending": "#EEEEEE", "approved": "#C5E0B4", "rejected": "#F4B6B6", "needs_change": "#FFE699"}
STATUS_TXT = {"pending": "Pending review", "approved": "Approved", "rejected": "Rejected", "needs_change": "Needs change"}
STATUS_LINE = "Advisory only · Recommendations require authorized engineer review; see each item for its current status."

st.set_page_config(page_title="TARA Assistant", page_icon="🛡️", layout="wide")
st.markdown(f"""
<style>
[data-testid="stAppViewContainer"] {{ background:#F5F8FC; }}
[data-testid="stHeader"] {{ background:rgba(245,248,252,.92); }}
[data-testid="stMainBlockContainer"] {{ max-width:1440px; padding-top:2rem; padding-bottom:3rem; }}
h1, h2, h3 {{ color:{INK} !important; letter-spacing:-.025em; }}
h1 {{ font-size:2.25rem !important; font-weight:750 !important; }}
h2 {{ font-size:1.55rem !important; font-weight:700 !important; }}
h3 {{ font-size:1.12rem !important; font-weight:700 !important; }}
p, label, [data-testid="stMarkdownContainer"] {{ color:{INK}; }}
section[data-testid="stSidebar"] {{ background:#EAF0F6; }}
section[data-testid="stSidebar"] h2, section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] label, section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
section[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p,
section[data-testid="stSidebar"] [data-testid="stRadio"] p,
section[data-testid="stSidebar"] [data-testid="stSelectbox"] label {{ color:{INK} !important; }}
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {{ color:{MUTED} !important; }}
section[data-testid="stSidebar"] [data-baseweb="select"] > div {{ background:#FFFFFF; border-radius:10px; }}
[data-testid="stMetric"] {{ background:#FFFFFF; border:1px solid #E5EBF2; border-radius:14px; padding:18px 20px; box-shadow:0 3px 12px rgba(20,46,78,.045); min-height:112px; }}
[data-testid="stMetricLabel"] {{ color:{MUTED}; font-size:.88rem; font-weight:600; }}
[data-testid="stMetricValue"] {{ color:{NAVY}; font-weight:750; }}
[data-testid="stVerticalBlockBorderWrapper"] {{ border-radius:14px; border-color:#E4EAF2; background:#FFFFFF; box-shadow:0 2px 9px rgba(20,46,78,.035); }}
.chip {{ display:inline-block; padding:4px 10px; border-radius:999px; font-size:.78rem; font-weight:600; margin:3px 6px 3px 0; border:1px solid #DCE5EF; color:{INK}; }}
.chip.src {{ background:#EDF5FC; border-color:#CCDFF0; color:{NAVY}; }}
.gov {{ background:#FFF8E5; border:1px solid #E8D28B; border-radius:12px; padding:14px 18px; margin:14px 0; color:#624E0A; }}
.gov b {{ color:#624E0A; }}
.statusline {{ color:{MUTED}; font-size:.84rem; margin-top:26px; padding-top:14px; border-top:1px solid #E3EAF2; }}
.small {{ color:{MUTED}; font-size:.85rem; }}
.hero {{ background:linear-gradient(120deg,#102A4C 0%,#1F4D78 68%,#087F93 100%); border-radius:20px; padding:30px 34px; margin:2px 0 24px; color:#FFFFFF; box-shadow:0 12px 30px rgba(16,42,76,.16); }}
.hero h1 {{ color:#FFFFFF !important; margin:0 0 8px; font-size:2.3rem !important; }}
.hero p {{ color:#DCEAF5 !important; margin:0; font-size:1rem; }}
.eyebrow {{ color:#8FE5ED; text-transform:uppercase; font-weight:700; font-size:.72rem; letter-spacing:.12em; margin-bottom:12px; }}
.section-kicker {{ color:{MUTED}; font-size:.88rem; margin-top:-12px; margin-bottom:20px; }}
.stButton > button {{ border-radius:10px; border:1px solid #DCE5EF; font-weight:650; transition:all .15s ease; }}
.stButton > button:hover {{ border-color:{CYAN}; color:{NAVY}; box-shadow:0 3px 10px rgba(24,182,201,.12); }}
.stButton > button[kind="primary"] {{ background:{NAVY}; border-color:{NAVY}; color:#FFFFFF; }}
.stButton > button[kind="primary"]:hover {{ background:#17385F; border-color:#17385F; color:#FFFFFF; }}
[data-testid="stFileUploader"] {{ background:#FFFFFF; border:1px dashed #B7C9DA; border-radius:14px; padding:8px; }}
[data-testid="stDataFrame"] {{ border:1px solid #E4EAF2; border-radius:12px; overflow:hidden; }}
[data-testid="stExpander"] {{ border-color:#E4EAF2; border-radius:12px; }}
@media (max-width: 760px) {{
  [data-testid="stMainBlockContainer"] {{ padding:1.25rem 1rem 2rem; }}
  .hero {{ padding:22px; border-radius:15px; }}
  .hero h1 {{ font-size:1.8rem !important; }}
}}
</style>""", unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers
def esc(x) -> str:
    return html.escape(str(x))


def chip(text, bg=None, cls=""):
    style = f' style="background:{bg}"' if bg else ""
    return f'<span class="chip {cls}"{style}>{esc(text)}</span>'


def call(method, path, **kw):
    headers = {"X-User": st.session_state.get("user", "engineer1")}
    try:
        r = httpx.request(method, API + path, headers=headers, timeout=180, **kw)
    except httpx.HTTPError:
        st.error(f"Cannot reach the TARA service at {API}. Start it with `uvicorn app.api:app` (see README).")
        st.stop()
    if r.status_code >= 400:
        try:
            msg = r.json().get("detail", r.text)
        except Exception:
            msg = r.text
        st.error(f"{msg}")
        return None
    return r


def get_json(path, **kw):
    r = call("GET", path, **kw)
    return r.json() if r is not None else None


def post_json(path, body=None):
    r = call("POST", path, json=body)
    return r.json() if r is not None else None


def ingest_upload(pid, uploaded_file):
    response = call(
        "POST",
        "/ingestion/upload",
        data={"project_id": pid},
        files={"file": (uploaded_file.name, uploaded_file.getvalue())},
    )
    if response is None:
        return
    job_id = response.json()["job_id"]
    with st.spinner(f"Ingesting {uploaded_file.name}..."):
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status_response = call("GET", f"/ingestion/status/{job_id}")
            if status_response is None:
                return
            job = status_response.json()
            if job["status"] == "completed":
                result = job["result"]
                st.success(f"{result['document']}: {result['n_chunks']} chunks ({result['doc_type']})")
                return
            if job["status"] == "failed":
                st.error(f"Ingestion failed for {job['filename']}: {job['error']}")
                return
            time.sleep(0.5)
    st.warning(f"Ingestion is still running. Job ID: {job_id}")


def can(perm: str) -> bool:
    role = st.session_state.get("user", "engineer1")
    return perm in ROLE_PERMISSIONS.get(role, set())


def status_line():
    st.markdown(f'<div class="statusline">{esc(STATUS_LINE)}</div>', unsafe_allow_html=True)


def review_controls(pid, item, key):
    """Approve / Reject / Needs change with stored rationale (audit trail)."""
    st.markdown(chip(STATUS_TXT[item["status"]], STATUS_BG[item["status"]]), unsafe_allow_html=True)
    if not can("review"):
        st.caption("Read-only role")
        return
    rat = st.text_input("Rationale (required to reject or request change)", key=f"rat-{key}", label_visibility="collapsed",
                        placeholder="Rationale (required to reject / request change)")
    c1, c2, c3 = st.columns(3)
    for col, (label, dec) in zip((c1, c2, c3), (("Approve", "approve"), ("Reject", "reject"), ("Needs change", "needs_change"))):
        if col.button(label, key=f"{key}-{dec}", use_container_width=True):
            r = call("POST", f"/projects/{pid}/items/{item['id']}/review", json={"decision": dec, "rationale": rat})
            if r is not None:
                st.rerun()
    if item["status"] == "needs_change" and item["kind"] in ("rating", "mitigation"):
        if st.button("Regenerate recommendation", key=f"{key}-regen"):
            if call("POST", f"/projects/{pid}/items/{item['id']}/regenerate") is not None:
                st.rerun()


# ------------------------------------------------------------------ sidebar
users = ROLES
with st.sidebar:
    st.markdown(f"<div style='padding:8px 0 16px'><div style='font-size:1.65rem;font-weight:800;color:{NAVY}'>◈ TARA</div><div style='color:{MUTED};font-size:.82rem'>Automotive Cybersecurity Workspace</div></div>", unsafe_allow_html=True)
    st.selectbox("Role", list(ROLES), format_func=lambda u: ROLES[u], key="user")
    projects = get_json("/projects") or []
    if not projects:
        st.warning("No projects yet.")
        st.stop()
    names = {p["id"]: p["name"] for p in projects}
    pid = st.selectbox("Project", list(names), format_func=lambda i: names[i], key="project_id")
    st.caption(f"Project: {names[pid]}")
    if can("project"):
        with st.expander("Create project"):
            with st.form("create-project"):
                new_project_id = st.text_input("Project ID")
                new_project_name = st.text_input("Project name")
                new_project_description = st.text_area("Description")
                submitted = st.form_submit_button("Create project")
            if submitted:
                if not new_project_id.strip() or not new_project_name.strip():
                    st.error("Project ID and project name are required.")
                else:
                    result = call("POST", "/projects", json={
                        "id": new_project_id.strip(),
                        "name": new_project_name.strip(),
                        "description": new_project_description.strip(),
                    })
                    if result is not None:
                        st.success("Project created.")
                        st.rerun()
    page = st.radio("Navigation", PAGES, label_visibility="collapsed", key="page")
    st.divider()
    health = get_json("/health") or {}
    st.caption(f"Engine: {health.get('llm_engine', '?')}  \nEmbeddings: {health.get('embedder', '?')}")


# ------------------------------------------------------------------ pages
def page_dashboard():
    st.markdown(
        f"<div class='hero'><div class='eyebrow'>Threat analysis · Risk assessment</div>"
        f"<h1>Security overview</h1><p>{esc(names[pid])} &nbsp;·&nbsp; Live summary of persisted project evidence and review activity.</p></div>",
        unsafe_allow_html=True,
    )

    documents = get_json(f"/projects/{pid}/documents")
    assets_data = get_json(f"/projects/{pid}/assets")
    surface = get_json(f"/projects/{pid}/attack-surface")
    threats = get_json(f"/projects/{pid}/threats")
    ratings = get_json(f"/projects/{pid}/ratings")
    mitigations = get_json(f"/projects/{pid}/mitigations")
    if any(value is None for value in (documents, assets_data, surface, threats, ratings, mitigations)):
        st.warning("Dashboard metrics could not be loaded. Check the API response above and retry.")
        return

    assets = assets_data["assets"]
    recommendations = assets + assets_data["boundaries"] + surface + threats + ratings + mitigations
    metric_data = [
        ("Projects", len(projects)),
        ("Documents", len(documents)),
        ("Assets", len(assets)),
        ("Threat scenarios", len(threats)),
    ]
    for offset in range(0, len(metric_data), 2):
        metric_cols = st.columns(2)
        for column, (label, value) in zip(metric_cols, metric_data[offset:offset + 2]):
            column.metric(label, value)

    st.subheader("Review status")
    st.markdown("<div class='section-kicker'>Current status across stored assets, surfaces, threats, ratings and mitigation drafts</div>", unsafe_allow_html=True)
    review_metrics = [
        ("Pending", sum(item["status"] == "pending" for item in recommendations)),
        ("Approved", sum(item["status"] == "approved" for item in recommendations)),
        ("Rejected", sum(item["status"] == "rejected" for item in recommendations)),
    ]
    for offset in range(0, len(review_metrics), 2):
        review_cols = st.columns(2)
        for column, (label, value) in zip(review_cols, review_metrics[offset:offset + 2]):
            column.metric(label, value)

    st.subheader("Risk profile")
    st.markdown("<div class='section-kicker'>Deterministic assessments currently saved for this project</div>", unsafe_allow_html=True)
    risk_counts = {}
    for item in ratings:
        label = item["data"].get("risk_label")
        if label:
            risk_counts[label] = risk_counts.get(label, 0) + 1
    if risk_counts:
        risk_order = ["Critical", "High", "Medium", "Low", "Very low"]
        chart_data = pd.DataFrame(
            {"Risk level": [level for level in risk_order if level in risk_counts],
             "Assessments": [risk_counts[level] for level in risk_order if level in risk_counts]}
        )
        st.bar_chart(chart_data, x="Risk level", y="Assessments", color=CYAN)
    else:
        st.info("No risk assessments have been stored for this project yet. Run the workflow to build the first risk profile.")

    st.subheader("Workspace snapshot")
    snapshot = st.columns(2)
    snapshot[0].metric("Attack-surface entries", len(surface))
    snapshot[1].metric("Mitigation drafts", len(mitigations))
    st.caption(f"{sum(item['status'] == 'approved' for item in threats)} threat scenarios approved by an engineer")
    if not documents:
        st.info("No documents uploaded yet. Load the sample TCU-Gen2 documents or upload project inputs.")
    action_cols = st.columns(3)
    for column, label, destination in (
        (action_cols[0], "Add architecture evidence", "Architecture input"),
        (action_cols[1], "Review threat scenarios", "Threat scenarios"),
        (action_cols[2], "Open traceability report", "Traceability report"),
    ):
        if column.button(label, key=f"dashboard-{destination}", use_container_width=True):
            st.session_state["page"] = destination
            st.rerun()
    status_line()


def page_input():
    st.title("Architecture input")
    st.markdown("<div class='section-kicker'>Bring in reviewed architecture evidence to ground assets, threats and risk recommendations.</div>", unsafe_allow_html=True)
    st.write("Ingest architecture descriptions, communication matrices, asset catalogues and (optionally) approved project knowledge. "
             "Documents are cleaned, chunked, embedded and stored in the local vector store with metadata.")
    c1, c2 = st.columns([1, 2])
    with c1:
        if can("ingest") and st.button("Load sample TCU-Gen2 documents", type="primary"):
            if post_json(f"/projects/{pid}/documents/sample") is not None:
                st.rerun()
        if can("run") and st.button("Run full TARA workflow"):
            with st.spinner("Running assets, attack surface, threats, risk and mitigations..."):
                res = post_json(f"/projects/{pid}/workflow/run")
            if res:
                st.success(f"Workflow finished in {res['seconds']} s ({res['assets']} assets, {res['surface_entries']} attack-surface entries, "
                           f"{res['threats']} threat scenarios). All items are pending engineer review.")
    with c2:
        files = st.file_uploader("Upload documents (PDF, DOCX, XLSX, CSV, JSON, MD, TXT)", accept_multiple_files=True,
                                 type=["pdf", "docx", "xlsx", "csv", "json", "md", "txt"], disabled=not can("ingest"))
        if files and st.button("Ingest uploaded files"):
            for f in files:
                ingest_upload(pid, f)
    st.subheader("Ingestion log")
    docs = get_json(f"/projects/{pid}/documents") or []
    if docs:
        st.dataframe(pd.DataFrame(docs)[["document", "doc_type", "scope", "n_chunks", "avg_tokens", "interfaces", "review_date", "sha256", "ingested_at"]],
                     hide_index=True, use_container_width=True)
    else:
        st.info("No project documents yet. Load the sample documents or upload your own.")
    status_line()


def page_assets():
    st.title("Assets and trust boundaries")
    st.markdown("<div class='section-kicker'>Search, filter, inspect sources, and edit candidate assets. Changes return to pending review.</div>", unsafe_allow_html=True)
    if can("run") and st.button("Identify assets", type="primary"):
        if post_json(f"/projects/{pid}/assets/identify") is not None:
            st.rerun()
    data = get_json(f"/projects/{pid}/assets") or {"assets": [], "boundaries": []}
    shown_assets = data["assets"]
    if not data["assets"]:
        st.info("No assets yet. Ingest documents, then identify assets.")
    else:
        filter_cols = st.columns(4)
        search_text = filter_cols[0].text_input("Search assets", key=f"asset-search-{pid}").strip().lower()
        asset_types = sorted({item["data"]["type"] for item in data["assets"]})
        asset_interfaces = sorted({item["data"]["interface"] for item in data["assets"]})
        asset_statuses = sorted({item["status"] for item in data["assets"]})
        selected_type = filter_cols[1].selectbox("Asset type", ["All"] + asset_types, key=f"asset-type-{pid}")
        selected_interface = filter_cols[2].selectbox("Interface", ["All"] + asset_interfaces, key=f"asset-interface-{pid}")
        selected_status = filter_cols[3].selectbox("Review status", ["All"] + asset_statuses, key=f"asset-status-{pid}")
        shown_assets = [
            item for item in data["assets"]
            if (not search_text or search_text in " ".join(str(value) for value in item["data"].values()).lower())
            and (selected_type == "All" or item["data"]["type"] == selected_type)
            and (selected_interface == "All" or item["data"]["interface"] == selected_interface)
            and (selected_status == "All" or item["status"] == selected_status)
        ]
        st.caption(f"Showing {len(shown_assets)} of {len(data['assets'])} assets.")
    for a in shown_assets:
        d = a["data"]
        with st.container(border=True):
            c1, c2 = st.columns([3, 2])
            with c1:
                st.markdown(f"**{esc(d['asset_id'])}  {esc(d['name'])}**")
                st.write(d["description"])
                st.markdown(chip(f"{d['type']} | {d['interface']}") + chip(f"Origin: {d['origin']}") +
                            "".join(chip("Source: " + c, cls="src") for c in d["citations"][:3]), unsafe_allow_html=True)
            with c2:
                review_controls(pid, a, f"asset-{a['id']}")
            if can("review"):
                with st.expander(f"Edit {d['asset_id']} candidate details"):
                    with st.form(f"edit-asset-{a['id']}"):
                        edited_name = st.text_input("Asset name", value=d["name"])
                        edited_description = st.text_area("Description", value=d["description"])
                        edited_type = st.text_input("Asset type", value=d["type"])
                        edited_interface = st.text_input("Interface", value=d["interface"])
                        edited_properties = st.text_area("Properties", value=d["properties"])
                        edited_owner = st.text_input("Owner", value=d["owner"])
                        edit_rationale = st.text_input("Edit rationale")
                        saved = st.form_submit_button("Save asset edits")
                    if saved:
                        result = call(
                            "POST",
                            f"/projects/{pid}/assets/{a['id']}/edit",
                            json={
                                "name": edited_name,
                                "description": edited_description,
                                "type": edited_type,
                                "interface": edited_interface,
                                "properties": edited_properties,
                                "owner": edited_owner,
                                "rationale": edit_rationale,
                            },
                        )
                        if result is not None:
                            st.success("Asset changes saved and returned to pending review.")
                            st.rerun()
    if data["boundaries"]:
        st.subheader("Trust boundaries")
        for b in data["boundaries"]:
            st.markdown(f"**{esc(b['data']['boundary_id'])}**  {esc(b['data']['description'])}  " + chip("Source: " + b["data"]["citations"][0], cls="src"),
                        unsafe_allow_html=True)
    status_line()


def page_surface():
    st.title("Attack surface")
    st.markdown("<div class='section-kicker'>Rule-based exposure hypotheses linked to assets and supporting project evidence.</div>", unsafe_allow_html=True)
    if can("run") and st.button("Map attack surface", type="primary"):
        if post_json(f"/projects/{pid}/attack-surface/map") is not None:
            st.rerun()
    items = get_json(f"/projects/{pid}/attack-surface") or []
    if not items:
        st.info("No attack-surface map yet.")
    else:
        rows = [{"Interface": i["data"]["interface_name"], "Entry point": i["data"]["entry_point"], "Attack vector": i["data"]["vector"],
                 "Exposure": i["data"]["exposure"], "Linked assets": ", ".join(i["data"]["asset_names"]),
                 "Trust boundary": i["data"]["trust_boundary"],
                 "Derivation": i["data"].get("derivation", "legacy taxonomy-rule inference"),
                 "Evidence basis": i["data"].get(
                     "evidence_status",
                     "supporting project passages found" if i["data"]["citations"] else "no supporting project passage found",
                 ),
                 "Sources": " || ".join(i["data"]["citations"])} for i in items]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        with st.expander("Attack-surface interpretation"):
            st.info("Entry points and exposure are taxonomy-based inferences, not confirmed vulnerabilities. Supporting citations show related project passages; verify each item against the design.")
    status_line()


def threat_card(t):
    d = t["data"]
    with st.container(border=True):
        st.markdown(f"### {esc(t['ref'])}  {esc(d['title'])}")
        st.write(d["description"])
        st.markdown(chip("Source: " + d["citation"], cls="src") + chip("Proposed: " + d["proposed_risk"], RISK_BG.get(d["proposed_risk"], "#EEE")) +
                    chip(f"Asset: {', '.join(d['asset_names']) or 'none identified'}") + chip(f"STRIDE: {d['stride']}"), unsafe_allow_html=True)
        if d.get("warning"):
            st.warning(d["warning"])
        with st.expander("Rationale, assumptions and alternatives"):
            st.write(d["rationale"])
            st.markdown("**Assumptions**\n" + "\n".join(f"- {a}" for a in d["assumptions"]))
            st.markdown("**Alternatives**\n" + "\n".join(f"- {a}" for a in d["alternatives"]))
            st.caption(f"Retrieval score {d['retrieval_score']} | engine: {t['engine']}")
        review_controls(pid, t, f"threat-{t['id']}")
        if can("review"):
            with st.expander(f"Edit {t['ref']} recommendation"):
                with st.form(f"edit-threat-{t['id']}"):
                    edited_title = st.text_input("Threat title", value=d["title"])
                    edited_description = st.text_area("Threat description", value=d["description"])
                    edited_rationale = st.text_area("Recommendation rationale", value=d["rationale"])
                    edited_assumptions = st.text_area("Assumptions (one per line)", value="\n".join(d["assumptions"]))
                    edited_alternatives = st.text_area("Alternatives (one per line)", value="\n".join(d["alternatives"]))
                    edit_reason = st.text_input("Edit rationale")
                    saved = st.form_submit_button("Save threat edits")
                if saved:
                    result = call("POST", f"/projects/{pid}/items/{t['id']}/edit", json={
                        "title": edited_title,
                        "description": edited_description,
                        "rationale": edited_rationale,
                        "assumptions": [line.strip() for line in edited_assumptions.splitlines() if line.strip()],
                        "alternatives": [line.strip() for line in edited_alternatives.splitlines() if line.strip()],
                        "edit_rationale": edit_reason,
                    })
                    if result is not None:
                        st.success("Threat edits saved and returned to pending review.")
                        st.rerun()


def page_threats():
    st.title("Threat scenario recommendation")
    st.markdown("<div class='section-kicker'>Retrieve cited scenarios from the local approved knowledge base; recommendations remain advisory.</div>", unsafe_allow_html=True)
    q = st.text_input("Question", value="Suggest threat scenarios for the OTA update channel of the telematics unit", label_visibility="collapsed")
    with st.expander("Retrieval options"):
        top_k = st.slider("Top-k entries", 1, 15, 8)
    if can("run") and st.button("Retrieve", type="primary"):
        res = post_json(f"/projects/{pid}/threats/recommend", {"query": q, "top_k": top_k})
        st.session_state["last_threats"] = None
        if res:
            if res["status"] == "declined":
                st.error(res["message"])
                for m in res.get("mitigation_guidance", []):
                    st.markdown(f"- **{esc(m['control_id'])} {esc(m['title'])}**: {esc(m['requirement'])}  \n  <span class='small'>Source: {esc(m['citation'])}</span>",
                                unsafe_allow_html=True)
            elif res["status"] == "insufficient_context":
                st.warning(res["message"])
            else:
                st.session_state["last_threats"] = [t["id"] for t in res["threats"]]
                st.caption(f"Engine: {res['engine']}")
    all_t = get_json(f"/projects/{pid}/threats") or []
    last = st.session_state.get("last_threats")
    show_all = st.toggle("Show all stored threat scenarios", value=last is None)
    shown = all_t if show_all or not last else [t for t in all_t if t["id"] in last]
    if not shown:
        st.info("No threat scenarios yet. Ask a question above.")
    for t in shown:
        threat_card(t)
    with st.expander("Ask a cited question about the approved knowledge"):
        question = st.text_input("Question about threats or controls", key="askq")
        if st.button("Ask") and question:
            res = post_json(f"/projects/{pid}/ask", {"question": question})
            if res:
                (st.error if res["status"] == "declined" else st.write)(res["answer"])
                for c in res.get("citations", [])[:5]:
                    st.caption("Source: " + c["citation"])
    status_line()


def page_risk():
    st.title("Risk assessment")
    st.markdown("<div class='section-kicker'>Inspect proposed inputs and deterministic pilot-matrix outputs. Engineer approval is required.</div>", unsafe_allow_html=True)
    matrix = get_json("/risk/matrix")
    if matrix:
        st.caption(
            f"Selected pilot matrix {matrix['version']} (illustrative, not an official ISO/SAE scoring formula). "
            "Rows are impact; columns are attack feasibility."
        )
        st.dataframe(
            pd.DataFrame.from_dict(
                matrix["rows"], orient="index", columns=matrix["feasibility_levels"]
            ),
            use_container_width=True,
        )
    threats = [t for t in (get_json(f"/projects/{pid}/threats") or []) if t["status"] != "rejected"]
    ratings = {r["parent_ref"]: r for r in (get_json(f"/projects/{pid}/ratings") or [])}
    if not threats:
        st.info("No threat scenarios to assess yet.")
    if ratings and can("run") and st.button("Recalculate stored ratings with current matrix"):
        for threat_ref in ratings:
            post_json(f"/projects/{pid}/risk/recalculate", {"threat_ref": threat_ref})
        st.rerun()
    if threats and can("run") and st.button("Assess all unassessed threats", type="primary"):
        for t in threats:
            if t["ref"] not in ratings:
                post_json(f"/projects/{pid}/threats/{t['ref']}/assess")
        st.rerun()
    for t in threats:
        r = ratings.get(t["ref"])
        with st.container(border=True):
            st.markdown(f"### {esc(t['ref'])}  {esc(t['data']['title'])}")
            if not r:
                if can("run") and st.button("Propose rating", key=f"assess-{t['id']}"):
                    post_json(f"/projects/{pid}/threats/{t['ref']}/assess")
                    st.rerun()
                continue
            d = r["data"]
            st.markdown(chip(f"Impact: {d['overall_impact']}") + chip(f"Attack feasibility: {d['feasibility']} (potential {d['attack_potential']})") +
                        chip(f"Risk: {d['risk_label']} ({d['risk_value']}/5)", RISK_BG.get(d["risk_label"], "#EEE")) + chip(d["approval_state"], "#FFF2CC"),
                        unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            c1.markdown("**Impact (S / F / O / P)**")
            c1.dataframe(pd.DataFrame([d["impact"]]), hide_index=True, use_container_width=True)
            c2.markdown("**Attack-potential factors**")
            c2.dataframe(pd.DataFrame([d["factors"]]), hide_index=True, use_container_width=True)
            st.write(d["rationale"])
            st.caption(f"Rating source: {d['rating_source']} | risk value computed by the deterministic matrix | engine: {r['engine']}")
            st.markdown("".join(chip("Source: " + s, cls="src") for s in d["sources"]), unsafe_allow_html=True)
            review_controls(pid, r, f"rating-{r['id']}")
            if can("review") and matrix:
                with st.expander(f"Edit {r['ref']} rating inputs"):
                    with st.form(f"edit-rating-{r['id']}"):
                        edited_impact = {
                            category: st.selectbox(
                                f"{category.title()} impact",
                                matrix["impact_levels"],
                                index=matrix["impact_levels"].index(d["impact"][category]),
                                key=f"rating-impact-{r['id']}-{category}",
                            )
                            for category in ("safety", "financial", "operational", "privacy")
                        }
                        edited_factors = {
                            factor: st.selectbox(
                                f"Attack-potential {factor}",
                                matrix["factor_options"][factor],
                                index=matrix["factor_options"][factor].index(d["factors"][factor]),
                                key=f"rating-factor-{r['id']}-{factor}",
                            )
                            for factor in matrix["factor_options"]
                        }
                        edited_rationale = st.text_area("Rating rationale", value=d["rationale"])
                        edit_reason = st.text_input("Edit rationale")
                        saved = st.form_submit_button("Save rating inputs")
                    if saved:
                        result = call("POST", f"/projects/{pid}/items/{r['id']}/edit", json={
                            "impact": edited_impact,
                            "factors": edited_factors,
                            "rationale": edited_rationale,
                            "edit_rationale": edit_reason,
                        })
                        if result is not None:
                            st.success("Rating updated using the deterministic matrix and returned to pending review.")
                            st.rerun()
    status_line()


def page_mitigations():
    st.title("Mitigations and requirement drafts")
    st.markdown("<div class='section-kicker'>Review catalogue-backed defensive controls and edit draft requirements before approval.</div>", unsafe_allow_html=True)
    threats = [t for t in (get_json(f"/projects/{pid}/threats") or []) if t["status"] != "rejected"]
    mits = get_json(f"/projects/{pid}/mitigations") or []
    if threats and can("run") and st.button("Recommend mitigations for all threats", type="primary"):
        for t in threats:
            if not any(m["parent_ref"] == t["ref"] for m in mits):
                post_json(f"/projects/{pid}/threats/{t['ref']}/mitigations")
        st.rerun()
    if not mits:
        st.info("No mitigations yet.")
    for t in threats:
        ms = [m for m in mits if m["parent_ref"] == t["ref"]]
        if not ms:
            continue
        st.subheader(f"{t['ref']}  {t['data']['title']}")
        for m in ms:
            d = m["data"]
            with st.container(border=True):
                st.markdown(f"**{esc(d['requirement_id'])}  {esc(d['title'])} ({esc(d['control_id'])})**")
                st.write(d["requirement"])
                st.markdown(chip(d.get("draft_status", "Draft - pending human review"), "#FFF2CC") +
                            chip("Goal: " + d["cybersecurity_goal"]) + chip("Tests: " + ", ".join(d["test_ids"])) +
                            chip("Source: " + d["citation"], cls="src"),
                            unsafe_allow_html=True)
                if can("review"):
                    with st.expander(f"Edit {d['requirement_id']} draft"):
                        with st.form(f"edit-mitigation-{m['id']}"):
                            edited_title = st.text_input("Control title", value=d["title"])
                            edited_requirement = st.text_area("Draft requirement", value=d["requirement"])
                            edited_assumptions = st.text_area("Assumptions (one per line)", value="\n".join(d["assumptions"]))
                            edit_reason = st.text_input("Edit rationale")
                            saved = st.form_submit_button("Save requirement edits")
                        if saved:
                            result = call("POST", f"/projects/{pid}/items/{m['id']}/edit", json={
                                "title": edited_title,
                                "requirement": edited_requirement,
                                "assumptions": [line.strip() for line in edited_assumptions.splitlines() if line.strip()],
                                "edit_rationale": edit_reason,
                            })
                            if result is not None:
                                st.success("Requirement edits saved and returned to pending review.")
                                st.rerun()
                if d["alternatives"]:
                    with st.expander("Alternatives from the control catalogue"):
                        for a in d["alternatives"]:
                            st.markdown(f"- {a['control_id']} {a['title']}  ({a['citation']})")
                review_controls(pid, m, f"mit-{m['id']}")
    status_line()


def page_trace():
    st.title("Cybersecurity traceability report")
    st.markdown("<div class='section-kicker'>Evidence-to-test links, review status, assumptions, and coverage gaps from persisted records.</div>", unsafe_allow_html=True)
    rep = get_json(f"/projects/{pid}/traceability")
    if not rep:
        st.info("Could not load the traceability report.")
        return
    if not rep["rows"]:
        st.info("No threat scenarios yet. The export can still include the current asset and attack-surface inventories.")
    rows = [{"Asset": r["asset"], "Threat scenario": r["threat"], "Risk": r["risk"],
             "Control / requirement": "; ".join(detail["id"] + ": " + detail["text"] for detail in r["requirement_details"]),
             "Test link": ", ".join(r["tests"]), "Review status": f"{r['status']['threat']} / {r['status']['rating']}"} for r in rep["rows"]]
    if rows:
        df = pd.DataFrame(rows)
        def colour(v):
            return f"background-color: {RISK_BG.get(str(v).replace(' (preliminary)', ''), '#FFFFFF')}"
        st.dataframe(df.style.map(colour, subset=["Risk"]), hide_index=True, use_container_width=True)
    st.markdown(f'<div class="gov"><b>Governance principle</b><br>{esc(rep["governance_principle"])}</div>', unsafe_allow_html=True)
    if rep["gaps"]:
        with st.expander(f"Coverage gaps ({len(rep['gaps'])})"):
            for g in rep["gaps"]:
                st.write("- " + g)
    c1, c2, _ = st.columns([1, 1, 4])
    pdf = call("GET", f"/projects/{pid}/traceability.pdf")
    csv = call("GET", f"/projects/{pid}/traceability.csv")
    if pdf is not None:
        c1.download_button("Export PDF", pdf.content, file_name=f"traceability_{pid}.pdf", mime="application/pdf", type="primary")
    if csv is not None:
        c2.download_button("Export CSV", csv.content, file_name=f"traceability_{pid}.csv", mime="text/csv", type="primary")
    st.caption("Sample data for illustration" if "sample" in names[pid].lower() else "")


def page_audit():
    st.title("Audit trail")
    st.markdown("<div class='section-kicker'>Persisted project actions and reviewer decisions.</div>", unsafe_allow_html=True)
    rows = get_json(f"/projects/{pid}/audit") or []
    if rows:
        st.dataframe(pd.DataFrame([{**r, "detail": str(r["detail"])} for r in rows])[["ts", "username", "action", "entity", "detail"]],
                     hide_index=True, use_container_width=True)
    else:
        st.info("No audit entries yet.")
    stats = get_json(f"/projects/{pid}/metrics") or []
    if stats:
        st.subheader("Step latency (ms, average)")
        st.dataframe(pd.DataFrame(stats), hide_index=True)


{"Dashboard": page_dashboard, "Architecture input": page_input, "Assets": page_assets, "Attack surface": page_surface, "Threat scenarios": page_threats,
 "Risk assessment": page_risk, "Mitigations": page_mitigations, "Traceability report": page_trace, "Audit trail": page_audit}[page]()
