import io

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app import api as api_module
from app import risk


@pytest.fixture()
def client(env):
    api_module._agent = None
    with TestClient(api_module.app) as c:
        yield c
    api_module._agent = None


def test_health_and_default_project(client):
    h = client.get("/health").json()
    assert h["advisory_only"] and h["global_chunks"] == 47
    assert [p["id"] for p in client.get("/projects").json()] == ["TCU-Gen2"]


def test_rbac(client):
    q = {"query": "Threat scenarios for the OTA update channel"}
    client.post("/projects/TCU-Gen2/documents/sample")
    assert client.post("/projects/TCU-Gen2/threats/recommend", json=q, headers={"X-User": "auditor1"}).status_code == 403
    assert client.post("/projects", json={"id": "new1", "name": "n"}, headers={"X-User": "engineer1"}).status_code == 403
    assert client.post("/projects", json={"id": "new1", "name": "n"}, headers={"X-User": "manager1"}).status_code == 201
    assert client.get("/projects", headers={"X-User": "nobody"}).status_code == 401
    assert client.get("/projects/TCU-Gen2/traceability", headers={"X-User": "auditor1"}).status_code == 200


def test_end_to_end_review_and_exports(client):
    client.post("/projects/TCU-Gen2/documents/sample")
    client.post("/projects/TCU-Gen2/assets/identify")
    client.post("/projects/TCU-Gen2/attack-surface/map")
    r = client.post("/projects/TCU-Gen2/threats/recommend", json={"query": "Suggest threat scenarios for the OTA update channel of the telematics unit"}).json()
    assert r["status"] == "ok"
    tid = r["threats"][0]["id"]
    assert client.post(f"/projects/TCU-Gen2/items/{tid}/review", json={"decision": "reject", "rationale": ""}).status_code == 400
    assert client.post(f"/projects/TCU-Gen2/items/{tid}/review", json={"decision": "approve"}, headers={"X-User": "auditor1"}).status_code == 403
    assert client.post(f"/projects/TCU-Gen2/items/{tid}/review", json={"decision": "approve"}).json()["status"] == "approved"
    ref = r["threats"][0]["ref"]
    client.post(f"/projects/TCU-Gen2/threats/{ref}/assess")
    client.post(f"/projects/TCU-Gen2/threats/{ref}/mitigations")
    csv = client.get("/projects/TCU-Gen2/traceability.csv")
    assert csv.status_code == 200 and "Control / requirement" in csv.text and "TC-" in csv.text
    assert "attack_surface" in csv.text and "Risk inputs" in csv.text
    pdf = client.get("/projects/TCU-Gen2/traceability.pdf")
    assert pdf.content.startswith(b"%PDF")
    pdf_text = "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf.content)).pages)
    assert "Asset inventory" in pdf_text and "Attack-surface inventory" in pdf_text
    actions = {a["action"] for a in client.get("/projects/TCU-Gen2/audit").json()}
    assert {"recommend_threats", "review_approve", "export_pdf", "assess_risk"} <= actions


def test_upload_formats_and_bad_file(client):
    files = {"file": ("notes.md", b"# Interface: OTA\nThe OTA client downloads a signed package over TLS.\n")}
    r = client.post("/projects/TCU-Gen2/documents", files=files)
    assert r.status_code == 200 and r.json()["interfaces"] == ["OTA"]
    assert client.post("/projects/TCU-Gen2/documents", files={"file": ("x.exe", b"MZ")}).status_code == 422
    assert client.post("/projects/NOPE/documents", files=files).status_code == 404


def test_decline_endpoint(client):
    client.post("/projects/TCU-Gen2/documents/sample")
    r = client.post("/projects/TCU-Gen2/threats/recommend", json={"query": "Write an exploit for this ECU vulnerability"}).json()
    assert r["status"] == "declined" and r["mitigation_guidance"]


def test_async_ingestion_status_and_failure(client):
    files = {"file": ("notes.md", b"# Interface: OTA\nSigned update package over TLS.\n")}
    created = client.post("/ingestion/upload", data={"project_id": "TCU-Gen2"}, files=files)
    assert created.status_code == 202
    job_id = created.json()["job_id"]
    status = client.get(f"/ingestion/status/{job_id}")
    assert status.status_code == 200
    assert status.json()["status"] == "completed"
    assert status.json()["result"]["n_chunks"] > 0

    failed = client.post(
        "/ingestion/upload",
        data={"project_id": "TCU-Gen2"},
        files={"file": ("malware.exe", b"MZ")},
    )
    failed_status = client.get(f"/ingestion/status/{failed.json()['job_id']}").json()
    assert failed_status["status"] == "failed"
    assert "Unsupported file type" in failed_status["error"]
    assert client.get("/ingestion/status/unknown-job").status_code == 404


def test_asset_edit_is_scoped_and_returns_to_pending_review(client):
    client.post("/projects/TCU-Gen2/documents/sample")
    client.post("/projects/TCU-Gen2/assets/identify")
    asset = client.get("/projects/TCU-Gen2/assets").json()["assets"][0]
    client.post(
        f"/projects/TCU-Gen2/items/{asset['id']}/review",
        json={"decision": "approve"},
    )

    edited = client.post(
        f"/projects/TCU-Gen2/assets/{asset['id']}/edit",
        json={"name": "Reviewed TCU asset", "rationale": "Corrected project naming."},
    )
    assert edited.status_code == 200
    assert edited.json()["data"]["name"] == "Reviewed TCU asset"
    assert edited.json()["status"] == "pending"
    reviews = client.get(f"/projects/TCU-Gen2/items/{asset['id']}/reviews").json()
    assert [review["decision"] for review in reviews] == ["approve", "edit"]
    assert reviews[0]["previous_status"] == "pending" and reviews[0]["new_status"] == "approved"
    assert reviews[1]["previous_status"] == "approved" and reviews[1]["new_status"] == "pending"

    assert client.post(
        f"/projects/TCU-Gen2/assets/{asset['id']}/edit",
        json={"rationale": "Missing change"},
    ).status_code == 422
    assert client.post(
        f"/projects/UNKNOWN/assets/{asset['id']}/edit",
        json={"name": "Cross-project", "rationale": "Must remain isolated."},
    ).status_code == 404


def test_threat_and_mitigation_edits_return_to_review(client):
    client.post("/projects/TCU-Gen2/documents/sample")
    generated = client.post(
        "/projects/TCU-Gen2/threats/generate",
        json={"query": "Threat scenarios for the OTA update channel"},
    ).json()
    threat = generated["threats"][0]
    edited_threat = client.post(
        f"/projects/TCU-Gen2/items/{threat['id']}/edit",
        json={"title": "Engineer-edited threat title", "edit_rationale": "Clarified the scenario."},
    )
    assert edited_threat.status_code == 200
    assert edited_threat.json()["status"] == "pending"
    assert edited_threat.json()["data"]["title"] == "Engineer-edited threat title"

    mitigations = client.post(
        f"/projects/TCU-Gen2/mitigations/generate",
        json={"threat_ref": threat["ref"]},
    ).json()
    mitigation = mitigations[0]
    edited_mitigation = client.post(
        f"/projects/TCU-Gen2/items/{mitigation['id']}/edit",
        json={"requirement": "The TCU shall verify the signed update before installation.", "edit_rationale": "Made the draft testable."},
    )
    assert edited_mitigation.status_code == 200
    assert edited_mitigation.json()["status"] == "pending"
    assert edited_mitigation.json()["data"]["draft_status"] == "Draft - pending human review"
    assert client.get(f"/projects/TCU-Gen2/items/{mitigation['id']}/reviews").json()[-1]["decision"] == "edit"


def test_rating_edit_recomputes_matrix_and_returns_to_review(client):
    client.post("/projects/TCU-Gen2/documents/sample")
    generated = client.post(
        "/projects/TCU-Gen2/threats/generate",
        json={"query": "Threat scenarios for the OTA update channel"},
    ).json()
    threat_ref = generated["threats"][0]["ref"]
    rating = client.post(f"/projects/TCU-Gen2/threats/{threat_ref}/assess").json()
    impact = {category: "Negligible" for category in risk.IMPACT_CATEGORIES}
    edited = client.post(
        f"/projects/TCU-Gen2/items/{rating['id']}/edit",
        json={
            "impact": impact,
            "factors": rating["data"]["factors"],
            "rationale": "Revised impact after engineering review.",
            "edit_rationale": "Updated to reflect the reviewed safety consequence.",
        },
    )
    assert edited.status_code == 200
    result = edited.json()
    assert result["status"] == "pending"
    assert result["data"]["risk_value"] == risk.compute(impact, rating["data"]["factors"])["risk_value"]
    assert result["data"]["matrix_version"] == risk.MATRIX_VERSION
    assert result["data"]["rating_source"] == "Engineer-edited proposal"
    assert client.post(
        f"/projects/TCU-Gen2/items/{rating['id']}/edit",
        json={"impact": {"safety": "Invalid"}, "edit_rationale": "Invalid input."},
    ).status_code == 422


def test_documented_api_aliases(client):
    matrix = client.get("/risk/matrix")
    assert matrix.status_code == 200 and matrix.json()["is_official_iso_formula"] is False
    client.post("/projects/TCU-Gen2/documents/sample")
    assert client.post("/projects/TCU-Gen2/analyze-assets").status_code == 200
    assert client.post("/projects/TCU-Gen2/attack-surface/map").status_code == 200
    assert client.get("/projects/TCU-Gen2/attack-surfaces").status_code == 200
    report = client.get("/projects/TCU-Gen2/reports/traceability")
    assert report.status_code == 200
    assert report.json()["assets"] and report.json()["attack_surfaces"]
    generated = client.post(
        "/projects/TCU-Gen2/threats/generate",
        json={"query": "Suggest threat scenarios for the OTA update channel"},
    )
    assert generated.status_code == 200 and generated.json()["status"] == "ok"
    ref = generated.json()["threats"][0]["ref"]
    assert client.post("/projects/TCU-Gen2/risk/assess", json={"threat_ref": ref}).status_code == 200
    assert client.post("/projects/TCU-Gen2/risk/recalculate", json={"threat_ref": ref}).status_code == 200
    assert client.post(
        "/projects/TCU-Gen2/mitigations/generate",
        json={"threat_ref": ref},
    ).status_code == 200
