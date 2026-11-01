"""Regression coverage for the proposal -> canonical patch -> approval contract."""
import json
from unittest.mock import patch

import pytest

from backend.guardian import remediation as r
from backend.guardian.projects import project_manager, compute_sha256
from backend.guardian.models import Advisory
from test_remediation import AXIOS_PKG_JSON, AXIOS_LOCK_JSON, make_val_report


def metadata(name, version, **extra):
    return dict(name=name, version=version, dist={
        "tarball": f"https://registry.npmjs.org/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz",
        "integrity": "sha512-" + version,
    }, **extra)


def snapshot(lock_version=3, compact=False):
    lock = json.loads(AXIOS_LOCK_JSON)
    lock["lockfileVersion"] = lock_version
    if lock_version == 2:
        lock["dependencies"] = {"axios": dict(lock["packages"]["node_modules/axios"])}
    return project_manager.save_snapshot("pipeline", "app", {
        "package.json": AXIOS_PKG_JSON,
        "package-lock.json": json.dumps(lock, indent=None if compact else 2),
    })


def registry(name, version=None):
    versions = {v: metadata(name, v) for v in ("1.7.9", "1.8.2", "2.0.0")}
    return (versions[version] if version else {"name": name, "versions": versions}), "ok", None


def apply_changes(plan, files):
    result = dict(files)
    for change in plan.proposed_changes:
        assert compute_sha256(result[change.file_path]) == change.original_sha256
        for edit in change.edits:
            assert result[change.file_path].count(edit.old_text) == 1
            result[change.file_path] = result[change.file_path].replace(edit.old_text, edit.new_text, 1)
        assert compute_sha256(result[change.file_path]) == change.proposed_sha256
    return result


@pytest.mark.parametrize("compact", [False, True])
def test_v2_duplicate_dist_metadata_is_updated_atomically(compact):
    snap = snapshot(2, compact)
    lock = snap.files["package-lock.json"]
    dist = metadata("axios", "1.8.2")["dist"]
    edits = r.generate_lockfile_edits(lock, "axios", "^1.8.2", "1.8.2", dist["tarball"], dist["integrity"])
    updated = lock
    for edit in edits:
        assert updated.count(edit.old_text) == 1
        updated = updated.replace(edit.old_text, edit.new_text, 1)
    changes = r.extract_manifest_dependency_changes(AXIOS_PKG_JSON, AXIOS_PKG_JSON.replace("1.7.9", "1.8.2"))
    assert r.validate_lockfile_consistency(lock, updated, changes, {"axios": metadata("axios", "1.8.2")}) == []


def test_structured_ai_proposal_produces_canonical_manifest_and_lock():
    snap = snapshot(2)
    raw = r.LLMRemediationOutput(title="Upgrade", summary="Fix advisory", findings_addressed=["f_axios_ssrf"],
        dependency_proposals=[r.DependencyChangeProposal(package_name="axios", original_version="^1.7.9", proposed_version="1.8.2")])
    with patch.object(r, "get_ai_config", return_value={"enabled": True, "provider": "gemini"}), \
         patch.object(r.remediation_planner, "_generate_with_gemini", return_value=raw), \
         patch.object(r, "query_npm_registry", side_effect=registry), \
         patch.object(r, "query_osv_vulnerability", return_value=([], "ok")):
        plan = r.remediation_planner.generate_plan(make_val_report("pipeline"), snap, consent=True)
    assert plan.validation_status == "VERIFIED", plan.validation_reasons
    assert {ch.file_path for ch in plan.proposed_changes} == {"package.json", "package-lock.json"}
    apply_changes(plan, snap.files)


def test_multiple_changes_share_one_file_hash_and_diff():
    snap = project_manager.save_snapshot("pipeline-multi", "app", {"app.js": "const a = 1;\nconst b = 2;\n"})
    raw = r.LLMRemediationOutput(title="Fix", summary="Fix", proposed_changes=[
        r.LLMProposedFileChange(file_path="app.js", edits=[r.LLMTextEdit(old_text=old, new_text=new)], rationale="Fix", expected_result="Fixed")
        for old, new in [("a = 1", "a = 3"), ("b = 2", "b = 4")]])
    plan = r.remediation_planner._validate_and_build_plan(make_val_report(), snap, raw, [])
    assert len(plan.proposed_changes) == 1
    assert apply_changes(plan, snap.files)["app.js"] == "const a = 3;\nconst b = 4;\n"


def test_advisory_open_interval_and_semver_prerelease():
    advisory = Advisory(id="open", affected_ranges=[{"type": "SEMVER", "events": [{"introduced": "1.2.0"}]}])
    assert r.is_version_vulnerable_to_advisory("1.3.0", advisory)
    assert r.compare_semver("1.2.0-beta.2", "1.2.0-beta.10") == -1


def proposal(name="axios", target="1.8.2", original="^1.7.9"):
    return r.LLMRemediationOutput(title="Upgrade", summary="Resolve selected advisory", findings_addressed=["f_axios_ssrf"],
        dependency_proposals=[r.DependencyChangeProposal(package_name=name, original_version=original, proposed_version=target)])


def ai_plan(snap, raw, query=registry, osv=([], "ok"), report=None):
    with patch.object(r, "get_ai_config", return_value={"enabled": True, "provider": "gemini"}), \
         patch.object(r.remediation_planner, "_generate_with_gemini", return_value=raw), \
         patch.object(r, "query_npm_registry", side_effect=query), \
         patch.object(r, "query_osv_vulnerability", return_value=osv):
        return r.remediation_planner.generate_plan(report or make_val_report("pipeline"), snap, consent=True)


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("compact", [False, True])
def test_generated_plan_passes_for_both_lockfile_formats(version, compact):
    snap = snapshot(version, compact)
    plan = ai_plan(snap, proposal())
    assert plan.validation_status == "VERIFIED", plan.validation_reasons
    files = apply_changes(plan, snap.files)
    lock = json.loads(files["package-lock.json"])
    assert lock["packages"]["node_modules/axios"]["version"] == "1.8.2"
    assert next(c for c in plan.proposed_changes if c.file_path == "package-lock.json").edit_source == "npm_registry"
    if version == 2:
        assert lock["dependencies"]["axios"]["integrity"] == metadata("axios", "1.8.2")["dist"]["integrity"]


@pytest.mark.parametrize("target,expected", [("1.8.0", "Vulnerable"), ("0.29.0", "downgrade"), ("9.9.999", "nonexistent")])
def test_ai_dependency_proposal_cannot_bypass_target_validation(target, expected):
    def query(name, version=None):
        if version == "9.9.999":
            return None, "not_found", "404"
        if version:
            return metadata(name, version), "ok", None
        return registry(name)
    plan = ai_plan(snapshot(), proposal(target=target), query=query)
    assert plan.validation_status == "REJECTED", plan.validation_reasons
    assert expected.lower() in " ".join(plan.validation_reasons).lower()


@pytest.mark.parametrize("outage", ["registry", "advisory", "missing-dist", "identity"])
def test_unverifiable_metadata_stays_unverified(outage):
    def query(name, version=None):
        if outage == "registry":
            return None, "unavailable", "Registry offline"
        meta = metadata(name, version or "1.8.2")
        if outage == "missing-dist":
            meta["dist"] = {}
        if outage == "identity":
            meta["name"] = "unrelated"
        return meta, "ok", None
    plan = ai_plan(snapshot(), proposal(), query=query, osv=([], "unavailable" if outage == "advisory" else "ok"))
    assert plan.validation_status == "UNVERIFIED", plan.validation_reasons
    assert plan.validation_reasons


def test_unrelated_advisory_does_not_reject_another_packages_target():
    report = make_val_report("pipeline")
    other = report.findings[0].model_copy(deep=True)
    other.id = "other"
    other.package = "axios-extra@20.0.0"
    other.advisory = Advisory(id="other-advisory", fixed_versions=["21.0.0"])
    report.findings.append(other)
    assert ai_plan(snapshot(), proposal(), report=report).validation_status == "VERIFIED"


def test_changed_transitive_requirements_are_resolved_and_registry_backed():
    def query(name, version=None):
        if name == "axios":
            return metadata(name, version, dependencies={"helper": "^3.0.0"}), "ok", None
        if version:
            return metadata(name, version), "ok", None
        return {"name": name, "versions": {"3.1.0": metadata(name, "3.1.0")}}, "ok", None
    snap = snapshot(2)
    plan = ai_plan(snap, proposal(), query=query)
    assert plan.validation_status == "VERIFIED", plan.validation_reasons
    lock = json.loads(apply_changes(plan, snap.files)["package-lock.json"])
    assert lock["packages"]["node_modules/axios"]["dependencies"] == {"helper": "^3.0.0"}
    assert lock["packages"]["node_modules/axios/node_modules/helper"]["version"] == "3.1.0"
    assert lock["dependencies"]["axios"]["requires"] == {"helper": "^3.0.0"}
    assert lock["dependencies"]["axios"]["dependencies"]["helper"]["version"] == "3.1.0"


def test_published_dependency_graph_must_match_patch_not_just_version_and_hash():
    snap = snapshot()
    plan = ai_plan(snap, proposal())
    with patch.object(r, "query_npm_registry", return_value=(metadata("axios", "1.8.2", dependencies={"missing": "^2.0.0"}), "ok", None)):
        status, reasons = r.validate_remediation_plan(plan, snap, make_val_report(), [])
    assert status == "REJECTED"
    assert "dependency metadata" in " ".join(reasons)


def test_major_upgrade_is_rejected_when_same_major_fix_is_available():
    plan = ai_plan(snapshot(), proposal(target="2.0.0"))
    assert plan.validation_status == "REJECTED"
    assert "same-major fix" in " ".join(plan.validation_reasons)


def test_sha1_fallback_comes_only_from_published_shasum():
    def query(name, version=None):
        meta = metadata(name, version)
        meta["dist"].pop("integrity")
        meta["dist"]["shasum"] = "ab" * 20
        return meta, "ok", None
    snap = snapshot()
    plan = ai_plan(snap, proposal(), query=query)
    assert plan.validation_status == "VERIFIED", plan.validation_reasons
    import base64
    lock = json.loads(apply_changes(plan, snap.files)["package-lock.json"])
    assert lock["packages"]["node_modules/axios"]["integrity"] == "sha1-" + base64.b64encode(bytes.fromhex("ab" * 20)).decode()


@pytest.mark.parametrize("path", ["../package.json", "/package.json", ".git/config", ".env"])
def test_invalid_paths_reject_entire_plan(path):
    snap = snapshot()
    raw = r.LLMRemediationOutput(title="Unsafe", summary="Unsafe", proposed_changes=[
        r.LLMProposedFileChange(file_path=path, operation="create", created_content="secret", rationale="unsafe", expected_result="unsafe")])
    plan = r.remediation_planner._validate_and_build_plan(make_val_report(), snap, raw, [])
    assert plan.validation_status == "REJECTED"


@pytest.mark.parametrize("response", [[], {"vulns": "wrong"}, {"next_page_token": "more"}, {"vulns": [{}]}])
def test_malformed_or_partial_osv_response_is_not_safety(response):
    with patch.object(r, "_metadata_request", return_value=(200, response)):
        assert r.query_osv_vulnerability("axios", "1.8.2") == ([], "unavailable")


def test_verification_does_not_lose_advisory_when_version_or_title_changes():
    before = make_val_report()
    after = before.model_copy(deep=True)
    after.findings[0].package = "axios@1.8.0"
    after.findings[0].title = "Axios SSRF in 1.8.0"
    plan = ai_plan(snapshot(), proposal())
    verification = r.remediation_planner.verify_plan(plan, before, after)
    assert verification.persistent_findings
    assert not verification.resolved_findings


@pytest.mark.parametrize("use_ai", [False, True])
def test_api_generated_plan_browser_apply_rescan_and_undo(monkeypatch, tmp_path, use_ai):
    """Real API jobs + parser + scanner + browser filesystem code; only external data is mocked."""
    import base64
    import hashlib
    import subprocess
    import time
    from pathlib import Path
    from urllib.parse import unquote
    from unittest.mock import MagicMock
    import httpx
    from fastapi.testclient import TestClient
    from backend.guardian.main import app
    from backend.guardian import ingestion
    from test_dependencies import tarball
    from test_remediation import AXIOS_ADVISORY

    monkeypatch.setenv("GUARDIAN_OSV_ENABLED", "true")
    monkeypatch.setenv("GUARDIAN_AI_ENABLED", "false")
    archives = {version: tarball("axios", version) for version in ("1.7.9", "1.8.2")}
    published = {}
    for version, raw in archives.items():
        published[version] = metadata("axios", version)
        published[version]["dist"]["integrity"] = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()
    detail = {"id": AXIOS_ADVISORY.id, "summary": "Synthetic advisory", "affected": [{
        "package": {"name": "axios", "ecosystem": "npm"}, "ranges": AXIOS_ADVISORY.affected_ranges,
    }]}

    def osv(payload):
        return {"vulns": [{"id": AXIOS_ADVISORY.id}]} if payload["package"]["name"] == "axios" and payload["version"] == "1.7.9" else {}

    def post(url, **kwargs):
        assert url == "https://api.osv.dev/v1/querybatch"
        return httpx.Response(200, json={"results": [osv(q) for q in kwargs["json"]["queries"]]}, request=httpx.Request("POST", url))

    def get(url, **kwargs):
        assert url == f"https://api.osv.dev/v1/vulns/{AXIOS_ADVISORY.id}"
        return httpx.Response(200, json=detail, request=httpx.Request("GET", url))

    def download(url, *args, **kwargs):
        assert url.startswith("https://registry.npmjs.org/axios/")
        if "/-/" in url:
            version = url.rsplit("axios-", 1)[1][:-4]
            return archives[version]
        return json.dumps(published[url.rsplit("/", 1)[1]]).encode()

    def meta_request(method, url, payload=None):
        if method == "POST":
            assert url == "https://api.osv.dev/v1/query"
            return 200, osv(payload)
        assert url.startswith("https://registry.npmjs.org/axios")
        suffix = unquote(url.removeprefix("https://registry.npmjs.org/axios"))
        return 200, published[suffix[1:]] if suffix else {"name": "axios", "versions": published}

    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr(httpx, "get", get)
    monkeypatch.setattr(ingestion, "download", download)
    monkeypatch.setattr(r, "_metadata_request", meta_request)
    client = TestClient(app)

    def scan(files):
        response = client.post("/api/scans/project", json={"name": "autopilot-val-app", "files": files})
        assert response.status_code == 202, response.text
        job_id = response.json()["id"]
        for _ in range(100):
            job = client.get(f"/api/jobs/{job_id}").json()
            if job["status"] in ("complete", "failed"):
                break
            time.sleep(0.05)
        assert job["status"] == "complete", job
        return client.get(f"/api/scans/{job_id}").json()

    files = dict(snapshot(2).files)
    # Exercise both exact and range manifests; the latter produces partial scan
    # intelligence and must be verified against its actual resolved copies.
    original_spec = "^1.7.9" if use_ai else "1.7.9"
    files["package.json"] = files["package.json"].replace("^1.7.9", original_spec)
    lock = json.loads(files["package-lock.json"])
    lock["packages"][""]["dependencies"]["axios"] = original_spec
    lock["packages"]["node_modules/axios"].update(published["1.7.9"]["dist"])
    lock["packages"]["node_modules/axios"]["resolved"] = lock["packages"]["node_modules/axios"].pop("tarball")
    lock["dependencies"]["axios"] = dict(lock["packages"]["node_modules/axios"])
    files["package-lock.json"] = json.dumps(lock, indent=2)
    files["index.js"] = "export const app = true;\n"
    before = scan(files)
    findings = [f for f in before["findings"] if f["rule"] == "OSV"]
    expected_intelligence = "partial" if use_ai else "checked"
    assert findings and before["intelligence"] == expected_intelligence
    raw = proposal(original=original_spec)
    raw.findings_addressed = [f["id"] for f in findings]
    ai_client = MagicMock()
    ai_client.models.generate_content.return_value.text = raw.model_dump_json()
    with patch.object(r, "get_ai_config", return_value={"enabled": use_ai, "provider": "gemini", "api_key": "test", "model": "gemini-3.8-flash"}), \
         patch("google.genai.Client", return_value=ai_client):
        generated = client.post(f"/api/scans/{before['id']}/remediation/plan", json={"consent": use_ai, "finding_ids": [f["id"] for f in findings]})
    assert generated.status_code == 200, generated.text
    plan = generated.json()
    assert plan["validation_status"] == "VERIFIED", plan["validation_reasons"]
    approved = client.post(f"/api/remediation/plans/{plan['plan_id']}/approve")
    assert approved.status_code == 200, approved.text
    case_path, output_path = tmp_path / "case.json", tmp_path / "result.json"
    case_path.write_text(json.dumps({"plan": approved.json(), "files": files}))
    root = Path(__file__).resolve().parents[2]
    process = subprocess.run(["node", "--experimental-strip-types", "scripts/test_fs_reapply.mjs", "--case", str(case_path), str(output_path)], cwd=root, capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stdout + process.stderr
    result = json.loads(output_path.read_text())
    applied = client.post(f"/api/remediation/plans/{plan['plan_id']}/applied", json={"applied_at": "now", "modified_files": result["applied"]["modifiedFiles"], "success": True})
    assert applied.status_code == 200, applied.text
    after = scan(result["modified"])
    assert after["intelligence"] == expected_intelligence
    assert not [f for f in after["findings"] if f["rule"] == "OSV"]
    verified = client.post(f"/api/remediation/plans/{plan['plan_id']}/verification", json={"rescanned_scan_id": after["id"]})
    assert verified.status_code == 200, verified.text
    assert verified.json()["resolved_findings"] and not verified.json()["persistent_findings"]
    reverted = client.post(f"/api/remediation/plans/{plan['plan_id']}/revert")
    assert reverted.status_code == 200, reverted.text
    assert result["restored"] == files
    restored_report = scan(result["restored"])
    assert any(f["rule"] == "OSV" for f in restored_report["findings"])


def test_verified_registry_lockfile_reaches_github_preflight():
    import base64
    from backend.guardian import github
    snap = snapshot(2)
    plan = ai_plan(snap, proposal())
    plan.repository_id, plan.branch, plan.commit_sha = 99, "main", "base"
    plan.status = "approved"
    def call(inst_id, endpoint, **kwargs):
        assert kwargs.get("method", "GET") == "GET"
        if endpoint.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "base"}}
        if endpoint.endswith("/git/commits/base"):
            return {"tree": {"sha": "tree"}}
        if "/git/trees/tree" in endpoint:
            return {"tree": [{"path": path, "type": "blob", "sha": path} for path in snap.files]}
        if "/git/blobs/" in endpoint:
            path = endpoint.split("/git/blobs/", 1)[1]
            return {"content": base64.b64encode(snap.files[path].encode()).decode()}
        raise AssertionError(endpoint)
    with patch.object(github, "_call_installation_api", side_effect=call):
        tree, contents, branch = github.preflight_validate_remediation(500, plan)
    assert tree == "tree"
    assert contents == apply_changes(plan, snap.files)


def test_scoped_package_and_arbitrary_versions_are_not_special_cased():
    name, old, target = "@example/tool", "4.2.0", "4.5.3"
    report = make_val_report("scoped").model_copy(deep=True)
    report.findings[0].package = f"{name}@{old}"
    report.findings[0].advisory = Advisory(id="SCOPED", affected_ranges=[{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": target}]}])
    manifest = {"name": "app", "devDependencies": {name: "~" + old}}
    lock = {"lockfileVersion": 3, "packages": {"": manifest, f"node_modules/{name}": {"version": old, "resolved": metadata(name, old)["dist"]["tarball"], "integrity": metadata(name, old)["dist"]["integrity"]}}}
    snap = project_manager.save_snapshot("scoped", "app", {"package.json": json.dumps(manifest), "package-lock.json": json.dumps(lock)})
    plan = ai_plan(snap, proposal(name, target, "~" + old), query=lambda name, version=None: (metadata(name, version), "ok", None), report=report)
    assert plan.validation_status == "VERIFIED", plan.validation_reasons
    assert json.loads(apply_changes(plan, snap.files)["package.json"])["devDependencies"][name] == "~" + target


def test_invalid_json_and_snapshot_hash_cannot_become_verified_noops():
    snap = snapshot()
    raw = r.LLMRemediationOutput(title="Invalid", summary="Invalid", proposed_changes=[r.LLMProposedFileChange(
        file_path="package.json", edits=[r.LLMTextEdit(old_text=AXIOS_PKG_JSON, new_text="{")], rationale="invalid", expected_result="invalid")])
    assert r.remediation_planner._validate_and_build_plan(make_val_report(), snap, raw, []).validation_status == "REJECTED"
    snap.file_hashes["package.json"] = "0" * 64
    assert r.remediation_planner._validate_and_build_plan(make_val_report(), snap, raw, []).validation_status == "REJECTED"


def test_unverified_applied_endpoint_is_blocked_even_if_status_is_approved():
    from backend.guardian import storage
    from fastapi.testclient import TestClient
    from backend.guardian.main import app
    plan = ai_plan(snapshot(), proposal(), osv=([], "unavailable"))
    plan.status = "approved"
    storage.save_plan(plan)
    response = TestClient(app).post(f"/api/remediation/plans/{plan.plan_id}/applied", json={"applied_at": "now", "success": True})
    assert response.status_code == 400
    assert "UNVERIFIED" in response.json()["detail"]


def test_rescan_with_unavailable_advisories_does_not_claim_resolution():
    before = make_val_report()
    after = before.model_copy(deep=True)
    after.findings = []
    after.intelligence = "unavailable"
    result = r.remediation_planner.verify_plan(ai_plan(snapshot(), proposal()), before, after)
    assert not result.resolved_findings
    assert "unverified" in result.persistent_findings[0]


@pytest.mark.parametrize("path", ["./package-lock.json", "nested/package-lock.json", "yarn.lock"])
def test_model_lockfile_paths_cannot_escape_provenance_guard(path):
    raw = r.LLMRemediationOutput(title="Unsafe lock", summary="Unsafe lock", proposed_changes=[r.LLMProposedFileChange(
        file_path=path, operation="create", created_content="{}", rationale="Unsafe", expected_result="Unsafe")])
    assert ai_plan(snapshot(), raw).validation_status == "REJECTED"


def test_unavailable_registry_is_visible_without_mislabeling_proposal_as_invalid():
    plan = ai_plan(snapshot(), proposal(), query=lambda *args: (None, "unavailable", "offline"))
    assert plan.validation_status == "UNVERIFIED"
    assert plan.status == "proposed"


def test_wrong_rescan_snapshot_is_rejected_before_marking_verified():
    from backend.guardian import storage
    from fastapi.testclient import TestClient
    from backend.guardian.main import app
    plan = ai_plan(snapshot(), proposal())
    storage.save(make_val_report(plan.scan_id))
    storage.save_plan(plan)
    storage.save(make_val_report("wrong-rescan"))
    project_manager.save_snapshot("wrong-rescan", "app", dict(snapshot().files))
    result = TestClient(app).post(f"/api/remediation/plans/{plan.plan_id}/verification", json={"rescanned_scan_id": "wrong-rescan"})
    assert result.status_code == 400
    assert "SHA-256" in result.json()["detail"]
    assert storage.get_plan(plan.plan_id).status == "proposed"


def test_new_transitive_nodes_preserve_development_and_optional_install_flags():
    snap = snapshot(2)
    manifest = json.loads(snap.files["package.json"])
    manifest["devDependencies"] = manifest.pop("dependencies")
    lock = json.loads(snap.files["package-lock.json"])
    lock["packages"][""]["devDependencies"] = lock["packages"][""].pop("dependencies")
    lock["packages"]["node_modules/axios"]["dev"] = True
    snap = project_manager.save_snapshot("pipeline-flags", "app", {"package.json": json.dumps(manifest), "package-lock.json": json.dumps(lock)})
    def query(name, version=None):
        if name == "axios":
            return metadata(name, version, optionalDependencies={"helper": "^3.0.0"}), "ok", None
        return (metadata(name, version) if version else {"name": name, "versions": {"3.1.0": metadata(name, "3.1.0")}}), "ok", None
    plan = ai_plan(snap, proposal(), query=query)
    assert plan.validation_status == "VERIFIED", plan.validation_reasons
    lock = json.loads(apply_changes(plan, snap.files)["package-lock.json"])
    assert lock["packages"]["node_modules/axios/node_modules/helper"]["dev"] is True
    assert lock["packages"]["node_modules/axios/node_modules/helper"]["optional"] is True
    assert lock["dependencies"]["axios"]["dependencies"]["helper"]["optional"] is True


def test_later_safe_release_is_reached_without_exhausting_budget_on_old_fixes():
    candidates = [f"4.{minor}.0" for minor in range(1, 41)]
    advisory = Advisory(id="old-boundary", fixed_versions=["4.1.0"])
    def osv(name, version):
        return ([], "ok") if version == "4.40.0" else ([{"id": "newer-advisory"}], "ok")
    with patch.object(r, "query_osv_vulnerability", side_effect=osv) as queries, \
         patch.object(r, "query_npm_registry", side_effect=lambda name, version=None: (metadata(name, version), "ok", None)):
        version, dist, error = r.select_patched_dependency_version("widget", "4.0.0", advisory, candidates)
    assert version == "4.40.0" and error is None
    assert queries.call_count == 2


def test_partial_report_enrichment_resolves_three_packages_once_and_preserves_ids():
    from backend.guardian.models import Finding
    report = make_val_report('partial-multi').model_copy(deep=True)
    report.findings = []
    versions = {'axios': ('0.21.1', '0.34.0'), 'lodash': ('4.17.20', '4.18.1'), 'minimist': ('1.2.5', '1.2.8')}
    manifest = {'name': 'app', 'dependencies': {name: old for name, (old, _) in versions.items()}}
    packages = {'': manifest}
    for name, (old, target) in versions.items():
        packages['node_modules/' + name] = dict(version=old, **{'resolved': metadata(name, old)['dist']['tarball'], 'integrity': metadata(name, old)['dist']['integrity']})
        for index in range(12):
            finding = make_val_report().findings[0].model_copy(deep=True)
            finding.id = f'{name}-{index}'
            finding.package = name + '@' + old
            finding.advisory = Advisory(id='ADV-' + name)
            report.findings.append(finding)
    snap = project_manager.save_snapshot(report.id, 'app', {'package.json': json.dumps(manifest), 'package-lock.json': json.dumps({'lockfileVersion': 3, 'packages': packages})})
    calls = []
    def query(name, version=None):
        calls.append((name, version))
        old, target = versions[name]
        return (metadata(name, version) if version else {'name': name, 'versions': {old: metadata(name, old), target: metadata(name, target)}}), 'ok', None
    def osv(name, version):
        old, target = versions[name]
        return ([{'id': 'ADV-' + name, 'affected': [{'package': {'name': name, 'ecosystem': 'npm'}, 'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': target}]}]}]}] if version == old else []), 'ok'
    with patch.object(r, 'query_npm_registry', side_effect=query), patch.object(r, 'query_osv_vulnerability', side_effect=osv):
        plan = r.remediation_planner.generate_plan(report, snap, consent=False)
    assert plan.validation_status == 'VERIFIED', plan.validation_reasons
    assert len(plan.proposed_changes) == 2
    assert len(plan.findings_addressed) == 36
    assert all(calls.count((name, None)) == 1 for name in versions)
    updated = apply_changes(plan, snap.files)
    assert json.loads(updated['package.json'])['dependencies'] == {name: target for name, (_, target) in versions.items()}


def test_background_generation_returns_before_work_and_delivers_same_plan():
    import threading
    import time
    from fastapi.testclient import TestClient
    from backend.guardian.main import app
    from backend.guardian import storage
    snap = snapshot()
    report = make_val_report('pipeline')
    storage.save(report)
    plan = ai_plan(snap, proposal())
    started, release = threading.Event(), threading.Event()
    def slow(*args, **kwargs):
        started.set()
        assert release.wait(10)
        return plan
    client = TestClient(app)
    with patch.object(r.remediation_planner, 'generate_plan', side_effect=slow):
        response = client.post('/api/scans/pipeline/remediation/jobs', json={'consent': False})
        assert response.status_code == 202
        identifier = response.json()['id']
        assert started.wait(2)
        assert client.get('/api/remediation/jobs/' + identifier).json()['status'] == 'running'
        release.set()
        for _ in range(100):
            state = client.get('/api/remediation/jobs/' + identifier).json()
            if state['status'] == 'complete':
                break
            time.sleep(.01)
        assert state['status'] == 'complete', state
        assert state['plan']['plan_id'] == plan.plan_id
        assert client.post('/api/remediation/plans/' + plan.plan_id + '/approve').status_code == 200


def test_background_generation_reports_failure_and_releases_capacity():
    import time
    from fastapi.testclient import TestClient
    from backend.guardian.main import app
    from backend.guardian import storage
    storage.save(make_val_report('background-fail'))
    client = TestClient(app)
    with patch.object(r.remediation_planner, 'generate_plan', side_effect=RuntimeError('registry transport failed')):
        for _ in range(3):
            response = client.post('/api/scans/background-fail/remediation/jobs', json={'consent': False})
            assert response.status_code == 202
            for _ in range(100):
                state = client.get('/api/remediation/jobs/' + response.json()['id']).json()
                if state['status'] == 'failed':
                    break
                time.sleep(.01)
            assert state['status'] == 'failed'
    # Missing snapshot is reported through the job, rather than a broken socket.
    assert 'snapshot' in state['error']
