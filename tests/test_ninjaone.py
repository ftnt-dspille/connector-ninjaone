"""Unit tests for the NinjaOne connector.

Every HTTP call is faked -- these tests assert on the wire shape the connector
produces (paths, query params, bodies, pagination, auth, retry) and on the error
messages it raises, not on NinjaOne's behaviour. The response shapes used here
were captured from a live tenant; see tests/fixtures/. The FortiSOAR-only
platform modules are stubbed in conftest.py.

    pytest -q
"""

import json

import pytest
from connectors.core.connector import ConnectorError

from ninjaone import operations as ops

CONFIG = {
    "region": "Canada (ca.ninjarmm.com)",
    "client_id": "client-id",
    "client_secret": "client-secret",
    "scope": "monitoring management control",
    "verify_ssl": True,
    # Pre-seeded so most tests do not have to fake a token mint every time.
    "access_token": "cached-token",
    "access_token_expiry": 4102444800,  # year 2100
}

BASE = "https://ca.ninjarmm.com/v2"


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload if payload is not None else {})
        self.headers = headers or {}
        self.content = self.text.encode()

    @property
    def ok(self):
        return 200 <= self.status_code < 300

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class Recorder:
    """Stands in for requests.request; replays a queue of responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError(f"unexpected extra request: {method} {url}")
        return self.responses.pop(0)


def config(**overrides):
    merged = dict(CONFIG)
    merged.update(overrides)
    return merged


@pytest.fixture
def recorder(monkeypatch):
    def _install(*responses):
        rec = Recorder(responses)
        monkeypatch.setattr(ops.requests, "request", rec)
        return rec

    return _install


def body_of(call):
    return json.loads(call["data"])


# ------------------------------------------------------------------- auth --

def test_region_selects_the_right_host(recorder):
    rec = recorder(FakeResponse(payload=[]))
    ops.get_groups(config(), {})
    assert rec.calls[0]["url"] == BASE + "/groups"


def test_unknown_region_is_rejected_rather_than_defaulting():
    # A typo in a hand-edited config must not silently query North America and
    # report an empty estate.
    with pytest.raises(ConnectorError) as err:
        ops.get_groups(config(region="Atlantis"), {})
    assert "Unknown region" in str(err.value)


def test_custom_server_url_overrides_region(recorder):
    rec = recorder(FakeResponse(payload=[]))
    ops.get_groups(config(server_url="https://ninja.internal.example.com/"), {})
    assert rec.calls[0]["url"] == "https://ninja.internal.example.com/v2/groups"


def test_token_is_minted_when_absent(monkeypatch):
    posts = []

    def fake_post(url, data=None, **kwargs):
        posts.append({"url": url, "data": data})
        return FakeResponse(payload={"access_token": "fresh", "expires_in": 3600})

    rec = Recorder([FakeResponse(payload=[])])
    monkeypatch.setattr(ops.requests, "post", fake_post)
    monkeypatch.setattr(ops.requests, "request", rec)

    cfg = config()
    cfg.pop("access_token")
    cfg.pop("access_token_expiry")
    ops.get_groups(cfg, {})

    assert posts[0]["url"] == "https://ca.ninjarmm.com/ws/oauth/token"
    assert posts[0]["data"]["grant_type"] == "client_credentials"
    # Live-verified: the token endpoint rejects a request with no scope
    # (invalid_scope), so the connector must always send one.
    assert posts[0]["data"]["scope"] == "monitoring management control"
    assert rec.calls[0]["headers"]["Authorization"] == "Bearer fresh"


def test_expired_cached_token_is_reminted(monkeypatch):
    monkeypatch.setattr(ops.requests, "post", lambda url, data=None, **kw: FakeResponse(
        payload={"access_token": "fresh", "expires_in": 3600}))
    rec = Recorder([FakeResponse(payload=[])])
    monkeypatch.setattr(ops.requests, "request", rec)

    ops.get_groups(config(access_token="stale", access_token_expiry=1), {})
    assert rec.calls[0]["headers"]["Authorization"] == "Bearer fresh"


def test_401_retries_exactly_once(monkeypatch):
    # Live-verified: an expired or tampered token answers 401 not_authenticated.
    monkeypatch.setattr(ops.requests, "post", lambda url, data=None, **kw: FakeResponse(
        payload={"access_token": "fresh", "expires_in": 3600}))
    rec = Recorder([
        FakeResponse(401, payload={"error": "not_authenticated"}),
        FakeResponse(payload=[{"id": 1}]),
    ])
    monkeypatch.setattr(ops.requests, "request", rec)

    ops.get_groups(config(), {})
    assert len(rec.calls) == 2
    assert rec.calls[1]["headers"]["Authorization"] == "Bearer fresh"


def test_repeated_401_does_not_loop(monkeypatch):
    monkeypatch.setattr(ops.requests, "post", lambda url, data=None, **kw: FakeResponse(
        payload={"access_token": "fresh", "expires_in": 3600}))
    rec = Recorder([
        FakeResponse(401, payload={"error": "not_authenticated"}),
        FakeResponse(401, payload={"error": "not_authenticated"}),
    ])
    monkeypatch.setattr(ops.requests, "request", rec)

    with pytest.raises(ConnectorError):
        ops.get_groups(config(), {})
    assert len(rec.calls) == 2


def test_400_is_not_retried(monkeypatch):
    # A missing/malformed Authorization header answers 400. That is a bug here,
    # not an expiry, so retrying would only double the latency.
    rec = Recorder([FakeResponse(400, payload={"error": "invalid_header"})])
    monkeypatch.setattr(ops.requests, "request", rec)
    with pytest.raises(ConnectorError):
        ops.get_groups(config(), {})
    assert len(rec.calls) == 1


@pytest.mark.parametrize("body,needle", [
    ({"resultCode": "Client app not exist"}, "region-isolated"),
    ({"error": "unauthorized_client"}, "client_credentials"),
    ({"error": "invalid_scope"}, "not authorized for one of the requested scopes"),
])
def test_token_errors_explain_the_actual_remedy(monkeypatch, body, needle):
    # These two strings both read like a bad secret but mean entirely different
    # things, and neither remedy is guessable from the message NinjaOne returns.
    monkeypatch.setattr(ops.requests, "post",
                        lambda url, data=None, **kw: FakeResponse(200, payload=body))
    cfg = config()
    cfg.pop("access_token")
    with pytest.raises(ConnectorError) as err:
        ops.get_groups(cfg, {})
    assert needle in str(err.value)


def test_missing_credentials_fail_before_any_request(monkeypatch):
    monkeypatch.setattr(ops.requests, "request", Recorder([]))
    cfg = config(client_id="", client_secret="")
    cfg.pop("access_token")
    with pytest.raises(ConnectorError) as err:
        ops.get_groups(cfg, {})
    assert "Client ID and Client Secret" in str(err.value)


def test_numeric_client_id_stored_as_int_does_not_crash(monkeypatch):
    # FortiSOAR stores a numeric-looking 'text' field as an int; .strip() on it
    # is the classic on-box-only crash.
    rec = Recorder([FakeResponse(payload=[])])
    monkeypatch.setattr(ops.requests, "request", rec)
    ops.get_groups(config(client_id=12345), {})
    assert rec.calls


# ---------------------------------------------------------------- errors --

def test_error_detail_prefers_the_message_over_the_incident_id(recorder):
    # Live shape: {"resultCode": "FAILURE", "errorMessage": "Device not found", ...}
    recorder(FakeResponse(404, payload={
        "resultCode": "FAILURE", "errorMessage": "Device not found",
        "incidentId": "WEB_MGMT_SERVICE-abc",
    }))
    with pytest.raises(ConnectorError) as err:
        ops.get_device(config(), {"device_id": 5})
    assert "Device not found" in str(err.value)


def test_error_detail_unwraps_a_nested_code(recorder):
    # Live shape from a tenant without the ticketing add-on.
    recorder(FakeResponse(403, payload={
        "errorMessage": {"code": "Ninja Ticketing Integration is not enabled", "params": {}}}))
    with pytest.raises(ConnectorError) as err:
        ops.get_ticket(config(), {"ticket_id": 1})
    assert "Ninja Ticketing Integration is not enabled" in str(err.value)


def test_error_detail_falls_back_to_a_plain_text_body(recorder):
    # Live shape: DELETE /v2/alert/<bad-uid> answers the bare string.
    recorder(FakeResponse(400, payload=None, text="uid incorrect type"))
    with pytest.raises(ConnectorError) as err:
        ops.reset_alert(config(), {"alert_uid": "nope"})
    assert "uid incorrect type" in str(err.value)


def test_non_numeric_device_id_names_the_fix():
    with pytest.raises(ConnectorError) as err:
        ops.get_device(config(), {"device_id": "WKSTN-01"})
    assert "Search Devices" in str(err.value)


def test_missing_required_param_is_named():
    with pytest.raises(ConnectorError) as err:
        ops.search_devices(config(), {})
    assert "Search Query is required" in str(err.value)


# ------------------------------------------------------------ pagination --

def test_paginate_after_walks_pages_and_stops_on_a_short_page(recorder):
    page1 = [{"id": i} for i in range(1, 1001)]
    page2 = [{"id": 1001}]
    rec = recorder(FakeResponse(payload=page1), FakeResponse(payload=page2))
    result = ops.get_devices(config(), {"max_records": 2000})

    assert result["count"] == 1001
    assert rec.calls[0]["params"]["pageSize"] == 1000
    # Page two must resume from the last id seen, not from an offset.
    assert rec.calls[1]["params"]["after"] == 1000


def test_paginate_after_respects_max_records(recorder):
    rec = recorder(FakeResponse(payload=[{"id": i} for i in range(1, 6)]))
    result = ops.get_devices(config(), {"max_records": 5})
    assert result["count"] == 5
    assert rec.calls[0]["params"]["pageSize"] == 5
    assert len(rec.calls) == 1


def test_paginate_cursor_follows_the_nested_cursor_name(recorder):
    # The report endpoints return the next cursor under cursor.name -- not at the
    # top level, and not as the `after` integer the device endpoints use.
    rec = recorder(
        FakeResponse(payload={"results": [{"deviceId": 1}] * 1000,
                              "cursor": {"name": "cursor-abc", "count": 1500}}),
        FakeResponse(payload={"results": [{"deviceId": 2}], "cursor": {"name": "cursor-def"}}),
    )
    result = ops.get_pending_os_patches_report(config(), {"max_records": 2000})
    assert result["count"] == 1001
    assert rec.calls[1]["params"]["cursor"] == "cursor-abc"


def test_paginate_cursor_handles_an_empty_report(recorder):
    # Live-verified: an empty report answers {"results": []} with no cursor key
    # at all, which must terminate rather than KeyError.
    rec = recorder(FakeResponse(payload={"results": []}))
    result = ops.get_pending_software_patches_report(config(), {})
    assert result == {"count": 0, "cursor": {}, "results": []}
    assert len(rec.calls) == 1


def test_paginate_after_tolerates_an_object_response(recorder):
    # A filter error answers an object, not a list; iterating it would silently
    # yield key names as if they were devices.
    recorder(FakeResponse(payload={"resultCode": "FAILURE"}))
    result = ops.get_devices(config(), {})
    assert result["count"] == 0


# ------------------------------------------------------------- filtering --

def test_device_filter_is_sent_as_df(recorder):
    rec = recorder(FakeResponse(payload=[]))
    ops.get_devices(config(), {"device_filter": "class = WINDOWS_WORKSTATION"})
    assert rec.calls[0]["params"]["df"] == "class = WINDOWS_WORKSTATION"


def test_multiselect_filters_are_sent_comma_separated(recorder):
    rec = recorder(FakeResponse(payload=[]))
    ops.get_device_pending_os_patches(
        config(), {"device_id": 7, "status": ["APPROVED", "FAILED"], "severity": "CRITICAL"})
    assert rec.calls[0]["params"]["status"] == "APPROVED,FAILED"
    assert rec.calls[0]["params"]["severity"] == "CRITICAL"


def test_empty_params_are_dropped_entirely(recorder):
    rec = recorder(FakeResponse(payload=[]))
    ops.get_device_windows_services(config(), {"device_id": 7, "name": "", "state": None})
    assert rec.calls[0]["params"] == {}


def test_datetimes_are_converted_to_iso(recorder):
    rec = recorder(FakeResponse(payload=[]))
    ops.get_device_installed_os_patches(
        config(), {"device_id": 7, "installed_after": "2026-08-01T00:00:00Z"})
    assert rec.calls[0]["params"]["installedAfter"].startswith("2026-08-01T00:00:00")


# --------------------------------------------------------------- devices --

def test_get_device_dashboard_url_suppresses_the_redirect(recorder):
    # Following the 302 would hand back an HTML login page instead of the link.
    rec = recorder(FakeResponse(payload={"url": "https://ca.ninjarmm.com/#/deviceDashboard/7"}))
    ops.get_device_dashboard_url(config(), {"device_id": 7})
    assert rec.calls[0]["params"]["redirect"] == "false"


def test_update_device_builds_a_patch_body(recorder):
    rec = recorder(FakeResponse(payload={}))
    ops.update_device(config(), {"device_id": 7, "display_name": "WKSTN-01", "policy_id": 3})
    assert rec.calls[0]["method"] == "PATCH"
    assert body_of(rec.calls[0]) == {"displayName": "WKSTN-01", "policyId": 3}


def test_update_device_with_nothing_to_change_is_refused():
    with pytest.raises(ConnectorError) as err:
        ops.update_device(config(), {"device_id": 7})
    assert "Nothing to update" in str(err.value)


def test_additional_fields_accepts_a_json_string(recorder):
    rec = recorder(FakeResponse(payload={}))
    ops.update_device(config(), {"device_id": 7, "additional_fields": '{"warranty": {"status": "OK"}}'})
    assert body_of(rec.calls[0])["warranty"] == {"status": "OK"}


def test_malformed_json_param_is_named(recorder):
    with pytest.raises(ConnectorError) as err:
        ops.update_device_custom_fields(config(), {"device_id": 7, "fields": "{not json"})
    assert "Field Values must be valid JSON" in str(err.value)


# -------------------------------------------------------------- patching --

@pytest.mark.parametrize("operation,path", [
    (ops.scan_os_patches, "/device/7/patch/os/scan"),
    (ops.apply_os_patches, "/device/7/patch/os/apply"),
    (ops.scan_software_patches, "/device/7/patch/software/scan"),
    (ops.apply_software_patches, "/device/7/patch/software/apply"),
])
def test_patch_jobs_post_and_report_submitted(recorder, operation, path):
    # These answer 204 with an empty body and no job id, so 'Submitted' is the
    # honest contract -- anything more would imply a handle the caller could poll.
    rec = recorder(FakeResponse(204, payload=None, text=""))
    result = operation(config(), {"device_id": 7})
    assert rec.calls[0]["method"] == "POST"
    assert rec.calls[0]["url"] == BASE + path
    assert result["status"] == "Submitted"
    assert result["device_id"] == 7
    assert "Get Device Jobs" in result["message"]


# --------------------------------------------------------------- control --

def test_run_script_sends_a_script_id_as_type_script(recorder):
    rec = recorder(FakeResponse(payload={"jobUid": "abc"}))
    ops.run_script(config(), {"device_id": 7, "script_id": 12, "parameters": "-Force"})
    assert body_of(rec.calls[0]) == {"type": "SCRIPT", "id": 12, "parameters": "-Force"}


def test_run_script_sends_an_action_uid_as_type_action(recorder):
    rec = recorder(FakeResponse(payload={"jobUid": "abc"}))
    ops.run_script(config(), {"device_id": 7, "action_uid": "built-in-uid"})
    assert body_of(rec.calls[0]) == {"type": "ACTION", "uid": "built-in-uid"}


def test_run_script_refuses_both_identifiers():
    # NinjaOne rejects the combination, and the API error does not say why.
    with pytest.raises(ConnectorError) as err:
        ops.run_script(config(), {"device_id": 7, "script_id": 12, "action_uid": "x"})
    assert "only one" in str(err.value)


def test_run_script_refuses_neither_identifier():
    with pytest.raises(ConnectorError) as err:
        ops.run_script(config(), {"device_id": 7})
    assert "Script ID" in str(err.value)


def test_reboot_uses_the_mode_in_the_path(recorder):
    rec = recorder(FakeResponse(204, payload=None, text=""))
    result = ops.reboot_device(config(), {"device_id": 7, "mode": "forced", "reason": "patching"})
    assert rec.calls[0]["url"] == BASE + "/device/7/reboot/FORCED"
    assert body_of(rec.calls[0]) == {"reason": "patching"}
    assert result["mode"] == "FORCED"


def test_reboot_rejects_an_unknown_mode():
    with pytest.raises(ConnectorError) as err:
        ops.reboot_device(config(), {"device_id": 7, "mode": "GENTLE"})
    assert "NORMAL or FORCED" in str(err.value)


def test_control_windows_service_posts_the_action(recorder):
    rec = recorder(FakeResponse(204, payload=None, text=""))
    ops.control_windows_service(
        config(), {"device_id": 7, "service_id": "Spooler", "action": "restart"})
    assert rec.calls[0]["url"] == BASE + "/device/7/windows-service/Spooler/control"
    assert body_of(rec.calls[0]) == {"action": "RESTART"}


def test_maintenance_requires_an_end_time():
    # NinjaOne has no open-ended maintenance; omitting end fails the call.
    with pytest.raises(ConnectorError) as err:
        ops.schedule_maintenance(config(), {"device_id": 7})
    assert "End Time is required" in str(err.value)


def test_maintenance_sends_epoch_milliseconds(recorder):
    rec = recorder(FakeResponse(204, payload=None, text=""))
    ops.schedule_maintenance(config(), {
        "device_id": 7, "end_time": "2026-09-01T00:00:00Z",
        "disabled_features": "ALERTS,PATCHING", "reason": "change window"})
    body = body_of(rec.calls[0])
    assert body["end"] == 1788220800000  # 2026-09-01T00:00:00Z
    assert body["disabledFeatures"] == ["ALERTS", "PATCHING"]


# ---------------------------------------------------------------- alerts --

def test_reset_alert_uses_delete_without_activity_data(recorder):
    rec = recorder(FakeResponse(204, payload=None, text=""))
    ops.reset_alert(config(), {"alert_uid": "uid-1"})
    assert rec.calls[0]["method"] == "DELETE"
    assert rec.calls[0]["url"] == BASE + "/alert/uid-1"


def test_reset_alert_uses_post_with_activity_data(recorder):
    rec = recorder(FakeResponse(204, payload=None, text=""))
    ops.reset_alert(config(), {"alert_uid": "uid-1", "activity_data": {"case": "IR-9"}})
    assert rec.calls[0]["method"] == "POST"
    assert rec.calls[0]["url"] == BASE + "/alert/uid-1/reset"
    assert body_of(rec.calls[0]) == {"case": "IR-9"}


# ------------------------------------------------------------- ticketing --

def test_create_ticket_wraps_a_string_description_in_an_object(recorder):
    # `description` is an object in the schema; a bare string is rejected.
    rec = recorder(FakeResponse(payload={"id": 1}))
    ops.create_ticket(config(), {
        "organization_id": 1, "ticket_form_id": 2, "subject": "Patch WKSTN-01",
        "status": "NEW", "description": "CVE-2026-1234 pending", "public": True})
    body = body_of(rec.calls[0])
    assert body["description"] == {"public": True, "body": "CVE-2026-1234 pending"}
    assert body["clientId"] == 1


def test_update_ticket_reads_then_merges(recorder):
    # The update endpoint is a full replace: version, clientId, ticketFormId,
    # subject, status and requesterUid are mandatory on every call, so sending
    # only the changed field would wipe the rest.
    rec = recorder(
        FakeResponse(payload={"id": 9, "version": 4, "clientId": 1, "ticketFormId": 2,
                              "subject": "Patch WKSTN-01", "status": "NEW",
                              "requesterUid": "uid-r", "priority": "LOW", "tags": ["patch"]}),
        FakeResponse(payload={"id": 9, "version": 5}),
    )
    ops.update_ticket(config(), {"ticket_id": 9, "status": "RESOLVED"})

    assert rec.calls[0]["method"] == "GET"
    body = body_of(rec.calls[1])
    assert rec.calls[1]["method"] == "PUT"
    assert body["status"] == "RESOLVED"
    # Everything not being changed must survive the replace.
    assert body["version"] == 4
    assert body["subject"] == "Patch WKSTN-01"
    assert body["requesterUid"] == "uid-r"
    assert body["priority"] == "LOW"
    assert body["tags"] == ["patch"]


def test_update_ticket_reports_fields_the_endpoint_needs(recorder):
    recorder(FakeResponse(payload={"id": 9, "subject": "x"}))
    with pytest.raises(ConnectorError) as err:
        ops.update_ticket(config(), {"ticket_id": 9, "status": "RESOLVED"})
    assert "version" in str(err.value)
    assert "Additional Fields" in str(err.value)


def test_add_ticket_comment_posts_multipart(recorder):
    # Live requirement: this endpoint is multipart/form-data even with no file,
    # and a plain JSON body returns 415. requests must set the boundary itself,
    # so no Content-Type may be forced here.
    rec = recorder(FakeResponse(payload={"id": 3}))
    ops.add_ticket_comment(config(), {"ticket_id": 9, "body": "Patched", "public": False})
    call = rec.calls[0]
    assert "files" in call
    assert "data" not in call
    assert call["headers"].get("Content-Type") is None
    name, payload, content_type = call["files"]["comment"]
    assert name is None and content_type == "application/json"
    assert json.loads(payload) == {"body": "Patched", "public": False}


# ------------------------------------------------------------ ingestion --

def test_fetch_patch_findings_merges_both_sources(recorder):
    rec = recorder(
        FakeResponse(payload={"results": [
            {"deviceId": 5, "kbNumber": "KB5001", "title": "Cumulative Update",
             "severity": "CRITICAL", "status": "APPROVED", "cveIds": ["CVE-2026-1"]}]}),
        FakeResponse(payload={"results": [
            {"deviceId": 5, "patchId": "p-1", "productName": "7-Zip", "version": "22.0",
             "impact": "RECOMMENDED", "status": "APPROVED"}]}),
    )
    result = ops.fetch_patch_findings(config(), {})

    assert len(rec.calls) == 2
    assert result["count"] == 2
    os_finding, sw_finding = result["findings"]
    assert os_finding["source_id"] == "os:5:KB5001"
    assert os_finding["cve_ids"] == ["CVE-2026-1"]
    assert os_finding["severity"] == "CRITICAL"
    assert sw_finding["source_id"] == "software:5:p-1"
    assert sw_finding["product"] == "7-Zip"
    assert sw_finding["version"] == "22.0"


def test_fetch_patch_findings_can_narrow_to_one_source(recorder):
    rec = recorder(FakeResponse(payload={"results": []}))
    ops.fetch_patch_findings(config(), {"patch_kind": "Operating System"})
    assert len(rec.calls) == 1
    assert rec.calls[0]["url"] == BASE + "/queries/os-patches"


def test_finding_source_id_is_stable_per_device_and_patch():
    # A source_id that varies between runs makes every ingestion create a
    # duplicate record instead of updating the existing one.
    row = {"deviceId": 5, "kbNumber": "KB5001"}
    assert ops._normalize_patch(row, "os")["source_id"] == \
        ops._normalize_patch(dict(row), "os")["source_id"]


def test_impact_filter_only_applies_to_software(recorder):
    rec = recorder(FakeResponse(payload={"results": []}),
                   FakeResponse(payload={"results": []}))
    ops.fetch_patch_findings(config(), {"severity": "CRITICAL", "impact": "OPTIONAL"})
    assert rec.calls[0]["params"].get("severity") == "CRITICAL"
    assert "impact" not in rec.calls[0]["params"]
    assert rec.calls[1]["params"].get("impact") == "OPTIONAL"
    assert "severity" not in rec.calls[1]["params"]


# ---------------------------------------------------------------- health --

def test_health_check_passes_on_a_list(recorder):
    rec = recorder(FakeResponse(payload=[{"id": 1, "name": "Internal Infrastructure"}]))
    assert ops._check_health(config()) is True
    # Must not walk a 10k-device estate just to prove the token works.
    assert rec.calls[0]["params"] == {"pageSize": 1}


def test_health_check_fails_on_an_unexpected_shape(recorder):
    recorder(FakeResponse(payload={"errorMessage": "nope"}))
    with pytest.raises(ConnectorError):
        ops._check_health(config())


def test_health_check_surfaces_the_token_hint(monkeypatch):
    monkeypatch.setattr(ops.requests, "post", lambda url, data=None, **kw: FakeResponse(
        200, payload={"resultCode": "Client app not exist"}))
    cfg = config()
    cfg.pop("access_token")
    with pytest.raises(ConnectorError) as err:
        ops._check_health(cfg)
    assert "region-isolated" in str(err.value)


# ------------------------------------------------------------ installers --

def test_generate_installer_always_sends_a_content_object(recorder):
    # Live-verified: the OpenAPI document marks `content` optional, but the
    # server rejects a request without it with a Jackson instantiation error
    # that reads like a server fault rather than a missing field.
    rec = recorder(FakeResponse(payload={"url": "https://ca.ninjarmm.com/agent/installer/x.msi"}))
    ops.generate_installer(config(), {
        "organization_id": 1, "location_id": 1,
        "installer_type": "windows_msi", "usage_limit": 1})
    body = body_of(rec.calls[0])
    assert body["content"] == {}
    assert body["installerType"] == "WINDOWS_MSI"
    assert body["usageLimit"] == 1


def test_generate_installer_rejects_an_unknown_type():
    with pytest.raises(ConnectorError) as err:
        ops.generate_installer(config(), {
            "organization_id": 1, "location_id": 1, "installer_type": "LINUX_SNAP"})
    assert "Installer Type must be one of" in str(err.value)
