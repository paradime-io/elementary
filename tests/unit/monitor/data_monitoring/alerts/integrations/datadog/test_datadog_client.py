from unittest import mock

import requests

from elementary.config.config import Config
from elementary.monitor.alerts.alerts_groups import AlertsGroup, GroupedByTableAlerts
from elementary.monitor.alerts.test_alert import TestAlertModel
from elementary.monitor.data_monitoring.alerts.data_monitoring_alerts import (
    DataMonitoringAlerts,
)
from elementary.monitor.data_monitoring.alerts.integrations.datadog.client import (
    MAX_INCIDENT_SUMMARY_LENGTH,
    MAX_INCIDENT_TITLE_LENGTH,
    MAX_RETRIES,
    DatadogApiClient,
    _truncate_utf8,
    build_incident_payload,
    get_alert_class_id,
    get_alert_token,
)
from elementary.monitor.data_monitoring.alerts.integrations.datadog.datadog import (
    DatadogIntegration,
)
from elementary.monitor.data_monitoring.alerts.integrations.datadog.types import (
    CreateIncidentInput,
    DatadogConfig,
    DatadogIncidentData,
    DatadogIncidentFieldAttributes,
    DatadogSite,
)

CLIENT_MODULE = "elementary.monitor.data_monitoring.alerts.integrations.datadog.client"


def _make_response(status_code, json_data=None, headers=None):
    response = mock.Mock(spec=requests.Response)
    response.status_code = status_code
    response.ok = status_code < 400
    response.headers = headers or {}
    response.reason = "mock-reason"
    response.text = ""
    response.json.return_value = json_data if json_data is not None else {}
    return response


def _make_client() -> DatadogApiClient:
    return DatadogApiClient(
        api_key="fake-api-key",
        application_key="fake-app-key",
        site=DatadogSite.US1,
    )


def _make_payload() -> CreateIncidentInput:
    return CreateIncidentInput(
        data=DatadogIncidentData(
            attributes=DatadogIncidentFieldAttributes(
                title="title",
                fields={},
                creation_idempotency_key="key",
            )
        )
    )


class _FakeAlert:
    def __init__(self, summary, meta=None):
        self.id = "alert-1"
        self.alert_class_id = "alert-class-1"
        self.summary = summary
        self.unified_meta = meta or {}
        self.status = "fail"
        self.data = {"id": "alert-1"}


@mock.patch(f"{CLIENT_MODULE}.time.sleep")
@mock.patch(f"{CLIENT_MODULE}.requests.request")
def test_create_incident_retries_on_rate_limit_honoring_retry_after(
    mock_request, mock_sleep
):
    mock_request.side_effect = [
        _make_response(429, headers={"Retry-After": "3"}),
        _make_response(201, {"data": {"id": "incident-1"}}),
    ]

    success, data = _make_client().create_incident(_make_payload())

    assert success
    assert data == {"data": {"id": "incident-1"}}
    assert mock_request.call_count == 2
    mock_sleep.assert_called_once_with(3.0)


@mock.patch(f"{CLIENT_MODULE}.time.sleep")
@mock.patch(f"{CLIENT_MODULE}.requests.request")
def test_create_incident_retries_on_server_error_with_backoff(mock_request, mock_sleep):
    mock_request.side_effect = [
        _make_response(503),
        _make_response(201, {"data": {"id": "incident-1"}}),
    ]

    success, _ = _make_client().create_incident(_make_payload())

    assert success
    assert mock_request.call_count == 2
    mock_sleep.assert_called_once_with(2)


@mock.patch(f"{CLIENT_MODULE}.time.sleep")
@mock.patch(f"{CLIENT_MODULE}.requests.request")
def test_create_incident_gives_up_after_max_retries(mock_request, mock_sleep):
    mock_request.return_value = _make_response(429, {"errors": ["rate limited"]})

    success, data = _make_client().create_incident(_make_payload())

    assert not success
    assert data == {"errors": ["rate limited"]}
    assert mock_request.call_count == MAX_RETRIES + 1
    assert mock_sleep.call_count == MAX_RETRIES


@mock.patch(f"{CLIENT_MODULE}.time.sleep")
@mock.patch(f"{CLIENT_MODULE}.requests.request")
def test_create_incident_does_not_retry_client_errors(mock_request, mock_sleep):
    mock_request.return_value = _make_response(400, {"errors": ["title too long"]})

    success, data = _make_client().create_incident(_make_payload())

    assert not success
    assert data == {"errors": ["title too long"]}
    assert mock_request.call_count == 1
    mock_sleep.assert_not_called()


@mock.patch(f"{CLIENT_MODULE}.time.sleep")
@mock.patch(f"{CLIENT_MODULE}.requests.request")
def test_create_incident_retries_on_connection_error(mock_request, mock_sleep):
    mock_request.side_effect = [
        requests.exceptions.ConnectionError("boom"),
        _make_response(201, {"data": {"id": "incident-1"}}),
    ]

    success, _ = _make_client().create_incident(_make_payload())

    assert success
    assert mock_request.call_count == 2


@mock.patch(f"{CLIENT_MODULE}.time.sleep")
@mock.patch(f"{CLIENT_MODULE}.requests.request")
def test_search_open_incidents_retries_on_rate_limit(mock_request, mock_sleep):
    mock_request.side_effect = [
        _make_response(429, headers={"x-ratelimit-reset": "5"}),
        _make_response(
            200,
            {"data": {"attributes": {"incidents": [{"data": {"id": "incident-9"}}]}}},
        ),
    ]

    incident_id = _make_client().search_open_incidents("edr-12345678")

    assert incident_id == "incident-9"
    assert mock_request.call_count == 2
    mock_sleep.assert_called_once_with(5.0)


def test_incident_title_truncated_to_datadog_limit():
    config = DatadogConfig(api_key="k", application_key="a")
    alert = _FakeAlert(summary="x" * 5000)

    payload = build_incident_payload(config=config, alert=alert)

    title = payload.data.attributes.title
    token_suffix = f" [{get_alert_token(alert.alert_class_id)}]"
    assert len(title) <= MAX_INCIDENT_TITLE_LENGTH
    assert title.endswith(token_suffix)


def test_incident_title_not_truncated_when_short():
    config = DatadogConfig(api_key="k", application_key="a")
    alert = _FakeAlert(summary="short summary")

    payload = build_incident_payload(config=config, alert=alert)

    title = payload.data.attributes.title
    token_suffix = f" [{get_alert_token(alert.alert_class_id)}]"
    assert title == f"[Elementary] Data Quality Alert: short summary{token_suffix}"


def test_incident_title_custom_override_from_meta():
    config = DatadogConfig(api_key="k", application_key="a")
    alert = _FakeAlert(
        summary="x" * 5000,
        meta={"datadog_incident_title": "Orders freshness check failed"},
    )

    payload = build_incident_payload(config=config, alert=alert)

    title = payload.data.attributes.title
    token_suffix = f" [{get_alert_token(alert.alert_class_id)}]"
    assert title == f"Orders freshness check failed{token_suffix}"


def test_truncate_utf8_counts_bytes_not_code_points():
    # Reproduces the Datadog 400: a 📊 (U+1F4CA) is one code point but 4 UTF-8
    # bytes, so a 2048-*character* string is 2051 *bytes*. Naive slicing keeps
    # 2048 chars (still 2051 bytes); _truncate_utf8 must cap the byte length.
    text = "📊" + "x" * 2047
    assert len(text) == 2048
    assert len(text.encode("utf-8")) == 2051

    result = _truncate_utf8(text, 2048)

    assert len(result.encode("utf-8")) <= 2048
    # No partial/mojibake character at the cut point.
    assert result == result.encode("utf-8").decode("utf-8")


def test_truncate_utf8_passthrough_when_within_limit():
    text = "📊 short summary"
    assert _truncate_utf8(text, MAX_INCIDENT_SUMMARY_LENGTH) == text


def test_truncate_utf8_with_ellipsis_stays_within_byte_budget():
    result = _truncate_utf8("x" * 5000, 2048, add_ellipsis=True)
    assert len(result.encode("utf-8")) <= 2048
    assert result.endswith("…")


def test_incident_summary_truncated_to_datadog_byte_limit():
    config = DatadogConfig(api_key="k", application_key="a")
    alert = _FakeAlert(summary="short summary")
    # Long error message drives a description well past 2048 bytes; the
    # generator prefixes it with the 📊 emoji (4 bytes), which is what pushed
    # the character-truncated payload to 2051 bytes in production.
    alert.error_message = "y" * 5000

    payload = build_incident_payload(config=config, alert=alert)

    summary = payload.data.attributes.fields["summary"]["value"]
    assert summary.startswith("📊")
    assert len(summary.encode("utf-8")) <= MAX_INCIDENT_SUMMARY_LENGTH


def test_incident_title_within_byte_limit_with_multibyte_summary():
    config = DatadogConfig(api_key="k", application_key="a")
    alert = _FakeAlert(summary="📊" * 5000)

    payload = build_incident_payload(config=config, alert=alert)

    title = payload.data.attributes.title
    token_suffix = f" [{get_alert_token(alert.alert_class_id)}]"
    assert len(title.encode("utf-8")) <= MAX_INCIDENT_TITLE_LENGTH
    assert title.endswith(token_suffix)


def _make_data_monitoring_alerts(ignore_send_failures: bool) -> DataMonitoringAlerts:
    data_monitoring = object.__new__(DataMonitoringAlerts)
    data_monitoring.success = True
    data_monitoring.ignore_send_failures = ignore_send_failures
    data_monitoring.sent_alert_count = 0
    data_monitoring.execution_properties = {}
    data_monitoring.alerts_api = mock.Mock()
    return data_monitoring


def test_send_failure_fails_run_by_default():
    data_monitoring = _make_data_monitoring_alerts(ignore_send_failures=False)
    with mock.patch.object(DataMonitoringAlerts, "_send_alert", return_value=False):
        data_monitoring._send_alerts([_FakeAlert(summary="s")])

    assert data_monitoring.success is False
    assert data_monitoring.sent_alert_count == 0


def test_send_failure_ignored_with_flag():
    data_monitoring = _make_data_monitoring_alerts(ignore_send_failures=True)
    with mock.patch.object(DataMonitoringAlerts, "_send_alert", return_value=False):
        data_monitoring._send_alerts([_FakeAlert(summary="s")])

    assert data_monitoring.success is True
    assert data_monitoring.sent_alert_count == 0
    # Failed alerts must not be marked as sent, so they retry next run
    data_monitoring.alerts_api.update_sent_alerts.assert_called_once_with(alert_ids=[])


def _make_test_alert(alert_id, alert_class_id, status="fail", model_meta=None):
    return TestAlertModel(
        id=alert_id,
        test_unique_id=f"test.proj.{alert_class_id}",
        elementary_unique_id=f"test.proj.{alert_class_id}.elementary",
        test_name="not_null",
        severity="ERROR",
        test_type="dbt_test",
        test_sub_type="generic",
        test_short_name="not_null",
        alert_class_id=alert_class_id,
        table_name="orders",
        model_unique_id="model.proj.orders",
        database_name="db",
        schema_name="analytics",
        status=status,
        model_meta=model_meta,
    )


def test_grouped_by_table_alerts_build_incident_payload():
    config = DatadogConfig(api_key="k", application_key="a")
    model_meta = {"datadog_notification_handle": "team-orders"}
    group = GroupedByTableAlerts(
        alerts=[
            _make_test_alert("alert-1", "class-a", "fail", model_meta),
            _make_test_alert("alert-2", "class-b", "error", model_meta),
        ]
    )

    attributes = build_incident_payload(config=config, alert=group).data.attributes

    token = get_alert_token(get_alert_class_id(group))
    assert attributes.title == (
        f"[Elementary] Multiple Issues: orders: 2 issues detected [{token}]"
    )
    assert attributes.fields["severity"]["value"] == "SEV-1"  # group status "error"
    assert attributes.creation_idempotency_key.startswith("elementary-group-")
    assert [h.handle for h in attributes.notification_handles] == ["@team-orders"]
    summary = attributes.fields["summary"]["value"]
    assert "**Alerts** (2):" in summary
    for member in group.alerts:
        assert f"- {member.summary} ({member.status})" in summary


def test_alerts_group_identity_follows_its_alert_classes():
    first_run = AlertsGroup(
        alerts=[
            _make_test_alert("alert-1", "class-a"),
            _make_test_alert("alert-2", "class-b"),
        ]
    )
    next_run_same_failures = AlertsGroup(
        alerts=[
            _make_test_alert("alert-4", "class-b"),
            _make_test_alert("alert-3", "class-a"),
        ]
    )
    next_run_new_failure = AlertsGroup(
        alerts=[
            _make_test_alert("alert-5", "class-a"),
            _make_test_alert("alert-6", "class-c"),
        ]
    )

    # Same failing alerts -> same dedup token, so the open incident is reused
    assert get_alert_class_id(first_run) == get_alert_class_id(next_run_same_failures)
    # A new failure -> new token, so it is not swallowed by the open incident
    assert get_alert_class_id(first_run) != get_alert_class_id(next_run_new_failure)

    config = DatadogConfig(api_key="k", application_key="a")
    first_key = build_incident_payload(config=config, alert=first_run)
    next_key = build_incident_payload(config=config, alert=next_run_same_failures)
    # The idempotency key is per run (alert ids), like for single alerts
    assert (
        first_key.data.attributes.creation_idempotency_key
        != next_key.data.attributes.creation_idempotency_key
    )


def test_alerts_group_of_failed_tests_uses_fail_severity():
    group = AlertsGroup(alerts=[_make_test_alert("alert-1", "class-a", "fail")])
    assert group.status == "failure"

    default_config = DatadogConfig(api_key="k", application_key="a")
    payload = build_incident_payload(config=default_config, alert=group)
    assert payload.data.attributes.fields["severity"]["value"] == "SEV-2"

    mapped_config = DatadogConfig(
        api_key="k", application_key="a", severity_mapping={"fail": "SEV-4"}
    )
    payload = build_incident_payload(config=mapped_config, alert=group)
    assert payload.data.attributes.fields["severity"]["value"] == "SEV-4"


@mock.patch(f"{CLIENT_MODULE}.requests.request")
def test_send_alert_creates_incident_for_alerts_group(mock_request, tmp_path):
    integration = DatadogIntegration(
        config=Config(
            config_dir=str(tmp_path),
            datadog_api_key="k",
            datadog_application_key="a",
        )
    )
    group = AlertsGroup(
        alerts=[
            _make_test_alert("alert-1", "class-a"),
            _make_test_alert("alert-2", "class-b"),
        ]
    )
    mock_request.side_effect = [
        _make_response(200, {"data": {"attributes": {"incidents": []}}}),
        _make_response(201, {"data": {"id": "incident-1"}}),
    ]

    assert integration.send_alert(group) is True

    assert [c.kwargs["method"] for c in mock_request.call_args_list] == ["GET", "POST"]
    title = mock_request.call_args_list[1].kwargs["json"]["data"]["attributes"]["title"]
    assert title.endswith(f"[{get_alert_token(get_alert_class_id(group))}]")


@mock.patch(f"{CLIENT_MODULE}.requests.request")
def test_send_test_message_creates_incident(mock_request, tmp_path):
    integration = DatadogIntegration(
        config=Config(
            config_dir=str(tmp_path),
            datadog_api_key="k",
            datadog_application_key="a",
        )
    )
    mock_request.side_effect = [
        _make_response(200, {"data": {"attributes": {"incidents": []}}}),
        _make_response(201, {"data": {"id": "incident-1"}}),
    ]

    assert integration.send_test_message() is True

    attributes = mock_request.call_args_list[1].kwargs["json"]["data"]["attributes"]
    assert attributes["title"] == (
        '[Elementary] Integration Test: "datadog_integration_test" test failed on '
        f"elementary.test_table [{get_alert_token('test-elementary-datadog')}]"
    )
    assert attributes["fields"]["severity"]["value"] == "SEV-3"  # status "warn"
    assert (
        "This is a test message to verify the integration is working correctly."
        in attributes["fields"]["summary"]["value"]
    )
