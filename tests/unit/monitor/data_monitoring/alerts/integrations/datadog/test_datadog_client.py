from unittest import mock

import requests

from elementary.monitor.data_monitoring.alerts.data_monitoring_alerts import (
    DataMonitoringAlerts,
)
from elementary.monitor.data_monitoring.alerts.integrations.datadog.client import (
    MAX_INCIDENT_TITLE_LENGTH,
    MAX_RETRIES,
    DatadogApiClient,
    build_incident_payload,
    get_alert_token,
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
            {
                "data": {
                    "attributes": {"incidents": [{"data": {"id": "incident-9"}}]}
                }
            },
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
