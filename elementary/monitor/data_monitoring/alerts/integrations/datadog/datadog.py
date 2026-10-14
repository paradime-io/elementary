from datetime import datetime, timezone
from typing import Optional, Union

from elementary.config.config import Config
from elementary.monitor.alerts.alert import AlertModel
from elementary.monitor.alerts.alerts_groups import GroupedByTableAlerts
from elementary.monitor.alerts.alerts_groups.base_alerts_group import BaseAlertsGroup
from elementary.monitor.alerts.model_alert import ModelAlertModel
from elementary.monitor.alerts.source_freshness_alert import SourceFreshnessAlertModel
from elementary.monitor.alerts.test_alert import TestAlertModel
from elementary.monitor.data_monitoring.alerts.integrations.base_integration import (
    BaseIntegration,
)
from elementary.monitor.data_monitoring.alerts.integrations.datadog.client import (
    DatadogApiClient,
    build_incident_payload,
    get_alert_class_id,
    get_alert_log_id,
    get_alert_token,
)
from elementary.monitor.data_monitoring.alerts.integrations.datadog.types import (
    DatadogConfig,
    DatadogSite,
)
from elementary.tracking.tracking_interface import Tracking
from elementary.utils.log import get_logger

logger = get_logger(__name__)


class DatadogIntegration(BaseIntegration):
    def __init__(
        self,
        config: Config,
        tracking: Optional[Tracking] = None,
        *args,
        **kwargs,
    ) -> None:
        self.config = config
        self.tracking = tracking
        self.datadog_config = self._build_datadog_config()
        super().__init__()

        # Enforce typing
        self.client: DatadogApiClient

    def _initial_client(self, *args, **kwargs) -> DatadogApiClient:
        if not self.config.datadog_api_key or not self.config.datadog_application_key:
            raise Exception("Datadog API key and application key are required")

        return DatadogApiClient(
            api_key=self.config.datadog_api_key,
            application_key=self.config.datadog_application_key,
            site=DatadogSite(self.config.datadog_site)
            if self.config.datadog_site
            else DatadogSite.US1,
        )

    def _build_datadog_config(self) -> DatadogConfig:
        """Build Datadog configuration from Elementary config"""
        from elementary.monitor.data_monitoring.alerts.integrations.datadog.types import (
            DatadogIncidentSeverity,
        )

        return DatadogConfig(
            api_key=self.config.datadog_api_key or "",
            application_key=self.config.datadog_application_key or "",
            site=DatadogSite(self.config.datadog_site)
            if self.config.datadog_site
            else DatadogSite.US1,
            default_severity=getattr(self.config, "datadog_default_severity", None)
            or DatadogIncidentSeverity.SEV3,
            severity_mapping=getattr(self.config, "datadog_severity_mapping", None),
            customer_impacted=getattr(self.config, "datadog_customer_impacted", None)
            or False,
            commander_user_id=getattr(self.config, "datadog_commander_user_id", None),
            notification_handles=getattr(
                self.config, "datadog_notification_handles", None
            ),
            tag_severity_rules=getattr(self.config, "datadog_tag_severity_rules", None),
        )

    def send_alert(
        self,
        alert: Union[AlertModel, GroupedByTableAlerts, BaseAlertsGroup],
        *args,
        **kwargs,
    ) -> bool:
        """Send an alert as a Datadog incident, skipping if an open incident already exists."""
        alert_log_id = get_alert_log_id(alert)
        logger.debug(f"Creating Datadog incident for alert: {alert_log_id}")

        try:
            token = get_alert_token(get_alert_class_id(alert))

            open_incident_id = self.client.search_open_incidents(token)
            if open_incident_id:
                logger.info(
                    f"Datadog: open incident {open_incident_id} already exists for "
                    f"{alert_log_id} ({token}) — skipping creation."
                )
                return True

            payload = build_incident_payload(config=self.datadog_config, alert=alert)
            success, response_data = self.client.create_incident(payload)

            if success:
                incident_id = (
                    response_data.get("data", {}).get("id")
                    if response_data
                    else "unknown"
                )
                logger.info(
                    f"Successfully created Datadog incident {incident_id} for alert {alert_log_id}"
                )
                return True
            else:
                logger.error(
                    f"Failed to create Datadog incident for alert {alert_log_id}"
                )
                return False

        except Exception as e:
            logger.error(
                f"Error creating Datadog incident for alert {alert_log_id}: {e}"
            )
            return False

    def send_test_message(self, *args, **kwargs) -> bool:
        """Send a test incident to verify Datadog integration"""
        test_alert = TestAlertModel(
            id="test-alert-123",
            test_unique_id="test.elementary.datadog_integration_test",
            elementary_unique_id="test.elementary.datadog_integration_test",
            test_name="datadog_integration_test",
            severity="WARN",
            test_type="integration_test",
            test_sub_type="generic",
            test_short_name="datadog_integration_test",
            alert_class_id="test-elementary-datadog",
            # TestAlertModel capitalizes this text, so it avoids proper nouns
            test_results_description="This is a test message to verify the integration is working correctly.",
            schema_name="elementary",
            table_name="test_table",
            detected_at=datetime.now(tz=timezone.utc),
            status="warn",
            tags=["test", "integration"],
            owners=["elementary-team"],
        )
        return self.send_alert(test_alert)

    # Abstract method implementations (required by BaseIntegration)
    def _get_dbt_test_template(self, alert: TestAlertModel, *args, **kwargs):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_elementary_test_template(self, alert: TestAlertModel, *args, **kwargs):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_model_template(self, alert: ModelAlertModel, *args, **kwargs):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_snapshot_template(self, alert: ModelAlertModel, *args, **kwargs):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_source_freshness_template(
        self, alert: SourceFreshnessAlertModel, *args, **kwargs
    ):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_group_by_table_template(
        self, alert: GroupedByTableAlerts, *args, **kwargs
    ):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_alerts_group_template(self, alert: BaseAlertsGroup, *args, **kwargs):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_fallback_template(
        self,
        alert: Union[AlertModel, GroupedByTableAlerts],
        *args,
        **kwargs,
    ):
        # Not used for Datadog integration - incidents are created directly
        return None
