import json
from typing import Any, Dict, Union

from elementary.config.config import Config
from elementary.monitor.alerts.alerts_groups import AlertsGroup, GroupedByTableAlerts
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
        tracking: Tracking = None,
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
            site=DatadogSite(self.config.datadog_site) if self.config.datadog_site else DatadogSite.US1,
        )

    def _build_datadog_config(self) -> DatadogConfig:
        """Build Datadog configuration from Elementary config"""
        from elementary.monitor.data_monitoring.alerts.integrations.datadog.types import DatadogIncidentSeverity
        
        return DatadogConfig(
            api_key=self.config.datadog_api_key or "",
            application_key=self.config.datadog_application_key or "",
            site=DatadogSite(self.config.datadog_site) if self.config.datadog_site else DatadogSite.US1,
            default_severity=getattr(self.config, 'datadog_default_severity', None) or DatadogIncidentSeverity.SEV3,
            severity_mapping=getattr(self.config, 'datadog_severity_mapping', None),
            customer_impacted=getattr(self.config, 'datadog_customer_impacted', None) or False,
            commander_user_id=getattr(self.config, 'datadog_commander_user_id', None),
            notification_handles=getattr(self.config, 'datadog_notification_handles', None),
            tag_severity_rules=getattr(self.config, 'datadog_tag_severity_rules', None),
        )

    def send_alert(
        self,
        alert: Union[
            TestAlertModel,
            ModelAlertModel,
            SourceFreshnessAlertModel,
            GroupedByTableAlerts,
            BaseAlertsGroup,
        ],
        *args,
        **kwargs,
    ) -> bool:
        """Send an alert as a Datadog incident"""
        logger.debug(f"Creating Datadog incident for alert: {alert.id}")
        
        try:
            payload = build_incident_payload(config=self.datadog_config, alert=alert)
            success, response_data = self.client.create_incident(payload)
            
            if success:
                incident_id = response_data.get("data", {}).get("id") if response_data else "unknown"
                logger.info(f"Successfully created Datadog incident {incident_id} for alert {alert.id}")
                return True
            else:
                logger.error(f"Failed to create Datadog incident for alert {alert.id}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating Datadog incident for alert {alert.id}: {e}")
            return False

    def send_test_message(self, *args, **kwargs) -> bool:
        """Send a test incident to verify Datadog integration"""
        from elementary.monitor.alerts.test_alert import TestAlertModel
        from datetime import datetime, timezone
        
        # Create a mock test alert for testing
        test_alert_data = {
            "id": "test-alert-123",
            "alert_class_id": "test-elementary-datadog",
            "test_name": "datadog_integration_test",
            "test_type": "integration_test",
            "status": "warn",
            "summary": "Datadog integration test message",
            "table_full_name": "elementary.test_table",
            "detected_at": datetime.now(tz=timezone.utc),
            "error_message": "This is a test message to verify Datadog integration is working correctly.",
            "tags": ["test", "integration"],
            "owners": ["elementary-team"],
        }
        
        # This is a simplified mock - in practice you'd create a proper TestAlertModel
        # For now, we'll create a basic object with the required attributes
        class MockTestAlert:
            def __init__(self, data):
                for key, value in data.items():
                    setattr(self, key, value)
                self.detected_at_str = self.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                self.is_elementary_test = True
            
            def get_report_link(self):
                return None
                
        mock_alert = MockTestAlert(test_alert_data)
        return self.send_alert(mock_alert)

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

    def _get_source_freshness_template(self, alert: SourceFreshnessAlertModel, *args, **kwargs):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_group_by_table_template(self, alert: GroupedByTableAlerts, *args, **kwargs):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_alerts_group_template(self, alert: BaseAlertsGroup, *args, **kwargs):
        # Not used for Datadog integration - incidents are created directly
        return None

    def _get_fallback_template(
        self,
        alert: Union[
            TestAlertModel,
            ModelAlertModel,
            SourceFreshnessAlertModel,
            GroupedByTableAlerts,
        ],
        *args,
        **kwargs,
    ):
        # Not used for Datadog integration - incidents are created directly
        return None