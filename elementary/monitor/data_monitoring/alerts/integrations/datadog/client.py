import logging
from typing import Any, Dict, Optional, Tuple, Union

import requests

from elementary.monitor.alerts.alerts_groups import GroupedByTableAlerts
from elementary.monitor.alerts.alerts_groups.base_alerts_group import BaseAlertsGroup
from elementary.monitor.alerts.model_alert import ModelAlertModel
from elementary.monitor.alerts.source_freshness_alert import SourceFreshnessAlertModel
from elementary.monitor.alerts.test_alert import TestAlertModel
from elementary.monitor.data_monitoring.alerts.integrations.datadog.types import (
    CreateIncidentInput,
    DatadogConfig,
    DatadogIncidentData,
    DatadogIncidentFieldAttributes,
    DatadogIncidentRelationships,
    DatadogNotificationHandle,
    DatadogSite,
)
from elementary.utils.log import get_logger

logger = get_logger(__name__)


class DatadogApiClient:
    def __init__(self, api_key: str, application_key: str, site: DatadogSite):
        self.headers = {
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": application_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.base_url = f"https://api.{site.value}"

    def create_incident(self, payload: CreateIncidentInput) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Create a Datadog incident and return (success, response_data)"""
        url = f"{self.base_url}/api/v2/incidents"
        
        try:
            response = requests.post(
                url=url,
                headers=self.headers,
                json=payload.dict(exclude_none=True),
                timeout=60
            )
            
            if response.ok:
                logger.info(f"Successfully created Datadog incident")
                return True, response.json()
            else:
                try:
                    error_json = response.json()
                    logger.error(
                        f"Failed to create Datadog incident: {response.status_code} {response.reason}\n"
                        f"Error details: {error_json}"
                    )
                    return False, error_json
                except ValueError:
                    logger.error(
                        f"Failed to create Datadog incident: {response.status_code} {response.reason}\n"
                        f"Response: {response.text}"
                    )
                    return False, None
                    
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed when creating Datadog incident: {e}")
            return False, None


def build_incident_payload(
    config: DatadogConfig,
    alert: Union[
        TestAlertModel,
        ModelAlertModel,
        SourceFreshnessAlertModel,
        GroupedByTableAlerts,
        BaseAlertsGroup,
    ],
) -> CreateIncidentInput:
    """Build a Datadog incident payload from an Elementary alert"""
    
    # Generate title
    title = _generate_incident_title(alert)
    
    # Generate description 
    description = _generate_incident_description(alert)
    
    # Generate idempotency key
    idempotency_key = f"elementary-{getattr(alert, 'alert_class_id', alert.id)}"
    
    # Determine severity based on alert status and tags
    alert_tags = getattr(alert, 'tags', None) or []
    severity = config.get_severity_for_status(
        getattr(alert, 'status', 'unknown'), 
        alert_tags
    )
    
    # Build notification handles
    notification_handles = None
    if config.notification_handles:
        notification_handles = [
            DatadogNotificationHandle(handle=handle) 
            for handle in config.notification_handles
        ]

    # Build commander relationship
    relationships = None
    if config.commander_user_id:
        relationships = DatadogIncidentRelationships(
            commander_user={"data": {"type": "users", "id": config.commander_user_id}}
        )

    # Truncate customer_impact_scope to 1024 characters (Datadog API limit)
    customer_impact_scope = title[:1024] if config.customer_impacted else None

    # Build fields dictionary
    fields = {
        "severity": {"type": "dropdown", "value": severity},
        "state": {"type": "dropdown", "value": "active"},
        "summary": {"type": "textbox", "value": description[:2048]},  # Datadog limit
    }

    attributes = DatadogIncidentFieldAttributes(
        title=title,
        customer_impact_scope=customer_impact_scope,
        customer_impacted=config.customer_impacted,
        notification_handles=notification_handles,
        fields=fields,
        creation_idempotency_key=idempotency_key,
    )

    return CreateIncidentInput(
        data=DatadogIncidentData(
            type="incidents",
            attributes=attributes,
            relationships=relationships,
        )
    )


def _generate_incident_title(
    alert: Union[
        TestAlertModel,
        ModelAlertModel,
        SourceFreshnessAlertModel,
        GroupedByTableAlerts,
        BaseAlertsGroup,
    ]
) -> str:
    """Generate a descriptive incident title from an alert"""
    if isinstance(alert, TestAlertModel):
        if alert.is_elementary_test:
            return f"[Elementary] {alert.test_type.replace('_', ' ').title()}: {alert.summary}"
        else:
            return f"[Elementary] Test Failure: {alert.summary}"
    elif isinstance(alert, ModelAlertModel):
        alert_type = "Snapshot Error" if alert.materialization == "snapshot" else "Model Error"
        return f"[Elementary] {alert_type}: {alert.summary}"
    elif isinstance(alert, SourceFreshnessAlertModel):
        return f"[Elementary] Source Freshness: {alert.summary}"
    elif isinstance(alert, (GroupedByTableAlerts, BaseAlertsGroup)):
        return f"[Elementary] Multiple Issues: {alert.summary}"
    else:
        return f"[Elementary] Data Quality Alert: {getattr(alert, 'summary', 'Unknown issue')}"


def _generate_incident_description(
    alert: Union[
        TestAlertModel,
        ModelAlertModel,
        SourceFreshnessAlertModel,
        GroupedByTableAlerts,
        BaseAlertsGroup,
    ]
) -> str:
    """Generate a comprehensive incident description from an alert"""
    
    lines = ["📊 **Elementary Data Quality Alert**", ""]
    
    # Basic information
    if hasattr(alert, 'table_full_name') and alert.table_full_name:
        lines.append(f"**Table**: {alert.table_full_name}")
    
    if hasattr(alert, 'test_name') and alert.test_name:
        lines.append(f"**Test**: {alert.test_name}")
    elif hasattr(alert, 'concise_name') and alert.concise_name:
        lines.append(f"**Test**: {alert.concise_name}")
    
    if hasattr(alert, 'status') and alert.status:
        lines.append(f"**Status**: {alert.status}")
    
    if hasattr(alert, 'detected_at_str') and alert.detected_at_str:
        lines.append(f"**Detected**: {alert.detected_at_str}")
    
    lines.append("")
    
    # Error details
    error_msg = None
    if hasattr(alert, 'error_message') and alert.error_message:
        error_msg = alert.error_message
    elif hasattr(alert, 'message') and alert.message:
        error_msg = alert.message
    elif hasattr(alert, 'result_description') and alert.result_description:
        error_msg = alert.result_description
    
    if error_msg:
        lines.extend([
            "**Error Details**:",
            f"```",
            error_msg.strip(),
            "```",
            ""
        ])
    
    # Test results sample
    if hasattr(alert, 'test_rows_sample') and alert.test_rows_sample:
        import json
        sample_str = str(alert.test_rows_sample)
        if isinstance(alert.test_rows_sample, list):
            sample_str = json.dumps(alert.test_rows_sample, indent=2)
        lines.extend([
            "**Test Results Sample**:",
            "```",
            sample_str,
            "```",
            ""
        ])
    
    # Metadata
    metadata_lines = []
    if hasattr(alert, 'owners') and alert.owners:
        owners_str = ', '.join(str(owner) for owner in alert.owners) if isinstance(alert.owners, list) else str(alert.owners)
        metadata_lines.append(f"**Owners**: {owners_str}")
    
    if hasattr(alert, 'tags') and alert.tags:
        tags_str = ', '.join(str(tag) for tag in alert.tags) if isinstance(alert.tags, list) else str(alert.tags)
        metadata_lines.append(f"**Tags**: {tags_str}")
    
    if hasattr(alert, 'subscribers') and alert.subscribers:
        subscribers_str = ', '.join(str(sub) for sub in alert.subscribers) if isinstance(alert.subscribers, list) else str(alert.subscribers)
        metadata_lines.append(f"**Subscribers**: {subscribers_str}")
    
    if hasattr(alert, 'column_name') and alert.column_name:
        metadata_lines.append(f"**Column**: {alert.column_name}")
    
    if metadata_lines:
        lines.extend(metadata_lines)
        lines.append("")
    
    # Report link
    if hasattr(alert, 'get_report_link') and callable(alert.get_report_link):
        report_link = alert.get_report_link()
        if report_link:
            lines.append(f"🔗 **[View Details]({report_link.url})**")
    
    return "\n".join(lines)