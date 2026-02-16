from enum import Enum
from typing import Any, Dict, List, Optional

from elementary.utils.pydantic_shim import BaseModel, Field


class DatadogSite(Enum):
    US1 = "datadoghq.com"
    US3 = "us3.datadoghq.com"
    US5 = "us5.datadoghq.com"
    EU1 = "datadoghq.eu"
    AP1 = "ap1.datadoghq.com"
    GOV = "ddog-gov.com"


class DatadogIncidentSeverity(Enum):
    SEV1 = "SEV-1"
    SEV2 = "SEV-2"
    SEV3 = "SEV-3"
    SEV4 = "SEV-4"
    SEV5 = "SEV-5"


class DatadogIncidentState(Enum):
    ACTIVE = "active"
    STABLE = "stable"
    RESOLVED = "resolved"


class DatadogNotificationHandle(BaseModel):
    handle: str


class DatadogUser(BaseModel):
    id: str
    name: str
    email: str
    handle: str
    icon: Optional[str] = Field(default=None)


class DatadogTeam(BaseModel):
    id: str
    name: str
    handle: str


class DatadogIncidentRelationships(BaseModel):
    commander_user: Optional[Dict[str, Any]] = Field(default=None)


class DatadogIncidentFieldAttributes(BaseModel):
    title: str
    customer_impact_scope: Optional[str] = Field(default=None)
    customer_impacted: bool = Field(default=False)
    notification_handles: Optional[List[DatadogNotificationHandle]] = Field(default=None)
    fields: Dict[str, Any]
    creation_idempotency_key: str


class DatadogIncidentData(BaseModel):
    type: str = Field(default="incidents")
    attributes: DatadogIncidentFieldAttributes
    relationships: Optional[DatadogIncidentRelationships] = Field(default=None)


class DatadogBase(BaseModel):
    pass


class CreateIncidentInput(DatadogBase):
    data: DatadogIncidentData


class DatadogConfig(BaseModel):
    api_key: str
    application_key: str
    site: DatadogSite = Field(default=DatadogSite.US1)
    default_severity: DatadogIncidentSeverity = Field(default=DatadogIncidentSeverity.SEV3)
    severity_mapping: Optional[Dict[str, str]] = Field(default=None)
    customer_impacted: bool = Field(default=False)
    commander_user_id: Optional[str] = Field(default=None)
    notification_handles: Optional[List[str]] = Field(default=None)
    tag_severity_rules: Optional[List[Dict[str, Any]]] = Field(default=None)

    def get_severity_for_status(self, status: str, tags: Optional[List[str]] = None) -> str:
        # Check tag-based severity rules first
        if self.tag_severity_rules and tags:
            for rule in self.tag_severity_rules:
                rule_tags = rule.get("tags", [])
                if any(tag in tags for tag in rule_tags):
                    return rule.get("severity", self.default_severity.value)
        
        # Use status-based mapping
        if self.severity_mapping:
            return self.severity_mapping.get(status, self.default_severity.value)
        
        # Default mapping
        default_mapping = {
            "error": DatadogIncidentSeverity.SEV1.value,
            "fail": DatadogIncidentSeverity.SEV2.value,
            "warn": DatadogIncidentSeverity.SEV3.value,
        }
        return default_mapping.get(status, self.default_severity.value)