"""Pacote principal do motor de segurança (security-engine) do cyber-security-checker."""

from security_engine.core.contracts import (
    AssetType,
    BaseSecurityModule,
    CheckEvaluationResult,
    CheckStatus,
    Confidence,
    EnvironmentType,
    ImpactLevel,
    ModuleExecutionResult,
    ModuleMetadata,
    NormalizedFinding,
    RemediationGuidance,
    SanitizedEvidence,
    ScanProfileDescriptor,
    ScanProfileType,
    Severity,
)
from security_engine.core.evidence import EvidenceManager
from security_engine.core.registry import PluginRegistry, default_registry
from security_engine.core.remediation import RemediationEngine
from security_engine.core.risk import RiskEngine
from security_engine.policies.execution_policy import (
    ScanExecutionPolicy,
    get_scan_profiles,
)
from security_engine.policies.scope_validator import (
    ScopePolicyValidator,
    ScopeViolationError,
)

__version__ = "0.1.0"

__all__ = [
    "AssetType",
    "BaseSecurityModule",
    "CheckEvaluationResult",
    "CheckStatus",
    "Confidence",
    "EnvironmentType",
    "EvidenceManager",
    "ImpactLevel",
    "ModuleExecutionResult",
    "ModuleMetadata",
    "NormalizedFinding",
    "PluginRegistry",
    "RemediationEngine",
    "RemediationGuidance",
    "RiskEngine",
    "SanitizedEvidence",
    "ScanExecutionPolicy",
    "ScanProfileDescriptor",
    "ScanProfileType",
    "ScopePolicyValidator",
    "ScopeViolationError",
    "Severity",
    "default_registry",
    "get_scan_profiles",
]
