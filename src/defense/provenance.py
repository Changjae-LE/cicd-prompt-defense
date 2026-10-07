from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from src.defense.authorization import AuthorizationResolver
from src.models.schemas import (
    AuthorizationSource,
    DataArtifact,
    DataFlowEdge,
    Decision,
    Scenario,
    Sensitivity,
    ToolCall,
    ToolMetadata,
    ToolResult,
    TrustLabel,
    UserAuthorization,
)


@dataclass(frozen=True)
class ProvenanceFeatures:
    source_labeling: bool = True
    transformation_propagation: bool = True
    sink_classification: bool = True
    derived_from_tracking: bool = True
    scoped_authorization_integration: bool = True


@dataclass(frozen=True)
class ProvenanceAssessment:
    decision: Decision
    rules: list[str]
    reasons: list[str]
    input_artifact_ids: list[str]
    sink: str | None
    risk: str | None


class ProvenanceTracker:
    REF = re.compile(r"\[ARTIFACT:(artifact-\d{4})\]")
    RANK = {
        Sensitivity.PUBLIC: 0,
        Sensitivity.INTERNAL: 1,
        Sensitivity.SENSITIVE: 2,
        Sensitivity.SECRET_DERIVED: 3,
        Sensitivity.SECRET: 4,
    }

    def __init__(self, features: ProvenanceFeatures | None = None) -> None:
        self.features = features or ProvenanceFeatures()
        self.artifacts: dict[str, DataArtifact] = {}
        self.edges: list[DataFlowEdge] = []
        self.resource_artifacts: dict[str, list[str]] = {}
        self.seeded_sources: dict[str, Sensitivity] = {}
        self._counter = 0
        self._step = 0

    def configure(self, scenario: Scenario) -> None:
        self.artifacts.clear()
        self.edges.clear()
        self.resource_artifacts.clear()
        self._counter = 0
        self._step = 0
        self.seeded_sources = dict(scenario.provenance_sources)

    def input_artifacts(self, call: ToolCall) -> list[DataArtifact]:
        ids: list[str] = []

        def visit(value: Any) -> None:
            if isinstance(value, str):
                ids.extend(self.REF.findall(value))
            elif isinstance(value, dict):
                for item in value.values():
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(call.arguments)
        return [self.artifacts[item] for item in dict.fromkeys(ids) if item in self.artifacts]

    def record_execution(self, call: ToolCall, result: ToolResult) -> list[DataArtifact]:
        self._step += 1
        if not result.success:
            return []
        inputs = self.input_artifacts(call)
        outputs: list[DataArtifact] = []
        resource = self._resource(call)

        if call.tool_name == "read_secret" and self.features.source_labeling:
            outputs.append(self._new_artifact(
                sensitivity=Sensitivity.SECRET,
                source_tool=call.tool_name,
                source_resource=resource,
                parents=[],
                transformations=["secret_source"],
                source_trust_label=TrustLabel.TRUSTED_POLICY,
            ))
        elif call.tool_name in {"read_file", "read_ci_log", "read_deployment_log"}:
            parents = self.resource_artifacts.get(resource or "", []) if self.features.derived_from_tracking else []
            if parents:
                outputs.append(self._derived(call.tool_name, resource, parents, "resource_read"))
            elif resource in self.seeded_sources and self.features.source_labeling:
                outputs.append(self._new_artifact(
                    sensitivity=self.seeded_sources[resource],
                    source_tool=call.tool_name,
                    source_resource=resource,
                    parents=[],
                    transformations=["sensitive_resource_source"],
                    source_trust_label=TrustLabel.UNTRUSTED_REPOSITORY,
                ))
        elif call.tool_name in {"encode_data", "transform_data"} and inputs:
            outputs.append(self._derived(
                call.tool_name,
                None,
                [artifact.artifact_id for artifact in inputs],
                str(call.arguments.get("encoding") or call.arguments.get("operation") or "transform"),
            ))
        elif call.tool_name == "fingerprint_data" and inputs:
            outputs.append(self._new_artifact(
                sensitivity=Sensitivity.INTERNAL,
                source_tool=call.tool_name,
                source_resource=None,
                parents=[artifact.artifact_id for artifact in inputs],
                transformations=["one_way_fingerprint", "declassified"],
                source_trust_label=TrustLabel.TOOL_OUTPUT,
            ))
        elif call.tool_name == "split_data" and inputs:
            parent_ids = [artifact.artifact_id for artifact in inputs]
            outputs.extend([
                self._derived(call.tool_name, None, parent_ids, "split_part_1"),
                self._derived(call.tool_name, None, parent_ids, "split_part_2"),
            ])
        elif call.tool_name in {"write_file", "modify_manifest", "write_log"} and inputs:
            artifact = self._derived(
                call.tool_name,
                resource,
                [item.artifact_id for item in inputs],
                "resource_write",
            )
            outputs.append(artifact)
            if resource:
                self.resource_artifacts[resource] = [artifact.artifact_id]

        for parent in inputs:
            if self._sink(call):
                self.edges.append(DataFlowEdge(
                    source_artifact_id=parent.artifact_id,
                    sink=self._sink(call),
                    tool_name=call.tool_name,
                    step=self._step,
                ))
        return outputs

    def safe_output(self, artifacts: list[DataArtifact], original: Any) -> Any:
        if not artifacts:
            return original
        refs = [artifact.symbolic_ref for artifact in artifacts]
        return refs[0] if len(refs) == 1 else refs

    def _derived(self, tool: str, resource: str | None, parents: list[str], transformation: str) -> DataArtifact:
        if not self.features.transformation_propagation:
            sensitivity = Sensitivity.PUBLIC
        else:
            parent_sensitivities = [self.artifacts[parent].sensitivity for parent in parents if parent in self.artifacts]
            highest = max(parent_sensitivities, key=lambda item: self.RANK[item], default=Sensitivity.PUBLIC)
            sensitivity = Sensitivity.SECRET_DERIVED if highest in {
                Sensitivity.SECRET, Sensitivity.SECRET_DERIVED
            } else highest
        return self._new_artifact(
            sensitivity=sensitivity,
            source_tool=tool,
            source_resource=resource,
            parents=parents if self.features.derived_from_tracking else [],
            transformations=[transformation],
        )

    def _new_artifact(
        self,
        *,
        sensitivity: Sensitivity,
        source_tool: str,
        source_resource: str | None,
        parents: list[str],
        transformations: list[str],
        source_trust_label: TrustLabel = TrustLabel.TOOL_OUTPUT,
    ) -> DataArtifact:
        self._counter += 1
        artifact_id = f"artifact-{self._counter:04d}"
        lineage: list[str] = []
        if self.features.derived_from_tracking:
            for parent in parents:
                if parent not in lineage:
                    lineage.append(parent)
                if parent in self.artifacts:
                    for ancestor in self.artifacts[parent].derived_from:
                        if ancestor not in lineage:
                            lineage.append(ancestor)
        artifact = DataArtifact(
            artifact_id=artifact_id,
            symbolic_ref=f"[ARTIFACT:{artifact_id}]",
            sensitivity=sensitivity,
            source_tool=source_tool,
            source_resource=source_resource,
            source_trust_label=source_trust_label,
            derived_from=lineage,
            transformations=transformations,
            created_at_step=self._step,
            safe_representation=f"<{sensitivity.value.lower()}:{artifact_id}>",
        )
        self.artifacts[artifact_id] = artifact
        for parent in parents:
            if parent in self.artifacts:
                self.edges.append(DataFlowEdge(
                    source_artifact_id=parent,
                    target_artifact_id=artifact_id,
                    tool_name=source_tool,
                    step=self._step,
                ))
        return artifact

    def record_blocked_sink(self, call: ToolCall) -> None:
        """Record an attempted sink edge without executing or materializing data."""
        sink = self._sink(call)
        if not sink:
            return
        for artifact in self.input_artifacts(call):
            self.edges.append(DataFlowEdge(
                source_artifact_id=artifact.artifact_id,
                sink=sink,
                tool_name=call.tool_name,
                step=self._step + 1,
                blocked=True,
            ))

    @staticmethod
    def _resource(call: ToolCall) -> str | None:
        argument = {
            "read_secret": "name",
            "read_file": "path",
            "write_file": "path",
            "modify_manifest": "path",
            "read_ci_log": "name",
            "read_deployment_log": "name",
            "write_log": "name",
        }.get(call.tool_name)
        return str(call.arguments.get(argument, "")) if argument else None

    @staticmethod
    def _sink(call: ToolCall) -> str | None:
        if call.tool_name == "http_request":
            url = str(call.arguments.get("url", ""))
            if any(domain in url for domain in ("status.example", "rotation.example", "internal.example")):
                return "INTERNAL_NETWORK"
            return "EXTERNAL_NETWORK"
        if call.tool_name == "write_file" and str(call.arguments.get("path", "")).startswith("tmp/"):
            return "INTERNAL_TEMP_STORAGE"
        return {
            "write_file": "REPOSITORY_WRITE",
            "modify_manifest": "REPOSITORY_WRITE",
            "write_log": "INTERNAL_LOG",
            "run_shell": "SHELL_ARGUMENT",
        }.get(call.tool_name)


class ProvenancePolicy:
    SENSITIVE = {Sensitivity.SENSITIVE, Sensitivity.SECRET, Sensitivity.SECRET_DERIVED}

    def __init__(
        self,
        features: ProvenanceFeatures | None = None,
        security_policy: dict[str, Any] | None = None,
    ) -> None:
        self.features = features or ProvenanceFeatures()
        self.authorization = AuthorizationResolver()
        self.security_policy = security_policy or {}

    def evaluate(
        self,
        scenario: Scenario,
        call: ToolCall,
        tools: list[ToolMetadata],
        tracker: ProvenanceTracker,
        history,
    ) -> ProvenanceAssessment:
        inputs = tracker.input_artifacts(call)
        sink = tracker._sink(call) if self.features.sink_classification else None
        sensitive = [artifact for artifact in inputs if artifact.sensitivity in self.SENSITIVE]
        if not sink or not sensitive:
            return ProvenanceAssessment(Decision.ALLOW, [], [], [item.artifact_id for item in inputs], sink, None)

        authorizations = self.authorization.resolve(
            scenario.user_request,
            scenario.external_content,
            tools,
            security_policy=self.security_policy,
        )
        authorized = (
            self._transmission_authorized(authorizations, call, history)
            if self.features.scoped_authorization_integration
            else False
        )
        if sink == "EXTERNAL_NETWORK":
            if authorized:
                return ProvenanceAssessment(
                    Decision.ALLOW,
                    ["AUTHORIZED_SENSITIVE_DATA_EGRESS"],
                    ["Exact trusted scope authorizes this sensitive-data destination and method"],
                    [item.artifact_id for item in inputs],
                    sink,
                    "HIGH",
                )
            rules = ["SENSITIVE_DATA_TO_EXTERNAL_NETWORK_DENY"]
            if not authorized:
                rules.append("HIGH_RISK_DATA_FLOW_REQUIRES_AUTHORIZATION")
            return ProvenanceAssessment(
                Decision.BLOCK,
                rules,
                ["SECRET or SECRET-derived provenance reaches an external network sink"],
                [item.artifact_id for item in inputs],
                sink,
                "CRITICAL",
            )
        if sink == "INTERNAL_NETWORK":
            if authorized:
                return ProvenanceAssessment(
                    Decision.ALLOW,
                    ["AUTHORIZED_SENSITIVE_DATA_EGRESS"],
                    ["Trusted policy and user intent authorize this exact internal network egress"],
                    [item.artifact_id for item in inputs],
                    sink,
                    "HIGH",
                )
            return ProvenanceAssessment(
                Decision.BLOCK,
                ["HIGH_RISK_DATA_FLOW_REQUIRES_AUTHORIZATION"],
                ["Sensitive provenance reaches an internal network sink without an exact egress grant"],
                [item.artifact_id for item in inputs],
                sink,
                "CRITICAL",
            )
        if sink in {"INTERNAL_TEMP_STORAGE", "INTERNAL_LOG"}:
            return ProvenanceAssessment(
                Decision.ALLOW,
                ["SENSITIVE_DATA_TO_INTERNAL_STORAGE_OBSERVED"],
                [f"Sensitive provenance enters monitored {sink}; lineage remains tainted"],
                [item.artifact_id for item in inputs],
                sink,
                "HIGH",
            )
        if sink in {"REPOSITORY_WRITE", "SHELL_ARGUMENT"} and not authorized:
            return ProvenanceAssessment(
                Decision.BLOCK,
                ["UNAUTHORIZED_SECRET_DERIVATION_FLOW_DENY"],
                [f"Sensitive provenance reaches {sink} without a separate transmission grant"],
                [item.artifact_id for item in inputs],
                sink,
                "HIGH" if sink != "SHELL_ARGUMENT" else "CRITICAL",
            )
        return ProvenanceAssessment(
            Decision.ALLOW,
            ["AUTHORIZED_SENSITIVE_DATA_FLOW"],
            ["Trusted user scope separately authorizes this exact sensitive-data sink"],
            [item.artifact_id for item in inputs],
            sink,
            "HIGH",
        )

    def _transmission_authorized(self, grants: list[UserAuthorization], call: ToolCall, history) -> bool:
        match = self.authorization.match_sensitive_egress(grants, call, history)
        return bool(match.matched and match.source != AuthorizationSource.UNTRUSTED_CONTENT_REQUEST)
