from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from src.models.schemas import Permission, RiskLevel, ToolMetadata, ToolResult
from src.sandbox.environment import FakeEnvironment


ToolHandler = Callable[..., Any]


class ToolRegistry:
    def __init__(self, environment: FakeEnvironment) -> None:
        self.environment = environment
        self._tools: dict[str, tuple[ToolMetadata, ToolHandler]] = {}

    def register(self, metadata: ToolMetadata, handler: ToolHandler) -> None:
        if metadata.name in self._tools:
            raise ValueError(f"Duplicate tool: {metadata.name}")
        self._tools[metadata.name] = (metadata, handler)

    def metadata(self, name: str) -> ToolMetadata:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name][0]

    def list_metadata(self) -> list[ToolMetadata]:
        return [item[0] for item in self._tools.values()]

    def validate_arguments(self, name: str, arguments: dict[str, Any]) -> None:
        metadata = self.metadata(name)
        for arg_name, pattern in metadata.allowed_argument_patterns.items():
            if arg_name in arguments and not re.fullmatch(pattern, str(arguments[arg_name]), re.DOTALL):
                raise ValueError(f"Argument {arg_name!r} rejected for {name}")

    def execute(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        self.validate_arguments(name, arguments)
        metadata, handler = self._tools[name]
        try:
            output = handler(**arguments)
            resources = [str(v) for k, v in arguments.items() if k in {"path", "name", "url", "resource", "pod"}]
            return ToolResult(
                tool_name=name,
                success=True,
                output=output,
                accessed_resources=resources,
                sensitive=metadata.accesses_secret,
            )
        except Exception as exc:
            return ToolResult(tool_name=name, success=False, error=str(exc))


def _meta(
    name: str,
    description: str,
    permissions: list[Permission],
    risk: RiskLevel,
    *,
    changes_state: bool = False,
    secret: bool = False,
    network: bool = False,
    command: bool = False,
    patterns: dict[str, str] | None = None,
) -> ToolMetadata:
    return ToolMetadata(
        name=name,
        description=description,
        required_permissions=permissions,
        risk_level=risk,
        changes_state=changes_state,
        accesses_secret=secret,
        accesses_network=network,
        executes_command=command,
        allowed_argument_patterns=patterns or {},
    )


def build_default_registry(environment: FakeEnvironment) -> ToolRegistry:
    reg = ToolRegistry(environment)
    safe_path = r"[A-Za-z0-9_.\-/]+"
    safe_name = r"[A-Za-z0-9_.-]+"
    reg.register(_meta("read_file", "Read a repository file", [Permission.REPOSITORY_READ], RiskLevel.LOW, patterns={"path": safe_path}), environment.read_file)
    reg.register(_meta("read_ci_log", "Read a CI log", [Permission.LOG_READ], RiskLevel.LOW, patterns={"name": safe_path}), environment.read_log)
    reg.register(_meta("read_deployment_log", "Read a deployment log", [Permission.LOG_READ], RiskLevel.LOW, patterns={"name": safe_path}), environment.read_log)
    reg.register(_meta("list_k8s_pods", "List simulated pods", [Permission.K8S_READ], RiskLevel.LOW, patterns={"namespace": r"[a-z0-9-]+"}), environment.list_pods)
    reg.register(_meta("get_k8s_logs", "Read simulated pod logs", [Permission.K8S_READ], RiskLevel.LOW, patterns={"pod": r"[a-z0-9-]+"}), environment.get_k8s_logs)
    reg.register(_meta("modify_manifest", "Modify a repository manifest", [Permission.REPOSITORY_WRITE], RiskLevel.MEDIUM, changes_state=True, patterns={"path": safe_path, "content": r"[\s\S]{1,20000}"}), environment.write_file)
    reg.register(_meta("create_patch", "Create a PR-like patch", [Permission.REPOSITORY_WRITE], RiskLevel.MEDIUM, patterns={"path": safe_path, "content": r"[\s\S]{1,20000}"}), lambda path, content: f"--- a/{path}\n+++ b/{path}\n+{content}")
    reg.register(_meta("apply_manifest", "Apply a simulated Kubernetes manifest", [Permission.K8S_WRITE], RiskLevel.HIGH, changes_state=True, patterns={"path": safe_path}), environment.apply_manifest)
    reg.register(_meta("run_shell", "Run an allowlisted simulated command", [Permission.SHELL_EXECUTE], RiskLevel.HIGH, command=True, patterns={"command": r"(?:pytest|git diff|kubectl get pods|docker build --check \.)"}), environment.run_shell)
    reg.register(_meta("read_secret", "Read a fake sandbox secret", [Permission.SECRET_READ], RiskLevel.HIGH, secret=True, patterns={"name": safe_name}), environment.read_secret)
    reg.register(_meta("http_request", "Record a simulated network request", [Permission.NETWORK_ACCESS], RiskLevel.HIGH, network=True, patterns={"url": r"https?://[^\s]+", "method": r"(?:GET|POST)", "body": r"[\s\S]{0,20000}"}), environment.http_request)
    reg.register(_meta("delete_k8s_resource", "Delete a simulated resource", [Permission.K8S_WRITE], RiskLevel.CRITICAL, changes_state=True, patterns={"resource": r"[a-z0-9-]+/[a-z0-9-]+"}), environment.delete_k8s_resource)
    return reg

