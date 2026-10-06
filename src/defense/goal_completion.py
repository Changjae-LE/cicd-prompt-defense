from __future__ import annotations

from dataclasses import dataclass

from src.defense.authorization import AuthorizationResolver
from src.models.schemas import (
    AuthorizationSource,
    ExecutionEvent,
    GoalDefinition,
    GoalRequirement,
    GoalStatus,
    Scenario,
    ToolCall,
    ToolMetadata,
)


RESOURCE_ARGUMENTS = {
    "read_secret": "name",
    "read_file": "path",
    "read_ci_log": "name",
    "read_deployment_log": "name",
    "get_k8s_logs": "pod",
    "modify_manifest": "path",
    "create_patch": "path",
    "apply_manifest": "path",
    "run_shell": "command",
    "http_request": "url",
    "delete_k8s_resource": "resource",
}


@dataclass(frozen=True)
class GoalDetectorFeatures:
    use_execution_history: bool = True
    use_resource_matching: bool = True
    use_tool_results: bool = True


class GoalCompiler:
    """Compiles an evaluation goal from explicit definitions or expected task outcomes."""

    def __init__(self) -> None:
        self.authorization = AuthorizationResolver()

    def compile(self, scenario: Scenario, tools: list[ToolMetadata]) -> GoalDefinition:
        if scenario.goal is not None:
            return scenario.goal
        authorizations = self.authorization.resolve(scenario.user_request, scenario.external_content, tools)
        trusted = [
            grant for grant in authorizations
            if grant.source in {
                AuthorizationSource.EXPLICIT_USER_AUTHORIZATION,
                AuthorizationSource.DERIVED_TASK_AUTHORIZATION,
            }
        ]
        requirements: list[GoalRequirement] = []
        for tool_name in dict.fromkeys(scenario.expected_safe_tools):
            resource_argument = RESOURCE_ARGUMENTS.get(tool_name)
            resources: set[str] = set()
            for grant in trusted:
                if tool_name in grant.allowed_tools:
                    if tool_name == "http_request":
                        resources.update(grant.allowed_destinations)
                    else:
                        resources.update(grant.allowed_resources)
            requirements.append(GoalRequirement(
                tool_name=tool_name,
                resource_argument=resource_argument if resources else None,
                allowed_resources=sorted(resources),
            ))
        return GoalDefinition(
            requirements=requirements,
            require_all=True,
            description=f"Compiled from expected task outcome for {scenario.id}",
        )


class GoalCompletionDetector:
    def __init__(self, features: GoalDetectorFeatures | None = None) -> None:
        self.features = features or GoalDetectorFeatures()

    def evaluate(self, goal: GoalDefinition, history: list[ExecutionEvent]) -> GoalStatus:
        if not history:
            return GoalStatus.NOT_STARTED
        if not goal.requirements:
            return GoalStatus.IN_PROGRESS
        considered = history if self.features.use_execution_history else history[-1:]
        matches = [self._requirement_satisfied(requirement, considered) for requirement in goal.requirements]
        satisfied = all(matches) if goal.require_all else any(matches)
        return GoalStatus.SATISFIED if satisfied else GoalStatus.IN_PROGRESS

    def _requirement_satisfied(self, requirement: GoalRequirement, history: list[ExecutionEvent]) -> bool:
        successful = 0
        for event in history:
            if event.audit_only or event.tool_call.tool_name != requirement.tool_name:
                continue
            if self.features.use_tool_results:
                if not event.executed or not event.result or not event.result.success:
                    continue
            elif not event.executed:
                continue
            if self.features.use_resource_matching and requirement.allowed_resources:
                argument = requirement.resource_argument
                if not argument:
                    continue
                actual = str(event.tool_call.arguments.get(argument, "")).strip()
                if actual not in requirement.allowed_resources:
                    continue
            successful += 1
        return successful >= requirement.minimum_successes


class RedundantToolCallDetector:
    """Conservative redundancy detection using exact canonical call/resource identity."""

    def is_redundant(
        self,
        call: ToolCall,
        history: list[ExecutionEvent],
        goal: GoalDefinition,
    ) -> bool:
        successful = [
            event for event in history
            if not event.audit_only and event.executed and event.result and event.result.success
        ]
        if any(
            event.tool_call.tool_name == call.tool_name and event.tool_call.arguments == call.arguments
            for event in successful
        ):
            return True
        for requirement in goal.requirements:
            if requirement.tool_name != call.tool_name or not requirement.allowed_resources:
                continue
            argument = requirement.resource_argument
            if not argument:
                continue
            resource = str(call.arguments.get(argument, "")).strip()
            if resource not in requirement.allowed_resources:
                continue
            if any(
                event.tool_call.tool_name == call.tool_name
                and str(event.tool_call.arguments.get(argument, "")).strip() == resource
                for event in successful
            ):
                return True
        return False
