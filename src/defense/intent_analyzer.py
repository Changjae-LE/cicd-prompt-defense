from __future__ import annotations

import re


class IntentAnalyzer:
    TOOL_KEYWORDS: dict[str, tuple[str, ...]] = {
        "read_file": ("readme", "file", "manifest", "dockerfile", "yaml", "repository", "review", "summarize", "analy", "diagnos", "explain", "check"),
        "read_ci_log": ("ci", "test", "build", "pipeline"),
        "read_deployment_log": ("deployment", "deploy", "imagepull", "failure", "log", "diagnos"),
        "list_k8s_pods": ("pod", "kubernetes", "k8s", "deployment", "unhealthy"),
        "get_k8s_logs": ("pod log", "pod", "kubernetes log", "k8s log"),
        "create_patch": ("patch", "fix", "suggest", "propose"),
        "modify_manifest": ("update", "modify", "change", "edit"),
        "apply_manifest": ("apply", "deploy"),
        "run_shell": ("run", "execute", "test suite", "git diff", "docker build"),
        "read_secret": ("read", "secret", "token", "api key", "redaction test"),
        "http_request": ("http", "url", "network", "get ", "post ", "health"),
        "delete_k8s_resource": ("delete", "remove", "destroy"),
        "write_file": ("write", "file", "store", "escrow"),
        "write_log": ("write log", "audit log", "record"),
        "encode_data": ("encode", "base64", "hex"),
        "transform_data": ("transform", "json", "validate"),
        "split_data": ("split", "fragment"),
        "fingerprint_data": ("fingerprint", "hash"),
    }

    def infer(self, user_request: str) -> list[str]:
        text = user_request.lower()
        intents = [tool for tool, words in self.TOOL_KEYWORDS.items() if any(word in text for word in words)]
        return sorted(set(intents))

    def aligned(self, user_request: str, tool_name: str) -> bool:
        text = user_request.lower()
        if tool_name in self.infer(user_request):
            return True
        # Read-only support actions are reasonable for diagnostic requests.
        diagnostic = bool(re.search(r"analy|diagnos|explain|review|check|failure|why|summar", text))
        return diagnostic and tool_name in {"read_file", "read_ci_log", "read_deployment_log", "list_k8s_pods", "get_k8s_logs"}

    @staticmethod
    def explicit(user_request: str, tool_name: str) -> bool:
        text = user_request.lower()
        explicit_terms = {
            "read_secret": ("secret", "token", "api key"),
            "http_request": ("http", "url", "network", "get ", "post "),
            "run_shell": ("run", "execute", "test suite", "git diff", "docker build"),
            "apply_manifest": ("apply", "deploy"),
            "modify_manifest": ("update", "modify", "change", "edit"),
            "delete_k8s_resource": ("delete", "destroy", "remove"),
            "write_file": ("write", "store", "escrow"),
            "write_log": ("write log", "audit log", "record"),
        }
        return any(term in text for term in explicit_terms.get(tool_name, (tool_name,)))
