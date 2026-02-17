from __future__ import annotations

SECURITY_RULE_IDS: set[str] = {
    "SS001",  # Python eval/exec
    "SS003",  # hardcoded secret
    "SS005",  # merge markers
    "SS006",  # subprocess shell=True
    "SS007",  # unsafe yaml.load
    "SS008",  # unsafe pickle deserialization
    "SS009",  # requests verify=False
    "SS101",  # dynamic eval
    "SS102",  # private key material
    "SS107",  # insecure HTTP URL literal
    "SS108",  # Dockerfile root user
    "SS109",  # Docker latest tag
    "SS110",  # Docker curl/wget pipe to shell
    "SS111",  # Kubernetes privileged container
    "SS112",  # Kubernetes allowPrivilegeEscalation true
    "SS113",  # Kubernetes runAsNonRoot false
    "SS114",  # Kubernetes host namespace sharing
    "SS221",  # Java command execution
    "SS306",  # Node.js child_process exec
    "SS407",  # Go insecure TLS verify skip
    "SS408",  # Go shell command execution
    "SS507",  # Kotlin command execution
}


def resolve_enabled_rules(
    enabled_rules: list[str] | None,
    security_only: bool,
) -> list[str] | None:
    if not security_only:
        return enabled_rules
    if enabled_rules is None:
        return sorted(SECURITY_RULE_IDS)
    filtered = [rule for rule in enabled_rules if rule in SECURITY_RULE_IDS]
    return list(dict.fromkeys(filtered))
