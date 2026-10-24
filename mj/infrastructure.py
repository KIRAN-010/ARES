"""Offline Kubernetes manifest checks. No cloud credentials or cluster writes."""


def audit_manifest(document):
    if not isinstance(document, dict):
        raise ValueError("Manifest must be a JSON object")
    kind = document.get("kind")
    spec = document.get("spec", {})
    if not isinstance(spec, dict):
        raise ValueError("Manifest spec must be an object")
    if kind in {"Deployment", "DaemonSet", "StatefulSet", "Job"}:
        spec = spec.get("template", {}).get("spec", {})
    elif kind != "Pod":
        raise ValueError("Supported kinds: Pod, Deployment, DaemonSet, StatefulSet, Job")
    if not isinstance(spec, dict):
        raise ValueError("Pod spec must be an object")
    results = []

    def add(code, severity, path, message):
        results.append({"code": code, "severity": severity, "path": path, "message": message,
                        "classification": "manifest_configuration_observation"})

    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(key) is True:
            add("HOST_NAMESPACE", "high", "spec." + key, "Container requests a host namespace")
    if spec.get("automountServiceAccountToken", True) is not False:
        add("SERVICE_ACCOUNT_TOKEN", "low", "spec.automountServiceAccountToken", "Service-account token mounting is not explicitly disabled")
    volumes = spec.get("volumes", [])
    if not isinstance(volumes, list):
        raise ValueError("volumes must be a list")
    for i, volume in enumerate(volumes):
        if isinstance(volume, dict) and "hostPath" in volume:
            add("HOST_PATH", "high", f"spec.volumes[{i}]", "Host filesystem mount declared")
    containers = spec.get("containers", []) + spec.get("initContainers", [])
    if len(containers) > 100:
        raise ValueError("At most 100 containers per assessment")
    pod_security = spec.get("securityContext", {})
    for i, container in enumerate(containers):
        if not isinstance(container, dict):
            raise ValueError("Container must be an object")
        security = container.get("securityContext", {})
        path = f"containers[{i}]"
        if security.get("privileged") is True:
            add("PRIVILEGED", "high", path, "Privileged container explicitly requested")
        if security.get("allowPrivilegeEscalation") is not False:
            add("PRIVILEGE_ESCALATION", "medium", path, "Privilege escalation is not explicitly disabled")
        if security.get("runAsNonRoot", pod_security.get("runAsNonRoot")) is not True:
            add("NON_ROOT_UNSPECIFIED", "medium", path, "Non-root execution is not explicitly required")
        if security.get("readOnlyRootFilesystem") is not True:
            add("WRITABLE_ROOT", "low", path, "Read-only root filesystem is not requested")
        image = str(container.get("image", ""))
        if "@sha256:" not in image:
            add("IMAGE_NOT_PINNED", "low", path + ".image", "Image is not pinned by digest")
    return {"kind": kind, "name": str(document.get("metadata", {}).get("name", "unnamed"))[:100],
            "findings": results, "cluster_contacted": False,
            "limitations": "Static manifest analysis only; admission policies and live cluster defaults are unknown"}
