#!/usr/bin/env python3
import json
import re
from pathlib import Path


SUSPICIOUS_NAME = re.compile(r"(SECRET|TOKEN|PASSWORD|KEY)", re.IGNORECASE)


def dockerfiles(root):
    direct = root / "Dockerfile"
    if direct.exists():
        yield direct
    for path in root.rglob("*"):
        if path.is_file() and (path.name == "Dockerfile" or path.name.endswith(".Dockerfile")):
            if path != direct:
                yield path


def inspect_dockerfile(path, root):
    findings = []
    for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) < 2 or parts[0] not in {"ENV", "ARG"}:
            continue

        body = parts[1]
        name = body.split("=", 1)[0].split()[0]
        if SUSPICIOUS_NAME.search(name):
            rel_path = path.relative_to(root).as_posix()
            findings.append(
                {
                    "id": "DOCKERFILE-001",
                    "severity": "medium",
                    "title": "Dockerfile may expose a sensitive build value",
                    "file": rel_path,
                    "line": line_number,
                    "evidence": stripped,
                    "recommendation": "Avoid placing secrets in Dockerfile ENV or ARG values; pass secrets through a runtime secret manager or build secret mechanism.",
                }
            )
    return findings


def main():
    input_path = Path("/adversary/input.json")
    output_path = Path("/adversary/output.json")
    input_data = json.loads(input_path.read_text())
    root = Path(input_data["source"]["path"])

    findings = []
    for path in dockerfiles(root):
        findings.extend(inspect_dockerfile(path, root))

    output = {
        "schema_version": "adversary.findings.v1",
        "adversary": "adversarylabs/dockerfile",
        "findings": findings,
    }
    output_path.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
