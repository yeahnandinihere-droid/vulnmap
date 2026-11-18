from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Any

import httpx
import streamlit as st
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT = httpx.Timeout(20.0, connect=10.0)
MAX_UPLOAD_BYTES = 1_000_000


@dataclass
class ParsedLine:
    line_number: int
    original: str
    name: str = ""
    version: str = ""
    status: str = ""
    detail: str = ""


def parse_requirements(contents: str) -> list[ParsedLine]:
    """Parse requirements.txt without evaluating or installing anything."""
    results: list[ParsedLine] = []

    for line_number, raw in enumerate(contents.splitlines(), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue

        # Keep URL fragments while allowing whitespace-prefixed inline comments.
        text = text.split(" #", 1)[0].strip()
        item = ParsedLine(line_number, raw.strip())

        if not text:
            continue

        if text.startswith(("-", "\\")) or "\\" in text:
            item.status = "Not checked"
            item.detail = (
                "Options, nested files, editable installs, and line "
                "continuations are not supported."
            )
            results.append(item)
            continue

        try:
            req = Requirement(text)
        except InvalidRequirement as exc:
            item.status = "Not checked"
            item.detail = f"Could not parse this requirement: {exc}"
            results.append(item)
            continue

        item.name = req.name

        if req.url:
            item.status = "Not checked"
            item.detail = "Direct URL dependencies are not queried in this MVP."
        elif req.marker:
            item.status = "Not checked"
            item.detail = (
                "Environment markers are not evaluated; review whether this "
                "dependency applies to your target environment."
            )
        elif len(req.specifier) != 1:
            item.status = "Not checked"
            item.detail = (
                "Only a single exact pin such as package==1.2.3 can be checked. "
                "Ranges and unpinned dependencies are reported here."
            )
        else:
            spec = next(iter(req.specifier))
            if spec.operator != "==":
                item.status = "Not checked"
                item.detail = (
                    "Only a single exact pin such as package==1.2.3 can be checked."
                )
            elif "*" in spec.version:
                item.status = "Not checked"
                item.detail = "Wildcard pins do not identify one exact version."
            else:
                try:
                    Version(spec.version)
                except InvalidVersion:
                    item.status = "Not checked"
                    item.detail = (
                        "The pinned version is not a standard Python version "
                        "understood by packaging."
                    )
                else:
                    item.version = spec.version
                    item.status = "Queued"

        results.append(item)

    return results


def _severity(vuln: dict[str, Any]) -> str:
    values = []

    for severity in vuln.get("severity", []) or []:
        score = severity.get("score")
        kind = severity.get("type")
        if score:
            values.append(f"{kind}: {score}" if kind else str(score))

    database_severity = vuln.get("database_specific", {}).get("severity", [])
    if isinstance(database_severity, str):
        values.append(database_severity)
    elif isinstance(database_severity, list):
        values.extend(str(item) for item in database_severity if item)

    return "; ".join(dict.fromkeys(values)) or "Not provided by OSV"


def _affected_versions(
    vuln: dict[str, Any], package_name: str
) -> tuple[str, str]:
    affected_ranges = []
    fixed_versions = []

    for affected in vuln.get("affected", []) or []:
        package = affected.get("package", {}) or {}
        if (
            package.get("ecosystem") != "PyPI"
            or canonicalize_name(package.get("name", ""))
            != canonicalize_name(package_name)
        ):
            continue

        for version in affected.get("versions", []) or []:
            affected_ranges.append(version)

        for version_range in affected.get("ranges", []) or []:
            for event in version_range.get("events", []) or []:
                if event.get("introduced"):
                    affected_ranges.append(
                        f"introduced {event['introduced']}"
                    )
                if event.get("last_affected"):
                    affected_ranges.append(
                        f"last affected {event['last_affected']}"
                    )
                if event.get("fixed"):
                    fixed_versions.append(event["fixed"])

    affected_text = ", ".join(dict.fromkeys(affected_ranges))
    fixed_text = ", ".join(dict.fromkeys(fixed_versions))

    return (
        affected_text or "See OSV advisory",
        fixed_text or "No fixed version listed",
    )


def query_osv(items: list[ParsedLine]) -> None:
    queued = [item for item in items if item.status == "Queued"]
    if not queued:
        return

    payload = {
        "queries": [
            {
                "package": {"name": item.name, "ecosystem": "PyPI"},
                "version": item.version,
            }
            for item in queued
        ]
    }

    try:
        with httpx.Client(
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "VulnMap-MVP/0.1"},
        ) as client:
            response = client.post(OSV_BATCH_URL, json=payload)
            response.raise_for_status()
            body = response.json()

        results = body.get("results")
        if not isinstance(results, list) or len(results) != len(queued):
            raise ValueError("OSV returned an unexpected batch response.")
    except (httpx.HTTPError, ValueError) as exc:
        for item in queued:
            item.status = "Query failed"
            item.detail = f"Could not get a reliable result from OSV: {exc}"
        return

    for item, result in zip(queued, results):
        vulnerabilities = (
            result.get("vulns", []) if isinstance(result, dict) else []
        )

        if not vulnerabilities:
            item.status = "No known vulnerability found"
            item.detail = (
                "OSV returned no matching advisory for this package and version."
            )
            continue

        item.status = "Vulnerable"
        advisories = []

        for vuln in vulnerabilities:
            affected, fixed = _affected_versions(vuln, item.name)
            references = vuln.get("references", []) or []
            url = next(
                (
                    reference.get("url")
                    for reference in references
                    if reference.get("type") == "ADVISORY"
                    and reference.get("url")
                ),
                "",
            )
            if not url:
                url = f"https://osv.dev/vulnerability/{vuln.get('id', '')}"

            advisories.append(
                {
                    "Package": item.name,
                    "Installed version": item.version,
                    "Advisory": vuln.get("id", "Unknown advisory"),
                    "Summary": vuln.get("summary")
                    or vuln.get("details", "")[:500],
                    "Severity": _severity(vuln),
                    "Affected versions / ranges": affected,
                    "Fixed versions": fixed,
                    "OSV link": url,
                }
            )

        item.detail = f"{len(vulnerabilities)} advisory/advisories found."
        item.advisories = advisories


def _csv_bytes(rows: list[dict[str, str]]) -> bytes:
    columns = [
        "Line",
        "Requirement",
        "Package",
        "Installed version",
        "Status",
        "Details",
        "Advisory",
        "Summary",
        "Severity",
        "Affected versions / ranges",
        "Fixed versions",
        "OSV link",
    ]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8-sig")


def main() -> None:
    st.set_page_config(
        page_title="VulnMap",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ VulnMap")
    st.subheader("Software Supply Chain Security Platform")
    st.write(
        "Understand your software dependencies and identify potential "
        "security vulnerabilities."
    )
    st.info(
        "This MVP checks known public advisories only. A clean result is not "
        "a security assurance, and OSV may not list every issue."
    )

    uploaded = st.file_uploader(
        "Choose requirements.txt",
        type=["txt"],
    )

    if uploaded is None:
        st.caption(
            "Requirements are parsed locally. Only package names and exact "
            "pinned versions are sent to OSV."
        )
        return

    if uploaded.size > MAX_UPLOAD_BYTES:
        st.error("This file is over the 1 MB limit. Please upload a smaller file.")
        return

    try:
        contents = uploaded.getvalue().decode("utf-8-sig")
    except UnicodeDecodeError:
        st.error("The file must use UTF-8 text encoding.")
        return

    items = parse_requirements(contents)

    if not items:
        st.warning("No requirements were found in this file.")
        return

    if any(item.status == "Queued" for item in items):
        with st.spinner("Checking exact pins with OSV…"):
            query_osv(items)
    else:
        st.warning(
            "No single exact package pins were found to query. "
            "Review the results below for unsupported entries."
        )

    rows = []

    for item in items:
        base = {
            "Line": str(item.line_number),
            "Requirement": item.original,
            "Package": item.name,
            "Installed version": item.version,
            "Status": item.status,
            "Details": item.detail,
        }
        advisories = getattr(item, "advisories", [])

        if advisories:
            rows.extend({**base, **advisory} for advisory in advisories)
        else:
            rows.append(base)

    counts = {}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1

    columns = st.columns(3)
    columns[0].metric("Requirements", len(items))
    columns[1].metric("Vulnerable pins", counts.get("Vulnerable", 0))
    columns[2].metric("Not checked", counts.get("Not checked", 0))

    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.download_button(
        "Download CSV report",
        data=_csv_bytes(rows),
        file_name="vulnmap-report.csv",
        mime="text/csv",
    )
    st.caption(
        "OSV results reflect the database response at the time of the query. "
        "Review linked advisories and validate findings for your environment."
    )


if __name__ == "__main__":
    main()
