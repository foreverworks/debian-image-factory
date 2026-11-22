"""`package-set` and `sbom-complete` (DESIGN 11), pure: package sets from a dpkg status text and an SPDX
document, compared with the plan's."""

import urllib.parse
from collections.abc import Collection, Mapping

from input_lock import Package

from .. import debian
from .model import PACKAGE_SET, SBOM_COMPLETE, Result, result, split

STATUS_PATH = "/var/lib/dpkg/status"
INPUT_ID_PREFIX = "SPDXRef-Input-"
DEB_PURL_PREFIX = "pkg:deb/"


def describe(package: Package) -> str:
    name, version, arch = package
    return f"{name} {version} ({arch})"


def installed(status: bytes | None) -> list[Package] | str:
    """The packages a dpkg status file installs, or what is wrong with it (absent, unreadable)."""
    if status is None:
        return f"{STATUS_PATH} is not in the tarball"
    try:
        return [(name, version, arch) for name, version, arch in debian.installed_packages(status.decode("utf-8"))]
    except ValueError as error:  # UnicodeDecodeError is one
        return f"{STATUS_PATH} cannot be read: {error}"


def differences(
    expected: Collection[Package], actual: Collection[Package], expected_name: str, actual_name: str
) -> tuple[list[str], list[str]]:
    """(in expected only, in actual only), each described and sorted."""
    left, right = set(expected), set(actual)
    return (
        [f"{describe(p)} is in {expected_name} and not in {actual_name}" for p in sorted(left - right)],
        [f"{describe(p)} is in {actual_name} and not in {expected_name}" for p in sorted(right - left)],
    )


def package_set(status: bytes | None, planned: Collection[Package]) -> Result:
    """The tarball's dpkg status equals the plan entry's packages."""
    found = installed(status)
    if isinstance(found, str):
        return result(PACKAGE_SET, [], failed=[f"dpkg-status-readable: {found}"])
    missing, extra = differences(planned, found, "the plan", "the image")
    ok_missing, bad_missing = split("no-missing-packages", missing)
    ok_extra, bad_extra = split("no-extra-packages", extra)
    return result(PACKAGE_SET, ["dpkg-status-readable", *ok_missing, *ok_extra], failed=[*bad_missing, *bad_extra])


def sbom_packages(document: Mapping[str, object]) -> tuple[list[Package], dict[str, str]] | str:
    """(the Debian packages the SBOM lists, the locked inputs it lists by entry name and version), or what
    is wrong with the document. A Debian package is one with a `pkg:deb/` purl; its architecture comes
    from the purl, its name and version from the package's own fields."""
    listed = document.get("packages")
    if not isinstance(listed, list):
        return "the SBOM has no packages list"
    debs: list[Package] = []
    inputs: dict[str, str] = {}
    for item in listed:
        if not isinstance(item, dict):
            return "the SBOM has a package that is not an object"
        name, version, ident = item.get("name"), item.get("versionInfo"), item.get("SPDXID")
        if not isinstance(name, str) or not isinstance(version, str):
            return f"the SBOM has a package without a name or versionInfo: {ident!r}"
        if isinstance(ident, str) and ident.startswith(INPUT_ID_PREFIX):
            inputs[name] = version
            continue
        refs = item.get("externalRefs")
        for ref in refs if isinstance(refs, list) else []:
            locator = ref.get("referenceLocator") if isinstance(ref, dict) else None
            if isinstance(locator, str) and locator.startswith(DEB_PURL_PREFIX):
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(locator).query)
                arch = query.get("arch", [""])[0]
                if not arch:
                    return f"the purl of {name} has no arch: {locator}"
                debs.append((name, version, arch))
                break
    return debs, inputs


def sbom_complete(status: bytes | None, document: Mapping[str, object] | str, locked: Mapping[str, str]) -> Result:
    """The SBOM lists every installed package and every locked input, and nothing installed is absent.

    `document` is the SBOM's predicate, or the reason there is not exactly one for this artifact.
    `locked` is the plan entry's locked inputs, entry name to version.
    """
    found = installed(status)
    if isinstance(found, str):
        return result(SBOM_COMPLETE, [], failed=[f"dpkg-status-readable: {found}"])
    if isinstance(document, str):
        return result(SBOM_COMPLETE, ["dpkg-status-readable"], failed=[f"sbom-present: {document}"])
    parsed = sbom_packages(document)
    if isinstance(parsed, str):
        return result(SBOM_COMPLETE, ["dpkg-status-readable", "sbom-present"], failed=[f"sbom-readable: {parsed}"])
    listed_debs, listed_inputs = parsed
    unlisted, phantom = differences(found, listed_debs, "the image", "the SBOM")
    ok_unlisted, bad_unlisted = split("every-package-listed", unlisted)
    ok_phantom, bad_phantom = split("no-package-not-installed", phantom)
    absent = [
        f"{name} {version} is locked and not in the SBOM"
        for name, version in sorted(locked.items())
        if listed_inputs.get(name) != version
    ]
    ok_inputs, bad_inputs = split("every-locked-input-listed", absent)
    return result(
        SBOM_COMPLETE,
        ["dpkg-status-readable", "sbom-present", "sbom-readable", *ok_unlisted, *ok_phantom, *ok_inputs],
        failed=[*bad_unlisted, *bad_phantom, *bad_inputs],
    )


def locked_versions(inputs: Mapping[str, object]) -> dict[str, str]:
    """Entry name to version from the plan entry's `inputs` (each a `build_fields` object)."""
    return {name: str(fields.get("version", "")) for name, fields in inputs.items() if isinstance(fields, dict)}
