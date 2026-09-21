# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Infer MSI installation scope from authored database tables."""

import io
import re
from collections.abc import Iterable, Mapping
from contextlib import redirect_stdout
from pathlib import Path

import pymsi

from whatyouship.model import InstallationScope, InstallationScopeKind


_USER_DIRECTORIES = frozenset({
    "appdatafolder", "localappdatafolder", "personalfolder", "favoritesfolder",
    "mypicturesfolder", "recentfolder", "sendtofolder", "templatesfolder",
})
_MACHINE_DIRECTORIES = frozenset({
    "commonappdatafolder", "commondesktopfolder", "windowsfolder",
    "systemfolder", "system64folder", "system16folder",
})
_SCOPE_PROPERTIES = frozenset({"ALLUSERS", "MSIINSTALLPERUSER"})
_TABLES = ("Property", "Directory", "Registry", "Component", "Shortcut", "CustomAction")
_FORMATTED_REFERENCE = re.compile(r"\[[^][]+\]")


def _value(row: Mapping[str, object], column: str) -> str:
    """Return an MSI column as text, treating null as an empty value.

    :param row: MSI table row.
    :param column: Column name.
    :returns: Text value or an empty string.
    """
    value = row.get(column)
    return "" if value is None else str(value).strip()


def _integer(value: object) -> int | None:
    """Parse an MSI integer without inferring invalid values.

    :param value: Table column value.
    :returns: Integer value, or ``None`` when it cannot be parsed.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _directory_scope(
    directory_id: str, parents: Mapping[str, str]
) -> tuple[InstallationScopeKind, str] | None:
    """Find a fixed user or machine directory in a component's ancestry.

    :param directory_id: Component directory identifier.
    :param parents: Parent identifiers from the Directory table.
    :returns: Scope and anchor identifier when a fixed destination is found.
    """
    seen: set[str] = set()
    current = directory_id
    while current and current not in seen:
        seen.add(current)
        if current.casefold() in _USER_DIRECTORIES:
            return "per-user", current
        if current.casefold() in _MACHINE_DIRECTORIES:
            return "per-machine", current
        current = parents.get(current, "")
    return None


def _non_advertised_shortcut_components(
    shortcuts: Iterable[Mapping[str, object]],
) -> set[str]:
    """Find components with shortcuts targeting a formatted path.

    :param shortcuts: Rows from the MSI Shortcut table.
    :returns: Component IDs containing non-advertised shortcuts.
    """
    return {
        _value(shortcut, "Component_")
        for shortcut in shortcuts
        if _value(shortcut, "Component_")
        and _FORMATTED_REFERENCE.search(_value(shortcut, "Target")) is not None
    }


def analyze_msi_scope(
    tables: Mapping[str, Iterable[Mapping[str, object]]],
) -> InstallationScope:
    """Infer scope and identify fixed destinations that contradict it.

    :param tables: Rows from the relevant MSI database tables.
    :returns: Installation scope and deterministic conflict descriptions.
    """
    rows = {name: list(tables.get(name, ())) for name in _TABLES}
    properties = {
        _value(row, "Property").upper(): _value(row, "Value")
        for row in rows["Property"]
    }
    allusers = properties.get("ALLUSERS", "")
    per_user_property = properties.get("MSIINSTALLPERUSER")
    conflicts: list[str] = []

    declared: InstallationScopeKind
    if allusers == "1":
        declared = "per-machine"
    elif allusers == "2":
        declared = "dual-purpose"
    elif allusers == "":
        declared = "per-user"
    else:
        declared = "ambiguous"
        conflicts.append(f"Property ALLUSERS has unsupported value '{allusers}'.")

    if allusers == "2":
        if per_user_property not in (None, "", "1"):
            conflicts.append(
                f"Property MSIINSTALLPERUSER has unsupported value '{per_user_property}'."
            )
    elif allusers == "1" and per_user_property not in (None, ""):
        conflicts.append(
            "Property MSIINSTALLPERUSER is ignored unless ALLUSERS=2; "
            f"ALLUSERS={allusers or '(unset)'} and MSIINSTALLPERUSER={per_user_property}."
        )

    for row in sorted(rows["CustomAction"], key=lambda item: _value(item, "Action")):
        action_type = _integer(row.get("Type"))
        if action_type is None or action_type & 0x3F != 51:
            continue
        property_name = _value(row, "Source").upper()
        if property_name not in _SCOPE_PROPERTIES:
            continue
        action = _value(row, "Action")
        target = _value(row, "Target")
        if property_name == "MSIINSTALLPERUSER" and allusers in ("", "1"):
            if allusers == "1" and target == "1":
                conflicts.append(
                    f"CustomAction '{action}' requests per-user installation through "
                    "MSIINSTALLPERUSER, which is ignored unless ALLUSERS=2."
                )
            continue
        if "[" in target or "]" in target:
            conflicts.append(
                f"CustomAction '{action}' sets {property_name} from a formatted value; "
                "the resulting installation scope is ambiguous."
            )
        elif property_name == "ALLUSERS":
            if target not in ("", "1", "2"):
                conflicts.append(
                    f"CustomAction '{action}' sets ALLUSERS to unsupported value '{target}'."
                )
            elif allusers != "2" and target != allusers:
                conflicts.append(
                    f"CustomAction '{action}' sets ALLUSERS={target or '(unset)'} "
                    f"while Property ALLUSERS={allusers or '(unset)'}."
                )
        elif target not in ("", "1"):
            conflicts.append(
                f"CustomAction '{action}' sets MSIINSTALLPERUSER to unsupported "
                f"value '{target}'."
            )

    parents = {
        _value(row, "Directory"): _value(row, "Directory_Parent")
        for row in rows["Directory"]
    }
    registry_by_component: dict[str, list[Mapping[str, object]]] = {}
    for row in rows["Registry"]:
        registry_by_component.setdefault(_value(row, "Component_"), []).append(row)
    non_advertised_shortcut_components = _non_advertised_shortcut_components(
        rows["Shortcut"]
    )

    component_ids = {_value(row, "Component") for row in rows["Component"]}
    for registry in sorted(rows["Registry"], key=lambda item: _value(item, "Registry")):
        if _value(registry, "Component_") in component_ids:
            continue
        root = _integer(registry.get("Root"))
        scope = "per-user" if root == 1 else "per-machine" if root == 2 else None
        if scope is not None and (
            declared == "dual-purpose" or (
                declared in ("per-user", "per-machine") and scope != declared
            )
        ):
            conflicts.append(
                f"Registry '{_value(registry, 'Registry')}' uses fixed {scope} root "
                f"without a matching component while the package declares {declared} "
                "installation scope."
            )

    for component in sorted(rows["Component"], key=lambda item: _value(item, "Component")):
        component_id = _value(component, "Component")
        signals: list[tuple[InstallationScopeKind, str]] = []
        destination = _directory_scope(_value(component, "Directory_"), parents)
        if destination is not None:
            scope, anchor = destination
            signals.append((scope, f"directory '{anchor}'"))

        attributes = _integer(component.get("Attributes")) or 0
        keypath = _value(component, "KeyPath") if attributes & 0x04 else ""
        for registry in sorted(
            registry_by_component.get(component_id, ()),
            key=lambda item: _value(item, "Registry"),
        ):
            root = _integer(registry.get("Root"))
            if root not in (1, 2):
                continue
            scope = "per-user" if root == 1 else "per-machine"
            root_name = "HKCU" if root == 1 else "HKLM"
            registry_id = _value(registry, "Registry")
            if (
                declared == "per-machine"
                and root == 1
                and keypath
                and registry_id == keypath
                and component_id in non_advertised_shortcut_components
            ):
                continue
            kind = "registry key path" if registry_id == keypath else "registry entry"
            signals.append((scope, f"{root_name} {kind} '{registry_id}'"))

        scopes = {scope for scope, _ in signals}
        if len(scopes) > 1:
            conflicts.append(
                f"Component '{component_id}' mixes per-user and per-machine destinations."
            )

        if _value(component, "Condition"):
            continue
        for scope, destination_name in signals:
            if declared == "dual-purpose" or (
                declared in ("per-user", "per-machine") and scope != declared
            ):
                conflicts.append(
                    f"Component '{component_id}' uses fixed {scope} {destination_name} "
                    f"while the package declares {declared} installation scope."
                )

    return InstallationScope(
        kind="ambiguous" if conflicts else declared,
        conflicts=tuple(dict.fromkeys(conflicts)),
    )


class MsiScopeInspector:
    """Read MSI database tables without running the installer."""

    def inspect(self, source_path: Path) -> InstallationScope:
        """Read scope-related MSI tables from the original package.

        :param source_path: MSI package to inspect.
        :returns: Static installation scope assessment.
        """
        with redirect_stdout(io.StringIO()), pymsi.Package(source_path) as package:
            tables = {
                name: list(table.iter()) if (table := package.get(name)) is not None else []
                for name in _TABLES
            }
        return analyze_msi_scope(tables)
