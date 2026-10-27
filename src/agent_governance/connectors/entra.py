# SPDX-License-Identifier: Apache-2.0
"""Microsoft Entra ID connector over Microsoft Graph shapes.

Reads the JSON a live connector gets from Graph v1.0: ``/users`` (with ``manager``),
``/servicePrincipals``, ``/roleManagement/directory/roleDefinitions`` and
``/roleManagement/directory/roleAssignments``. Directory roles become roles in system
``ENTRA`` whose single entitlement is ``directoryRole / templateId``, which is what the
starter rule set's ``ENTRA:*`` actions check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_governance.connectors.base import Snapshot
from agent_governance.model import (
    Assignment,
    Entitlement,
    Principal,
    PrincipalKind,
    PrincipalStatus,
    Role,
)


class EntraConnector:
    system = "ENTRA"

    def __init__(
        self, export: dict[str, Any], entitlements: dict[str, list[str]] | None = None
    ) -> None:
        self._data = export
        self._entitlements = entitlements or export.get("governance_entitlements", {})

    @classmethod
    def from_file(cls, path: str | Path) -> EntraConnector:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def snapshot(self) -> Snapshot:
        data = self._data
        by_object_id: dict[str, str] = {}
        principals: list[Principal] = []
        warnings: list[str] = []
        for user in data.get("users", []):
            pid = f"user:{user['userPrincipalName']}"
            by_object_id[user["id"]] = pid
        for user in data.get("users", []):
            pid = by_object_id[user["id"]]
            manager = user.get("manager", {}).get("id") if user.get("manager") else None
            principals.append(
                Principal(
                    pid,
                    PrincipalKind.HUMAN,
                    status=PrincipalStatus.ACTIVE
                    if user.get("accountEnabled", True)
                    else PrincipalStatus.SUSPENDED,
                    source_system="ENTRA",
                    display_name=user.get("displayName", ""),
                    entitlements=frozenset(self._entitlements.get(pid, [])),
                    manager_id=by_object_id.get(manager) if manager else None,
                )
            )
        for sp in data.get("servicePrincipals", []):
            owners = [
                by_object_id[o["id"]] for o in sp.get("owners", []) if o["id"] in by_object_id
            ]
            if not owners:
                warnings.append(
                    f"service principal {sp['displayName']} has no human owner; skipped"
                )
                continue
            pid = f"svc:entra-{sp['appId']}"
            by_object_id[sp["id"]] = pid
            principals.append(
                Principal(
                    pid,
                    PrincipalKind.NHI,
                    owner_id=owners[0],
                    source_system="ENTRA",
                    display_name=sp.get("displayName", ""),
                )
            )
        roles = {
            d["id"]: Role(
                role_id=f"ENTRA:{d['displayName']}",
                system="ENTRA",
                entitlements=(
                    Entitlement("ENTRA", "directoryRole", "templateId", d["templateId"]),
                ),
                description=d.get("description", ""),
                critical=bool(d.get("isPrivileged", False)),
            )
            for d in data.get("roleDefinitions", [])
        }
        assignments = []
        for ra in data.get("roleAssignments", []):
            holder = by_object_id.get(ra["principalId"])
            role = roles.get(ra["roleDefinitionId"])
            if holder is None or role is None:
                warnings.append(
                    f"role assignment {ra.get('id')} references an unknown principal or role"
                )
                continue
            assignments.append(Assignment(holder, role.role_id, "ENTRA"))
        return Snapshot(
            "ENTRA", tuple(principals), tuple(roles.values()), tuple(assignments), tuple(warnings)
        )
