# SPDX-License-Identifier: Apache-2.0
"""SAP S/4HANA connector over the standard user and role tables.

The reference implementation reads a JSON export of the tables a live connector reads over
RFC (``RFC_READ_TABLE``) or the CDS-based OData services:

* ``USR02`` — users (``BNAME``, ``USTYP``: A dialog, B system, C communication, S service);
* ``AGR_DEFINE`` / ``AGR_TEXTS`` — roles and descriptions;
* ``AGR_1251`` — role authorization values (``AGR_NAME, OBJECT, FIELD, LOW, HIGH``);
* ``AGR_USERS`` — role assignments (``AGR_NAME, UNAME, FROM_DAT, TO_DAT``).

SAP user names are mapped to governed principals through ``identity_map`` (dialog users) and
``owners`` (system and service users, which become NHIs that must have a human owner).
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import date
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

_NHI_TYPES = {"B", "C", "S"}


def _sap_date(value: str | None) -> date | None:
    if not value or value in ("00000000", "99991231"):
        return None
    return date(int(value[:4]), int(value[4:6]), int(value[6:8]))


class SapS4Connector:
    system = "S4"

    def __init__(self, export: dict[str, Any]) -> None:
        self._data = export

    @classmethod
    def from_file(cls, path: str | Path) -> SapS4Connector:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def snapshot(self) -> Snapshot:
        data = self._data
        identity: dict[str, str] = data.get("identity_map", {})
        owners: dict[str, str] = data.get("owners", {})
        warnings: list[str] = []
        principals: dict[str, Principal] = {}
        uname_to_principal: dict[str, str] = {}
        for row in data.get("USR02", []):
            bname = row["BNAME"]
            locked = row.get("UFLAG", 0) not in (0, "0", "")
            status = PrincipalStatus.SUSPENDED if locked else PrincipalStatus.ACTIVE
            if row.get("USTYP", "A") in _NHI_TYPES:
                owner = owners.get(bname)
                if owner is None:
                    warnings.append(f"service user {bname} has no human owner; skipped")
                    continue
                pid = f"svc:sap-{bname.lower()}"
                principals[pid] = Principal(
                    pid, PrincipalKind.NHI, owner_id=owner, status=status, source_system="S4"
                )
            else:
                pid = identity.get(bname, "")
                if not pid:
                    warnings.append(f"dialog user {bname} is not mapped to an identity; skipped")
                    continue
            uname_to_principal[bname] = pid

        texts = {r["AGR_NAME"]: r.get("TEXT", "") for r in data.get("AGR_TEXTS", [])}
        values: dict[str, list[Entitlement]] = defaultdict(list)
        for row in data.get("AGR_1251", []):
            if row.get("HIGH"):
                where = f"{row['AGR_NAME']} {row['OBJECT']}-{row['FIELD']}"
                warnings.append(f"{where} uses a range; only LOW is evaluated")
            values[row["AGR_NAME"]].append(
                Entitlement("S4", row["OBJECT"], row["FIELD"], row["LOW"])
            )
        roles = tuple(
            Role(
                role_id=r["AGR_NAME"],
                system="S4",
                entitlements=tuple(values.get(r["AGR_NAME"], ())),
                description=texts.get(r["AGR_NAME"], ""),
                owner_id=r.get("OWNER"),
                critical=bool(r.get("CRITICAL", False)),
            )
            for r in data.get("AGR_DEFINE", [])
        )
        assignments = []
        for row in data.get("AGR_USERS", []):
            holder = uname_to_principal.get(row["UNAME"])
            if holder is None:
                continue
            assignments.append(
                Assignment(
                    holder,
                    row["AGR_NAME"],
                    "S4",
                    _sap_date(row.get("FROM_DAT")),
                    _sap_date(row.get("TO_DAT")),
                )
            )
        return Snapshot(
            "S4", tuple(principals.values()), roles, tuple(assignments), tuple(warnings)
        )
