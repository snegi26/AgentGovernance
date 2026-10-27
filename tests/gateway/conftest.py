# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Iterator

import pytest

from agent_governance.demo.estate import DemoEstate, build_demo


@pytest.fixture
def estate() -> Iterator[DemoEstate]:
    estate = build_demo()
    yield estate
    estate.runtime.close()
