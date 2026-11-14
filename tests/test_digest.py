"""Tests for DailyDigestCompiler executive briefing compilation."""

import pytest

from cve_tracker.models.cve import CVEItem, CVSSData, Severity, SourceType
from cve_tracker.services.digest import DailyDigestCompiler
from cve_tracker.storage.repository import CVERepository


@pytest.mark.asyncio
async def test_compile_morning_digest(
    repository: CVERepository,
    sample_cve: CVEItem,
    sample_cisa_cve: CVEItem,
):
    await repository.upsert_cve(sample_cve)
    await repository.upsert_cve(sample_cisa_cve)

    compiler = DailyDigestCompiler(repository)
    digest = await compiler.compile_morning_digest(hours=24)

    assert digest is not None
    assert "EXECUTIVE THREAT INTELLIGENCE BRIEFING" in digest
    assert "SURFACE TELEMETRY" in digest
    assert sample_cve.id in digest
    assert sample_cisa_cve.id in digest
