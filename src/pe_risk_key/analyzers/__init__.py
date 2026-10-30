"""Document analyzers (SPEC §4.2). Not yet wired into the orchestrator."""

from pe_risk_key.analyzers.soc2 import SOC2Result, analyze_soc2

__all__ = ["SOC2Result", "analyze_soc2"]
