"""
Configuration module for persistent agents with infrastructure tax optimization.

This module provides configuration templates for different deployment scenarios:
- Serverless (scale-to-zero optimized)
- Long-running (optimized for continuous operation)
- Hybrid (balanced approach)
"""

from dataclasses import dataclass
from typing import Optional
from pathlib import Path


@dataclass
class AgentConfig:
    """Configuration for agent deployment with infrastructure tax considerations."""

    # Core settings
    agent_id: str
    context_window_size: int
    db_path: Optional[Path] = None

    # Memory hierarchy settings (infrastructure tax optimization)
    max_core_cache_size: int = 10  # Messages kept in RAM
    archival_search_limit: int = 5  # Max results from cold storage
    enable_deduplication: bool = True  # Prevent duplicate storage

    # Connection management (scale-to-zero optimization)
    connection_timeout: int = 300  # Seconds before closing idle DB connection
    enable_connection_pooling: bool = True

    # Context pruning (cost optimization)
    auto_prune_context: bool = True
    token_budget_safety_margin: float = 0.9  # Use 90% of budget

    # Cleanup settings (resource management)
    idle_timeout: int = 600  # Seconds before agent cleanup
    enable_auto_cleanup: bool = True

    # Monitoring
    enable_metrics: bool = True
    log_infrastructure_events: bool = True

    @classmethod
    def serverless(cls, agent_id: str) -> 'AgentConfig':
        """
        Optimized for serverless/FaaS environments (AWS Lambda, Cloud Functions).

        Infrastructure tax reduction focus:
        - Aggressive connection cleanup
        - Minimal in-memory footprint
        - Fast cold starts
        - Pay-per-use optimization
        """
        return cls(
            agent_id=agent_id,
            context_window_size=4000,  # Smaller for faster processing
            max_core_cache_size=5,  # Minimal RAM usage
            connection_timeout=120,  # Quick cleanup (2 min)
            idle_timeout=300,  # Scale to zero after 5 min
            enable_auto_cleanup=True,
            auto_prune_context=True,
            token_budget_safety_margin=0.85  # Conservative
        )

    @classmethod
    def long_running(cls, agent_id: str) -> 'AgentConfig':
        """
        Optimized for long-running services (Kubernetes, VMs).

        Infrastructure tax reduction focus:
        - Larger caches for performance
        - Longer connection timeouts
        - Balanced resource usage
        """
        return cls(
            agent_id=agent_id,
            context_window_size=8000,
            max_core_cache_size=50,  # Larger cache
            connection_timeout=1800,  # 30 min
            idle_timeout=3600,  # 1 hour
            enable_auto_cleanup=True,
            auto_prune_context=True,
            token_budget_safety_margin=0.95
        )

    @classmethod
    def development(cls, agent_id: str) -> 'AgentConfig':
        """
        Development configuration with verbose logging.
        """
        return cls(
            agent_id=agent_id,
            context_window_size=8000,
            max_core_cache_size=20,
            connection_timeout=600,
            idle_timeout=1800,
            enable_auto_cleanup=False,  # Manual cleanup for debugging
            enable_metrics=True,
            log_infrastructure_events=True
        )


# Deployment profiles
SERVERLESS_PROFILE = {
    "name": "Serverless (AWS Lambda, Cloud Functions)",
    "context_window": 4000,
    "cache_size": 5,
    "connection_timeout": 120,
    "idle_timeout": 300,
    "use_case": "Event-driven, infrequent requests, pay-per-use"
}

LONG_RUNNING_PROFILE = {
    "name": "Long-Running (Kubernetes, VMs)",
    "context_window": 8000,
    "cache_size": 50,
    "connection_timeout": 1800,
    "idle_timeout": 3600,
    "use_case": "Continuous operation, high request volume"
}

EDGE_PROFILE = {
    "name": "Edge Computing (CloudFlare Workers, Fastly)",
    "context_window": 2000,
    "cache_size": 3,
    "connection_timeout": 60,
    "idle_timeout": 180,
    "use_case": "Ultra-low latency, minimal compute resources"
}
