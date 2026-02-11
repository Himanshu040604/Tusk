"""
Advanced usage examples for persistent agents.

Demonstrates:
1. Integration with real LLM APIs (OpenAI, Anthropic)
2. Vector-based semantic search for archival memory
3. Multi-agent orchestration
4. Production monitoring and observability
5. Cost tracking and optimization
"""

import asyncio
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from persistent_agent import (
    PersistentAgent,
    AgentPool,
    Message,
    persistent_agent_session
)
from agent_config import AgentConfig


# Example 1: Integration with LLM API
class LLMIntegratedAgent(PersistentAgent):
    """
    Agent with real LLM integration.

    Infrastructure tax considerations:
    - Caching for repeated queries (reduce API costs)
    - Token counting for accurate budgeting
    - Error handling for API failures
    - Rate limiting for cost control
    """

    def __init__(
        self,
        agent_id: str,
        api_key: Optional[str] = None,
        model: str = "gpt-4",
        **kwargs
    ):
        super().__init__(agent_id, **kwargs)
        self.api_key = api_key
        self.model = model

        # Cost tracking (infrastructure tax monitoring)
        self._api_costs = {
            "total_tokens": 0,
            "total_cost_usd": 0.0,
            "request_count": 0
        }

    async def _generate_response(
        self,
        context: List[Message],
        current_message: str
    ) -> str:
        """
        Generate response using real LLM API.

        Replace this stub with actual API integration:
        - OpenAI: openai.ChatCompletion.create()
        - Anthropic: anthropic.messages.create()
        - Local: llama.cpp, vLLM, etc.
        """
        # Build conversation for LLM
        messages = [{"role": "system", "content": self.system_prompt}]
        messages.extend([
            {"role": msg.role, "content": msg.content}
            for msg in context
        ])

        # Stub: Replace with actual API call
        # Example OpenAI integration:
        # import openai
        # response = await openai.ChatCompletion.acreate(
        #     model=self.model,
        #     messages=messages,
        #     max_tokens=500
        # )
        # assistant_message = response.choices[0].message.content
        # self._track_api_usage(response.usage)

        # Simulated response
        assistant_message = (
            f"[Simulated {self.model} response]\n"
            f"Context size: {len(context)} messages\n"
            f"Query: {current_message[:100]}..."
        )

        # Track costs (stub)
        self._track_api_usage({
            "prompt_tokens": sum(len(m.content) // 4 for m in context),
            "completion_tokens": len(assistant_message) // 4,
            "total_tokens": sum(len(m.content) // 4 for m in context) + len(assistant_message) // 4
        })

        return assistant_message

    def _track_api_usage(self, usage: Dict[str, int]) -> None:
        """
        Track API costs for infrastructure tax monitoring.

        Cost estimation (as of 2025):
        - GPT-4: ~$0.03/1K prompt tokens, ~$0.06/1K completion tokens
        - Claude 3: ~$0.015/1K input, ~$0.075/1K output
        """
        self._api_costs["total_tokens"] += usage["total_tokens"]
        self._api_costs["request_count"] += 1

        # Rough cost estimate for GPT-4
        cost = (
            usage.get("prompt_tokens", 0) * 0.03 / 1000 +
            usage.get("completion_tokens", 0) * 0.06 / 1000
        )
        self._api_costs["total_cost_usd"] += cost

    async def get_cost_metrics(self) -> Dict[str, Any]:
        """Return infrastructure cost metrics."""
        metrics = await self.get_metrics()
        metrics["api_costs"] = self._api_costs
        return metrics


# Example 2: Semantic search with embeddings
class SemanticMemoryAgent(PersistentAgent):
    """
    Agent with vector-based semantic search.

    Infrastructure tax considerations:
    - Lazy embedding generation (only when needed)
    - Local embeddings vs API (cost tradeoff)
    - Efficient vector storage (FAISS, Annoy)
    """

    def __init__(self, agent_id: str, use_local_embeddings: bool = True, **kwargs):
        super().__init__(agent_id, **kwargs)
        self.use_local_embeddings = use_local_embeddings
        self._embedding_cache: Dict[str, List[float]] = {}

    async def _get_embedding(self, text: str) -> List[float]:
        """
        Generate embedding for semantic search.

        Infrastructure tax reduction:
        - Cache embeddings to avoid recomputation
        - Use local models (sentence-transformers) vs API

        Local option: sentence-transformers/all-MiniLM-L6-v2 (~80MB)
        API option: OpenAI embeddings, Cohere embeddings
        """
        # Check cache first
        if text in self._embedding_cache:
            return self._embedding_cache[text]

        # Stub: Replace with actual embedding generation
        # Local example:
        # from sentence_transformers import SentenceTransformer
        # model = SentenceTransformer('all-MiniLM-L6-v2')
        # embedding = model.encode(text).tolist()

        # API example:
        # import openai
        # response = await openai.Embedding.acreate(
        #     model="text-embedding-ada-002",
        #     input=text
        # )
        # embedding = response['data'][0]['embedding']

        # Simulated embedding (384 dimensions)
        embedding = [0.1] * 384

        # Cache result
        self._embedding_cache[text] = embedding

        return embedding

    async def semantic_search(self, query: str, top_k: int = 5) -> List[Message]:
        """
        Semantic search in archival memory using embeddings.

        Infrastructure tax reduction:
        - On-demand search (not always active)
        - Efficient vector similarity (cosine, dot product)
        - Could use FAISS for large-scale search
        """
        query_embedding = await self._get_embedding(query)

        # Fetch messages from archival
        all_messages = await self.memory.get_recent_messages(limit=100)

        # Compute similarity scores
        scored_messages = []
        for msg in all_messages:
            msg_embedding = await self._get_embedding(msg.content)
            similarity = self._cosine_similarity(query_embedding, msg_embedding)
            scored_messages.append((similarity, msg))

        # Sort by similarity and return top-k
        scored_messages.sort(reverse=True, key=lambda x: x[0])
        return [msg for _, msg in scored_messages[:top_k]]

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot_product = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x ** 2 for x in a) ** 0.5
        norm_b = sum(x ** 2 for x in b) ** 0.5
        return dot_product / (norm_a * norm_b) if norm_a and norm_b else 0.0


# Example 3: Multi-agent orchestration with task delegation
class MultiAgentOrchestrator:
    """
    Orchestrate multiple specialized agents.

    Infrastructure tax considerations:
    - Lazy agent instantiation (only create when needed)
    - Shared resource pools (DB connections, embedding models)
    - Load balancing across agents
    - Automatic cleanup of idle agents
    """

    def __init__(self):
        self.pool = AgentPool(idle_timeout=600)
        self._agent_specializations = {
            "general": "You are a general-purpose assistant.",
            "technical": "You are a technical expert in software engineering.",
            "creative": "You are a creative writing assistant."
        }

    async def route_message(
        self,
        user_id: str,
        message: str,
        specialization: str = "general"
    ) -> str:
        """
        Route message to appropriate specialized agent.

        Infrastructure tax reduction:
        - Agents created on-demand
        - Automatic cleanup after idle period
        - Shared persistence layer
        """
        system_prompt = self._agent_specializations.get(
            specialization,
            self._agent_specializations["general"]
        )

        agent_id = f"{user_id}_{specialization}"
        agent = await self.pool.get_agent(
            agent_id,
            system_prompt=system_prompt
        )

        return await agent.process_message(message)

    async def get_system_metrics(self) -> Dict[str, Any]:
        """
        Aggregate metrics across all active agents.

        Useful for infrastructure monitoring and cost tracking.
        """
        metrics = {
            "active_agents": len(self.pool._agents),
            "agent_details": []
        }

        for agent_id, agent in self.pool._agents.items():
            agent_metrics = await agent.get_metrics()
            metrics["agent_details"].append({
                "agent_id": agent_id,
                **agent_metrics
            })

        return metrics

    async def cleanup(self) -> None:
        """Cleanup all agents."""
        await self.pool.cleanup_all()


# Example 4: Production monitoring
class MonitoredAgent(PersistentAgent):
    """
    Agent with comprehensive observability.

    Infrastructure tax monitoring:
    - Request latency tracking
    - Resource usage monitoring
    - Cost attribution
    - Error rate tracking
    """

    def __init__(self, agent_id: str, **kwargs):
        super().__init__(agent_id, **kwargs)
        self._performance_metrics = {
            "request_latencies": [],
            "error_count": 0,
            "cache_hit_rate": 0.0
        }

    async def process_message(self, user_message: str) -> str:
        """Process message with performance tracking."""
        start_time = asyncio.get_event_loop().time()

        try:
            response = await super().process_message(user_message)

            # Track latency
            latency = asyncio.get_event_loop().time() - start_time
            self._performance_metrics["request_latencies"].append(latency)

            # Trim to last 100 requests
            if len(self._performance_metrics["request_latencies"]) > 100:
                self._performance_metrics["request_latencies"] = \
                    self._performance_metrics["request_latencies"][-100:]

            return response

        except Exception as e:
            self._performance_metrics["error_count"] += 1
            raise

    async def get_performance_report(self) -> Dict[str, Any]:
        """Generate infrastructure performance report."""
        latencies = self._performance_metrics["request_latencies"]

        report = {
            "agent_id": self.agent_id,
            "timestamp": datetime.now().isoformat(),
            "performance": {
                "avg_latency_ms": sum(latencies) / len(latencies) * 1000 if latencies else 0,
                "p95_latency_ms": sorted(latencies)[int(len(latencies) * 0.95)] * 1000 if latencies else 0,
                "total_requests": len(latencies),
                "error_rate": self._performance_metrics["error_count"] / max(len(latencies), 1)
            },
            "infrastructure": await self.get_metrics()
        }

        return report


# Usage examples
async def example_llm_integration():
    """Example: Agent with LLM API integration."""
    print("\n=== Example 1: LLM Integration ===")

    config = AgentConfig.serverless("llm_agent")
    agent = LLMIntegratedAgent(
        agent_id=config.agent_id,
        model="gpt-4",
        context_window_size=config.context_window_size
    )

    await agent.initialize()

    # Simulate conversation
    await agent.process_message("Explain infrastructure tax in AI systems")
    await agent.process_message("How can we reduce it?")

    # Check costs
    cost_metrics = await agent.get_cost_metrics()
    print(f"Cost metrics: {json.dumps(cost_metrics['api_costs'], indent=2)}")

    await agent.cleanup()


async def example_semantic_search():
    """Example: Semantic search in archival memory."""
    print("\n=== Example 2: Semantic Search ===")

    agent = SemanticMemoryAgent("semantic_agent")
    await agent.initialize()

    # Add some messages
    await agent.process_message("Tell me about machine learning")
    await agent.process_message("What is deep learning?")
    await agent.process_message("Explain neural networks")

    # Semantic search
    results = await agent.semantic_search("AI and neural nets", top_k=2)
    print(f"Found {len(results)} semantically similar messages")

    for i, msg in enumerate(results, 1):
        print(f"{i}. {msg.content[:100]}...")

    await agent.cleanup()


async def example_multi_agent():
    """Example: Multi-agent orchestration."""
    print("\n=== Example 3: Multi-Agent Orchestration ===")

    orchestrator = MultiAgentOrchestrator()

    # Route to different specialized agents
    response1 = await orchestrator.route_message(
        "user_123",
        "Write a poem about clouds",
        specialization="creative"
    )
    print(f"Creative agent: {response1[:100]}...")

    response2 = await orchestrator.route_message(
        "user_123",
        "Explain async/await in Python",
        specialization="technical"
    )
    print(f"Technical agent: {response2[:100]}...")

    # System-wide metrics
    metrics = await orchestrator.get_system_metrics()
    print(f"\nSystem metrics: {metrics['active_agents']} active agents")

    await orchestrator.cleanup()


async def example_monitoring():
    """Example: Production monitoring."""
    print("\n=== Example 4: Production Monitoring ===")

    agent = MonitoredAgent("monitored_agent")
    await agent.initialize()

    # Simulate load
    for i in range(10):
        await agent.process_message(f"Request {i}")

    # Performance report
    report = await agent.get_performance_report()
    print(f"\nPerformance Report:")
    print(f"- Avg Latency: {report['performance']['avg_latency_ms']:.2f}ms")
    print(f"- P95 Latency: {report['performance']['p95_latency_ms']:.2f}ms")
    print(f"- Error Rate: {report['performance']['error_rate']:.2%}")

    await agent.cleanup()


async def main():
    """Run all advanced examples."""
    await example_llm_integration()
    await example_semantic_search()
    await example_multi_agent()
    await example_monitoring()

    print("\n=== All Examples Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
