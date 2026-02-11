"""
Quick Start Script: Persistent AI Agent

Demonstrates basic usage in <10 lines of code.
Run this to verify installation and understand core concepts.
"""

import asyncio
from persistent_agent import persistent_agent_session


async def main():
    """
    Minimal example: Create agent, send messages, automatic cleanup.
    """
    print("=== Persistent Agent Quick Start ===\n")

    # Context manager handles initialization and cleanup automatically
    async with persistent_agent_session("quickstart_demo") as agent:
        print("Agent initialized. Sending messages...\n")

        # Send first message
        response1 = await agent.process_message(
            "What is infrastructure tax in AI systems?"
        )
        print(f"Response 1:\n{response1}\n")

        # Send follow-up message (agent maintains context)
        response2 = await agent.process_message(
            "How does this implementation reduce it?"
        )
        print(f"Response 2:\n{response2}\n")

        # Check agent metrics
        metrics = await agent.get_metrics()
        print(f"Agent Metrics:")
        print(f"  Total messages processed: {metrics['total_messages']}")
        print(f"  Cold starts: {metrics['cold_starts']}")
        print(f"  Context prunes: {metrics['context_prunes']}")

    print("\nAgent cleaned up. State persisted to disk.")
    print("Run this script again to see the agent recover its state!\n")


if __name__ == "__main__":
    asyncio.run(main())
