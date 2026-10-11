"""
Entrypoint for MCP Benchmark Server
"""
from mcp_servers.benchmark.server import server, main, benchmark_algorithm, compare_all_algorithms

__all__ = ["server", "main", "benchmark_algorithm", "compare_all_algorithms"]

if __name__ == "__main__":
    main()
