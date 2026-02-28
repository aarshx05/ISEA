import asyncio
import os
from agent.forensic_agent import ForensicAgent
from core.cluster_scanner import ClusterScanner

def test():
    scanner = ClusterScanner("uploads/8543ce7d/test_sample.img")
    result = scanner.run_full_scan()
    agent = ForensicAgent(result, scanner)
    
    # This query triggered the tool_use_failed error in the issue
    print("Testing agent...")
    response = agent.chat("Which directory has highest destruction?")
    print(f"\nFinal response: {response}")

if __name__ == "__main__":
    test()
