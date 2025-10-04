#!/usr/bin/env python3
import dns.resolver
import time
import statistics
import argparse
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
import sys

class DNSBenchmark:
    def __init__(self, dns_server: str, port: int = 53):
        """Initialize DNS benchmark with target server."""
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = [dns_server]
        self.resolver.port = port
        self.results: List[Dict] = []

    def query_domain(self, domain: str) -> Dict:
        """Make a single DNS query and return timing results."""
        start_time = time.time()
        try:
            self.resolver.resolve(domain, 'A')
            end_time = time.time()
            return {
                'domain': domain,
                'success': True,
                'time': (end_time - start_time) * 1000,  # Convert to milliseconds
                'error': None
            }
        except Exception as e:
            end_time = time.time()
            return {
                'domain': domain,
                'success': False,
                'time': (end_time - start_time) * 1000,
                'error': str(e)
            }

    def run_benchmark(self, domains: List[str], num_queries: int, concurrency: int) -> None:
        """Run the benchmark with specified parameters."""
        print(f"\nStarting DNS benchmark...")
        print(f"Target DNS Server: {self.resolver.nameservers[0]}:{self.resolver.port}")
        print(f"Number of queries: {num_queries}")
        print(f"Concurrency level: {concurrency}")
        print(f"Number of unique domains: {len(domains)}\n")

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            # Generate queries by cycling through domains
            queries = [(domains[i % len(domains)]) for i in range(num_queries)]
            self.results = list(executor.map(self.query_domain, queries))

    def print_results(self) -> None:
        """Print benchmark results."""
        successful_queries = [r for r in self.results if r['success']]
        failed_queries = [r for r in self.results if not r['success']]
        
        response_times = [r['time'] for r in successful_queries]
        
        print("\nBenchmark Results:")
        print("=" * 50)
        print(f"Total Queries:     {len(self.results)}")
        print(f"Successful:        {len(successful_queries)}")
        print(f"Failed:            {len(failed_queries)}")
        print(f"Success Rate:      {len(successful_queries)/len(self.results)*100:.2f}%")
        
        if response_times:
            print(f"\nTiming Statistics (ms):")
            print(f"Average:           {statistics.mean(response_times):.2f}")
            print(f"Median:            {statistics.median(response_times):.2f}")
            print(f"Min:               {min(response_times):.2f}")
            print(f"Max:               {max(response_times):.2f}")
            print(f"Std Dev:           {statistics.stdev(response_times):.2f}")
        
        if failed_queries:
            print("\nError Distribution:")
            error_counts = {}
            for query in failed_queries:
                error_counts[query['error']] = error_counts.get(query['error'], 0) + 1
            for error, count in error_counts.items():
                print(f"{error}: {count}")

def main():
    parser = argparse.ArgumentParser(description='DNS Server Benchmark Tool')
    parser.add_argument('--server', default='127.0.0.1',
                        help='DNS server IP address (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=53,
                        help='DNS server port (default: 53)')
    parser.add_argument('--queries', type=int, default=200,
                        help='Number of queries to perform (default: 200)')
    parser.add_argument('--concurrency', type=int, default=20,
                        help='Number of concurrent queries (default: 20)')
    parser.add_argument('--domains', nargs='+', default=['google.com', 'github.com', 'microsoft.com'],
                        help='List of domains to query (default: google.com github.com microsoft.com)')
    
    args = parser.parse_args()
    
    benchmark = DNSBenchmark(args.server, args.port)
    try:
        benchmark.run_benchmark(args.domains, args.queries, args.concurrency)
        benchmark.print_results()
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during benchmark: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
