#!/bin/bash

queries=10000
concurrency=20

# Generate domain list using for loop
domains=""
for i in {1..16}; do
    domains+="www.test${i}.com "
done

python dns_benchmark.py --queries $queries --concurrency $concurrency --domains $domains