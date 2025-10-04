#!/bin/bash

queries=2000
concurrency=20

# Generate domain list using for loop
domains="www.baidu.com \
    github.com \
    www.google.com \
    www.ustc.edu.cn \
    wikipedia.org \
    mail.qq.com \
    csdiy.wiki
    mirrors.tuna.tsinghua.edu.cn"

python dns_benchmark.py --queries $queries --concurrency $concurrency --domains $domains
