"""Calculates statistics for the numbers entered in the CLI"""

import argparse
from statistics import mean, median, stdev

parser = argparse.ArgumentParser(description="Numbers to analyze")

parser.add_argument("numbers", nargs="+", type=float)

group = parser.add_mutually_exclusive_group(required=True)

group.add_argument("--sum", dest="op", action="store_const", const="sum")
group.add_argument("--mean", dest="op", action="store_const", const="mean")
group.add_argument("--median", dest="op", action="store_const", const="median")
group.add_argument("--min", dest="op", action="store_const", const="min")
group.add_argument("--max", dest="op", action="store_const", const="max")
group.add_argument("--std", dest="op", action="store_const", const="std")

args = parser.parse_args()

if args.op == "sum":
    output = sum(args.numbers)
elif args.op == "mean":
    output = mean(args.numbers)
elif args.op == "median":
    output = median(args.numbers)
elif args.op == "min":
    output = min(args.numbers)
elif args.op == "max":
    output = max(args.numbers)
else:
    output = stdev(args.numbers)


print(f"Output: {output:.2f}")
