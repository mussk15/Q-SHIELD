"""Bounded local connection-rate test; not a denial-of-service tool."""
import argparse
import socket
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--count", type=int, default=35)
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("Safety guard: this generator only permits loopback targets.")
    if not 1 <= args.count <= 100:
        parser.error("--count must be between 1 and 100")
    if args.delay < 0.02:
        parser.error("--delay must be at least 0.02 seconds")

    successes = 0
    for _ in range(args.count):
        try:
            with socket.create_connection((args.host, args.port), timeout=1):
                successes += 1
        except OSError:
            pass
        time.sleep(args.delay)

    print(f"Completed {args.count} bounded attempts; connected={successes}")


if __name__ == "__main__":
    main()
