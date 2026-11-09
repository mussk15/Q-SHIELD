"""Generate a small amount of ordinary HTTP traffic to a local demo server."""
import argparse
import time
from urllib.request import urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.25)
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("Safety guard: normal traffic generator only permits loopback.")
    if not 1 <= args.requests <= 100:
        parser.error("--requests must be between 1 and 100")

    url = f"http://{args.host}:{args.port}/"
    for _ in range(args.requests):
        try:
            with urlopen(url, timeout=2) as response:
                response.read(128)
        except Exception as exc:
            print(f"Request failed: {exc}")
        time.sleep(args.delay)
    print(f"Generated {args.requests} bounded HTTP requests to {url}")


if __name__ == "__main__":
    main()
