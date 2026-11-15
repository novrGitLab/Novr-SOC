"""python -m novrsoc_ti --config /etc/novrsoc-ti/config.json [--once]   (PYTHONPATH must include packages/contracts/python)"""
import argparse
import json
import sys
import time

from .feeder import run_once


def log(event, fields):
    sys.stdout.write(json.dumps({"service": "novrsoc-ti", "event": event, **fields}) + "\n")
    sys.stdout.flush()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m novrsoc_ti")
    ap.add_argument("--config", required=True)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    while True:
        run_once(cfg, log)
        if args.once:
            return 0
        time.sleep(int(cfg.get("poll_seconds", 900)))


raise SystemExit(main())
