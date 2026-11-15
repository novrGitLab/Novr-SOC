"""python -m novrsoc_forwarder        run the service (systemd)
python -m novrsoc_forwarder --once run one cycle and exit (verification)
python -m novrsoc_forwarder --check validate configuration and connectivity, send nothing"""
from __future__ import annotations

import os
import signal
import sys

from .core import EXIT_FATAL, Config, Fatal, Forwarder, Retryable
from .http import Http
from .logs import log
from .state import LockError, State


def build(env) -> Forwarder:
    cfg = Config(env)
    state = State(cfg.state_dir)
    state.lock()
    return Forwarder(cfg, api=Http("api", cfg.api_ca, cfg.timeout), indexer=Http("indexer", cfg.indexer_ca, cfg.timeout),
                     manager=Http("manager", cfg.manager_ca, cfg.timeout), state=state)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        fwd = build(os.environ)
    except (Fatal, LockError) as e:
        log("error", "not_started", reason=str(e))
        return EXIT_FATAL
    if "--check" in argv:
        try:
            fwd.groups.refresh()
            fwd.search(fwd.now(), None, fwd.now(), 1)
            log("info", "check_ok", agents_known=len(fwd.groups.groups))
            return 0
        except (Fatal, Retryable) as e:
            log("error", "check_failed", reason=str(e))
            return EXIT_FATAL
    if "--once" in argv:
        try:
            log("info", "once_done", alerts=fwd.forward_once(1))
            return 0
        except Fatal as e:
            log("error", "stopped", reason=str(e))
            return EXIT_FATAL
        except Retryable as e:
            log("warning", "once_incomplete", reason=str(e))
            return 75  # EX_TEMPFAIL
    stopping = {"flag": False}

    def _stop(*_):
        stopping["flag"] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        return fwd.run(stop=lambda: stopping["flag"])
    finally:
        fwd.state.unlock()


if __name__ == "__main__":
    raise SystemExit(main())
