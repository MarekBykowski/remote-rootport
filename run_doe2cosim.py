#!/usr/bin/env python3

import argparse
import glob
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

PIPE_DIR = Path(os.environ.get("CXL_RELAY_SERVER_PATH", "/tmp/cxl_relay_pipes"))
PCI_DEV  = "0000:00:04.0"


# ------------------------------------------------------------
# Service definition
# ------------------------------------------------------------

@dataclass
class Service:
    name:     str
    cmd:      list[str]
    deps:     list[str]
    is_ready: Callable[["Service"], bool]
    proc:     subprocess.Popen | None = field(default=None, repr=False)

    def start(self, env: dict):
        print(f"Starting {self.name} ...")
        self.proc = subprocess.Popen(self.cmd, env=env)
        print(f"  {self.name} pid={self.proc.pid}, waiting for ready ...")
        while not self.is_ready(self):
            time.sleep(0.2)
        print(f"  {self.name} ready")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


# ------------------------------------------------------------
# Readiness probes
# ------------------------------------------------------------

def _tcp_state(port_hex: str, state_hex: str) -> bool:
    try:
        for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
            parts = line.split()
            # local_address is parts[1], state is parts[3]
            if parts[1].endswith(f":{port_hex.upper()}") and parts[3] == state_hex.upper():
                return True
    except OSError:
        pass
    return False

def ready_daemon(svc: Service) -> bool:
    return _tcp_state("15B3", "0A")          # :5555 LISTEN

def ready_thin_srv(svc: Service) -> bool:
    return bool(glob.glob(str(PIPE_DIR / "doe_*")))   # pipes created

def ready_doe_emu(svc: Service) -> bool:
    if svc.proc is None:
        return False
    try:
        for fd in Path(f"/proc/{svc.proc.pid}/fd").iterdir():
            if str(PIPE_DIR) in str(fd.resolve()):
                return True
    except OSError:
        pass
    return False


# ------------------------------------------------------------
# Service registry — declared in start order
# ------------------------------------------------------------

def build_services(mechanism: str) -> list[Service]:
    daemon_cmd = {
        "netlink": ["./daemon-doe-netlink"],
        "chardev": ["./daemon-doe"],
    }[mechanism]

    return [
        Service("daemon",   daemon_cmd,       deps=[],          is_ready=ready_daemon),
        Service("thin_srv", ["./thin-server"], deps=["daemon"],  is_ready=ready_thin_srv),
        Service("doe_emu",  ["./doe-emu"],     deps=["thin_srv"],is_ready=ready_doe_emu),
    ]


# ------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------

def start_all(services: list[Service], env: dict):
    started = {}
    for svc in services:
        for dep in svc.deps:
            if dep not in started:
                sys.exit(f"ERROR: cannot start '{svc.name}' — dependency '{dep}' is not running")
        svc.start(env)
        started[svc.name] = svc

def stop_all(services: list[Service]):
    print("Stopping processes")
    for svc in reversed(services):
        svc.stop()


def proc_write(path: str, value: str):
    print(f"  {path} <- {value!r}")
    Path(path).write_text(value)


# ------------------------------------------------------------
# Commands
# ------------------------------------------------------------

def cmd_redirect(mechanism: str):
    if mechanism not in ("netlink", "chardev"):
        sys.exit(f"Unknown mechanism '{mechanism}' — use netlink or chardev")

    # Fix interpreter for linux-cxl-apps built with a foreign toolchain
    lib64 = Path("/lib64")
    lib64.mkdir(exist_ok=True)
    link = lib64 / "ld-linux-x86-64.so.2"
    if not link.exists():
        link.symlink_to("/lib/ld-linux-x86-64.so.2")

    print("Redirect DOE to Remote RC")
    proc_write("/proc/cosim_doe_redirect", "1")
    print(Path("/proc/cosim_doe_redirect").read_text(), end="")

    print(f"Set DOE backend: {mechanism}")
    proc_write("/proc/cosim_doe_backend", mechanism)
    print(Path("/proc/cosim_doe_backend").read_text(), end="")

    PIPE_DIR.mkdir(parents=True, exist_ok=True)

    services = build_services(mechanism)
    env = {**os.environ, "CXL_RELAY_SERVER_PATH": str(PIPE_DIR)}

    def _shutdown(sig, frame):
        stop_all(services)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        start_all(services, env)

        print("Remove native rootport")
        proc_write(f"/sys/bus/pci/devices/{PCI_DEV}/remove", "1")
        time.sleep(1)

        print("Rescan PCI bus")
        proc_write("/sys/bus/pci/rescan", "1")
    finally:
        stop_all(services)

    print("Done")


def cmd_native():
    print("Remove native rootport")
    proc_write(f"/sys/bus/pci/devices/{PCI_DEV}/remove", "1")
    time.sleep(1)
    print("Rescan PCI bus")
    proc_write("/sys/bus/pci/rescan", "1")


# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DOE-to-cosim orchestrator")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("native", help="Remove native rootport and rescan")

    p_redirect = sub.add_parser("redirect", help="Start relay stack and redirect DOE")
    p_redirect.add_argument("mechanism", choices=["netlink", "chardev"])

    args = parser.parse_args()

    if args.command == "native":
        cmd_native()
    elif args.command == "redirect":
        cmd_redirect(args.mechanism)


if __name__ == "__main__":
    main()
