"""
    The network tripwire: airgap plan L4 (diy-seedsigner
    docs/security/software-enforced-airgap-plan.md), story
    multi-chain-radio-detect-auto-lockdown.

    The production image has no way onto a network: its kernel has no IP,
    unix or packet sockets, no network, Wi-Fi, Bluetooth or USB-gadget
    drivers and no loadable modules, and the radios are switched off in
    config.txt. This module checks, from inside the running app, that the
    device really is in that state, and stops it if not:
    - at boot, before any seed can be entered (boot_gate);
    - every POLL_SECONDS in a background thread (TripwireMonitor);
    - immediately before every key derivation and signature (assert_clean,
      called by the signing code itself).

    A trip is final for this power-on: it latches, the trip handler wipes
    the seeds from memory, draws a warning with no buttons and ends the
    process, and nothing restarts the app. The gates raise
    NetworkTripwireTripped, a BaseException, so no `except Exception` on the
    way can turn it into an ordinary refusal.

    What this cannot do: it runs inside the image it checks. It catches a
    mistake on a genuine image (the dev image on a Root-key unit, the wrong
    card, radios left on, a USB device plugged in). It cannot catch a
    hostile image or a kernel that lies about its devices; the build itself
    and checking the image's hash before flashing are what protect against
    those.

    Modes, chosen from facts in the image, never from a setting:
    - ENFORCE on a Raspberry Pi running anything but the dev image;
    - WARN on the dev image (hostname seedsigner-dev), which has Wi-Fi and
      USB networking on purpose: nothing trips, but 7F mainnet keys are
      refused (Jorge, 2026-10-09);
    - OFF off a Pi (desktop, CI).
"""
from __future__ import annotations

import gzip
import logging
import re
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from seedsigner.models.threads import BaseThread

logger = logging.getLogger(__name__)

OFF, WARN, ENFORCE = "off", "warn", "enforce"

POLL_SECONDS = 0.25
MONITOR_STALE_SECONDS = 2.0
ARPHRD_LOOPBACK = 772
DEV_IMAGE_HOSTNAME = "seedsigner-dev"
TEST_NETWORKS = ("testnet", "devnet")

TRANSPORTS = ("tcp", "tcp6", "udp", "udp6", "raw", "raw6", "packet", "unix")
RADIO_CLASSES = ("ieee80211", "bluetooth", "rfkill", "udc")
KERNEL_OPTIONS_REFUSED = (
    "CONFIG_INET", "CONFIG_UNIX", "CONFIG_PACKET", "CONFIG_NETDEVICES", "CONFIG_CFG80211",
    "CONFIG_MAC80211", "CONFIG_BT", "CONFIG_RFKILL", "CONFIG_USB_GADGET", "CONFIG_USB_USBNET",
    "CONFIG_MODULES",
)
# main.py --tripwire=enforce sets this before the Controller is made.
force_enforce_requested = False

_ROOT_HUB = re.compile(r"usb\d+")
_KERNEL_OPTION = re.compile(r"(CONFIG_[A-Z0-9_]+)=(.*)")


class NetworkTripwireTripped(BaseException):
    """ The device found a way onto a network. Not an Exception, so that no
        `except Exception` between a gate and the controller can catch it. """


class NetworkCapableImageRefusal(Exception):
    """ The dev image (WARN) refusing a 7F mainnet key. An ordinary
        refusal: the flow shows it and goes back. """


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}" if self.detail else self.code


# --- reading /sys and /proc ---------------------------------------------------

def _entries(path: Path) -> list[str]:
    """ The names in a directory; none if it does not exist (the release
        kernel lacks most of these directories, which is the clean state). """
    if not path.is_dir():
        return []
    return sorted(p.name for p in path.iterdir())


def _read(path: Path) -> str:
    return path.read_text().strip()


def _read_or(path: Path, default: str = "?") -> str:
    try:
        return _read(path)
    except OSError:
        return default


# --- the checks: each takes the filesystem root and returns its findings ------

def check_interfaces(root: Path) -> list[Finding]:
    """ Only `lo` may exist, it must really be a loopback, and nothing may
        have crossed it (without IP, unix or packet sockets nothing can). """
    net = root / "sys/class/net"
    findings = [Finding("extra_interface", name) for name in _entries(net) if name != "lo"]
    lo = net / "lo"
    if lo.is_dir():
        if int(_read(lo / "type")) != ARPHRD_LOOPBACK:
            findings.append(Finding("loopback_impersonation", "lo"))
        for stat in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
            if int(_read(lo / "statistics" / stat)) != 0:
                findings.append(Finding("loopback_traffic", stat))
                break
    return findings


def check_proc_net_dev(root: Path) -> list[Finding]:
    """ The kernel's second list of interfaces: one hidden from sysfs alone
        still shows here. """
    dev = root / "proc/net/dev"
    if not dev.exists():
        return []
    names = [line.split(":", 1)[0].strip() for line in dev.read_text().splitlines() if ":" in line]
    return [Finding("procfs_interface", name) for name in names if name != "lo"]


def check_transports(root: Path) -> list[Finding]:
    """ /proc/net/<transport> exists only if the kernel has that transport. """
    return [Finding("transport_present", t) for t in TRANSPORTS if (root / "proc/net" / t).exists()]


def check_radio_classes(root: Path) -> list[Finding]:
    return [Finding("radio_class", f"{cls}/{name}")
            for cls in RADIO_CLASSES for name in _entries(root / "sys/class" / cls)]


def check_sdio(root: Path) -> list[Finding]:
    """ The Wi-Fi/Bluetooth chip sits on SDIO; with the radios switched off
        in config.txt the bus is empty. """
    return [Finding("sdio_device", name) for name in _entries(root / "sys/bus/sdio/devices")]


def check_usb(root: Path) -> list[Finding]:
    """ Any USB device but a root hub: the device needs none (Jorge,
        2026-10-09), and a USB keyboard or network adapter is a way in.
        Entries with a colon are a device's interfaces; its device entry is
        what is reported. """
    devices = root / "sys/bus/usb/devices"
    return [Finding("usb_device", f"{name} class {_read_or(devices / name / 'bDeviceClass')} "
                                  f"{_read_or(devices / name / 'idVendor')}:{_read_or(devices / name / 'idProduct')}")
            for name in _entries(devices) if ":" not in name and not _ROOT_HUB.fullmatch(name)]


SWEEP_CHECKS: tuple[Callable[[Path], list[Finding]], ...] = (
    check_interfaces, check_proc_net_dev, check_transports, check_radio_classes, check_sdio, check_usb,
)


def sweep(root: Path) -> list[Finding]:
    """ Every check that can change while the device runs. A check that
        fails is a finding: an unreadable state is not a clean one. """
    findings: list[Finding] = []
    for check in SWEEP_CHECKS:
        try:
            findings += check(root)
        except Exception as e:
            findings.append(Finding("check_failed", f"{getattr(check, '__name__', check)}: {type(e).__name__}"))
    return findings


def check_kernel_config(root: Path) -> list[Finding]:
    """ What the running kernel was built with (/proc/config.gz): any
        network capability at all, or a way to load one later. """
    path = root / "proc/config.gz"
    if not path.exists():
        return [Finding("kernel_config_missing")]
    try:
        text = gzip.decompress(path.read_bytes()).decode("utf-8", "replace")
    except (OSError, EOFError, zlib.error):
        return [Finding("kernel_config_unreadable")]
    built = dict(m.groups() for m in map(_KERNEL_OPTION.fullmatch, text.splitlines()) if m)
    return [Finding("kernel_option", f"{name}={built[name]}")
            for name in KERNEL_OPTIONS_REFUSED if built.get(name) in ("y", "m")]


def detect_mode(root: Path = Path("/"), force_enforce: bool = False) -> str:
    """ ENFORCE, WARN or OFF, from the image itself. `force_enforce` (main.py
        --tripwire=enforce) can raise the dev image to ENFORCE for testing;
        nothing lowers ENFORCE. """
    try:
        model = (root / "proc/device-tree/model").read_text().rstrip("\x00\n")
    except OSError:
        return OFF
    if not model.startswith("Raspberry Pi"):
        return OFF
    if force_enforce:
        return ENFORCE
    return WARN if _read_or(root / "etc/hostname", default="") == DEV_IMAGE_HOSTNAME else ENFORCE


def network_of_path(path: str) -> str:
    """ A 7F derivation path's network: its second segment
        (<role>/<chain-kind>/...), or "" if it has none. """
    parts = path.split("/")
    return parts[1] if len(parts) > 1 else ""


# --- the tripwire's state -----------------------------------------------------

class _State:
    def __init__(self) -> None:
        self.mode = OFF
        self.root = Path("/")
        self.on_trip: Callable[[list[Finding]], None] | None = None
        self.tripped = threading.Event()
        self.findings: list[Finding] = []
        self.kernel_findings: list[Finding] | None = None
        self.heartbeat: float | None = None
        self.lock = threading.Lock()


_state = _State()


def configure(mode: str, root: Path = Path("/"), on_trip: Callable[[list[Finding]], None] | None = None) -> None:
    """ Set the mode and the trip handler, with fresh state (a new process;
        also each test). """
    global _state
    state = _State()
    state.mode, state.root, state.on_trip = mode, root, on_trip
    _state = state


def mode() -> str:
    return _state.mode


def is_tripped() -> bool:
    return _state.tripped.is_set()


def trip(found: list[Finding]) -> None:
    """ Latch, run the trip handler once (on the device it wipes, warns and
        ends the process), and raise. Never returns. """
    state = _state
    with state.lock:
        first = not state.tripped.is_set()
        state.tripped.set()
        if first:
            state.findings = list(found)
    if first:
        logger.critical("Network tripwire: %s", "; ".join(map(str, found)))
        if state.on_trip is not None:
            try:
                state.on_trip(list(found))
            except Exception:
                logger.exception("Network tripwire: the trip handler failed; the gates stay closed")
    raise NetworkTripwireTripped("; ".join(map(str, state.findings)))


def _kernel_findings(state: _State) -> list[Finding]:
    if state.kernel_findings is None:
        state.kernel_findings = check_kernel_config(state.root)
    return state.kernel_findings


def boot_gate() -> None:
    """ Before anything else runs: the kernel's build and the device's
        current state. """
    state = _state
    if state.mode == WARN:
        logger.warning("Network tripwire: dev image, networking expected; 7F mainnet keys are refused")
    if state.mode != ENFORCE:
        return
    found = _kernel_findings(state) + sweep(state.root)
    if found:
        trip(found)


def assert_clean(network: str | None = None) -> None:
    """ The gate before a secret is used. `network` is the 7F network the key
        belongs to, when there is one: the dev image refuses mainnet. """
    state = _state
    if state.mode == WARN:
        if network is not None and network not in TEST_NETWORKS:
            raise NetworkCapableImageRefusal(
                "This is the development image, which has networking. It does not use mainnet keys.")
        return
    if state.mode != ENFORCE:
        return
    if state.tripped.is_set():
        raise NetworkTripwireTripped("; ".join(map(str, state.findings)))
    found = _kernel_findings(state) + sweep(state.root)
    if state.heartbeat is not None and time.monotonic() - state.heartbeat > MONITOR_STALE_SECONDS:
        found.append(Finding("monitor_stalled", f"{time.monotonic() - state.heartbeat:.1f}s"))
    if found:
        trip(found)


class TripwireMonitor(BaseThread):
    """ Sweeps every POLL_SECONDS and trips on the first finding. Its
        heartbeat lets assert_clean see a monitor that died or stalled. """
    def run(self) -> None:
        state = _state
        while self.keep_running and state is _state:
            found = sweep(state.root)
            state.heartbeat = time.monotonic()
            if found or state.tripped.is_set():
                try:
                    trip(found or state.findings)
                except NetworkTripwireTripped:
                    return
            time.sleep(POLL_SECONDS)


def start_monitor() -> TripwireMonitor | None:
    """ The background sweep, in ENFORCE only. """
    if _state.mode != ENFORCE:
        return None
    _state.heartbeat = time.monotonic()
    monitor = TripwireMonitor()
    monitor.start()
    return monitor
