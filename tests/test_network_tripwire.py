"""
    The network tripwire (models/network_tripwire.py; story
    multi-chain-radio-detect-auto-lockdown, airgap plan L4), checked against
    fake /sys and /proc trees. Each case names the finding it expects, so a
    test cannot pass for the wrong reason.
"""
import gzip
import shutil
import threading
import time
from pathlib import Path

import pytest

import base  # noqa: F401  (hardware and display stand-ins, as every view test)
from seedsigner.models import network_tripwire as nt


# --- fake trees -------------------------------------------------------------

def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def make_iface(root: Path, name: str, *, type_: int = 1, rx_bytes: int = 0, tx_bytes: int = 0) -> None:
    d = root / "sys/class/net" / name
    _write(d / "type", f"{type_}\n")
    for stat, value in (("rx_bytes", rx_bytes), ("tx_bytes", tx_bytes), ("rx_packets", 0), ("tx_packets", 0)):
        _write(d / "statistics" / stat, f"{value}\n")


def write_proc_net_dev(root: Path, names) -> None:
    lines = ["Inter-|   Receive", " face |bytes    packets"]
    lines += [f"{n:>6}:       0       0    0    0    0     0          0         0        0       0" for n in names]
    _write(root / "proc/net/dev", "\n".join(lines) + "\n")


def make_usb(root: Path, name: str, *, cls: str = "09", vendor: str = "1d6b", product: str = "0002") -> None:
    d = root / "sys/bus/usb/devices" / name
    _write(d / "bDeviceClass", f"{cls}\n")
    _write(d / "idVendor", f"{vendor}\n")
    _write(d / "idProduct", f"{product}\n")


def write_config_gz(root: Path, options: dict) -> None:
    lines = ["# Linux/arm kernel configuration"]
    for name, value in options.items():
        lines.append(f"# {name} is not set" if value is None else f"{name}={value}")
    (root / "proc").mkdir(parents=True, exist_ok=True)
    (root / "proc/config.gz").write_bytes(gzip.compress(("\n".join(lines) + "\n").encode()))


RELEASE_KERNEL = {"CONFIG_NET": "y", **{name: None for name in nt.KERNEL_OPTIONS_REFUSED}}


@pytest.fixture
def release(tmp_path: Path) -> Path:
    """ What the production image shows: lo only, no transports, no radios,
        the root hub only, and a kernel built without any network driver. """
    make_iface(tmp_path, "lo", type_=nt.ARPHRD_LOOPBACK)
    write_proc_net_dev(tmp_path, ["lo"])
    make_usb(tmp_path, "usb1")
    (tmp_path / "sys/bus/usb/devices/1-0:1.0").mkdir(parents=True)
    (tmp_path / "sys/bus/sdio/devices").mkdir(parents=True)
    write_config_gz(tmp_path, RELEASE_KERNEL)
    _write(tmp_path / "proc/device-tree/model", "Raspberry Pi Zero 2 W Rev 1.0\x00")
    _write(tmp_path / "etc/hostname", "seedsigner-os\n")
    return tmp_path


def codes(findings) -> list[str]:
    return [f.code for f in findings]


# --- the checks -------------------------------------------------------------

class TestChecks:
    def test_the_release_image_is_clean(self, release):
        assert nt.sweep(release) == []
        assert nt.check_kernel_config(release) == []


    def test_an_extra_interface_is_found_in_sysfs_and_procfs(self, release):
        make_iface(release, "wlan0")
        write_proc_net_dev(release, ["lo", "wlan0"])
        found = nt.sweep(release)
        assert codes(found) == ["extra_interface", "procfs_interface"]
        assert found[0].detail == "wlan0"


    def test_an_interface_hidden_from_sysfs_is_still_found_in_procfs(self, release):
        write_proc_net_dev(release, ["lo", "usb0"])
        assert codes(nt.sweep(release)) == ["procfs_interface"]


    def test_a_device_named_lo_that_is_not_a_loopback_is_found(self, release):
        _write(release / "sys/class/net/lo/type", "1\n")
        assert codes(nt.sweep(release)) == ["loopback_impersonation"]


    def test_traffic_on_lo_is_found(self, release):
        _write(release / "sys/class/net/lo/statistics/tx_bytes", "1\n")
        assert codes(nt.sweep(release)) == ["loopback_traffic"]


    @pytest.mark.parametrize("transport", ["tcp", "tcp6", "udp", "udp6", "raw", "raw6", "packet", "unix"])
    def test_a_network_transport_is_found_by_its_proc_file(self, release, transport):
        _write(release / "proc/net" / transport, "  sl  local_address\n")
        found = nt.sweep(release)
        assert codes(found) == ["transport_present"]
        assert found[0].detail == transport


    @pytest.mark.parametrize("cls", ["ieee80211", "bluetooth", "rfkill", "udc"])
    def test_a_radio_or_gadget_class_with_a_device_is_found(self, release, cls):
        (release / "sys/class" / cls / "x0").mkdir(parents=True)
        assert codes(nt.sweep(release)) == ["radio_class"]


    def test_an_empty_radio_class_directory_is_clean(self, release):
        (release / "sys/class/bluetooth").mkdir(parents=True)
        assert nt.sweep(release) == []


    def test_the_wifi_chip_on_the_sdio_bus_is_found(self, release):
        (release / "sys/bus/sdio/devices/mmc1:0001:1").mkdir(parents=True)
        assert codes(nt.sweep(release)) == ["sdio_device"]


    @pytest.mark.parametrize("cls", ["03", "08", "ff", "e0", "02", "00"])
    def test_any_usb_device_is_found(self, release, cls):
        make_usb(release, "1-1", cls=cls, vendor="0bda", product="8153")
        (release / "sys/bus/usb/devices/1-1:1.0").mkdir(parents=True)
        found = nt.sweep(release)
        assert codes(found) == ["usb_device"]
        assert found[0].detail == f"1-1 class {cls} 0bda:8153"


    def test_a_second_root_hub_is_still_only_a_root_hub(self, release):
        make_usb(release, "usb2")
        (release / "sys/bus/usb/devices/2-0:1.0").mkdir(parents=True)
        assert nt.sweep(release) == []


    def test_without_networking_in_the_kernel_the_missing_directories_are_clean(self, tmp_path):
        assert nt.sweep(tmp_path) == []


    @pytest.mark.parametrize("option,value", [("CONFIG_INET", "y"), ("CONFIG_BT", "m"), ("CONFIG_USB_GADGET", "y"),
                                              ("CONFIG_MODULES", "y"), ("CONFIG_CFG80211", "y")])
    def test_a_kernel_built_with_a_network_capability_is_found(self, release, option, value):
        write_config_gz(release, {**RELEASE_KERNEL, option: value})
        found = nt.check_kernel_config(release)
        assert codes(found) == ["kernel_option"]
        assert found[0].detail == f"{option}={value}"


    def test_a_missing_or_unreadable_kernel_config_is_a_finding(self, release):
        (release / "proc/config.gz").unlink()
        assert codes(nt.check_kernel_config(release)) == ["kernel_config_missing"]
        (release / "proc/config.gz").write_bytes(b"not gzip")
        assert codes(nt.check_kernel_config(release)) == ["kernel_config_unreadable"]


    def test_a_check_that_fails_is_a_finding_not_clean(self, release, monkeypatch):
        def broken(root):
            raise OSError("unreadable")
        monkeypatch.setattr(nt, "SWEEP_CHECKS", (broken,))
        assert codes(nt.sweep(release)) == ["check_failed"]


# --- the mode ---------------------------------------------------------------

class TestMode:
    def test_the_release_image_on_a_pi_enforces(self, release):
        assert nt.detect_mode(release) == nt.ENFORCE


    def test_the_dev_image_warns(self, release):
        _write(release / "etc/hostname", "seedsigner-dev\n")
        assert nt.detect_mode(release) == nt.WARN


    def test_off_a_pi_it_is_off(self, release):
        _write(release / "proc/device-tree/model", "QEMU Virt\x00")
        assert nt.detect_mode(release, machine="armv7l") == nt.OFF
        (release / "proc/device-tree/model").unlink()
        assert nt.detect_mode(release, machine="x86_64") == nt.OFF
        assert nt.detect_mode(release, machine="arm64") == nt.OFF


    def test_an_unreadable_device_tree_on_the_device_enforces(self, release):
        """ Fail closed: the device's own CPU with no readable model is not
            evidence of another computer (review 2026-10-09). """
        (release / "proc/device-tree/model").unlink()
        assert nt.detect_mode(release, machine="armv7l") == nt.ENFORCE


    def test_any_other_hostname_on_a_pi_enforces(self, release):
        for name in ("", "seedsigner", "Seedsigner-dev", "seedsigner-dev2"):
            _write(release / "etc/hostname", name)
            assert nt.detect_mode(release) == nt.ENFORCE
        (release / "etc/hostname").unlink()
        assert nt.detect_mode(release) == nt.ENFORCE


    def test_enforce_can_be_forced_on_the_dev_image_but_nothing_lowers_it(self, release):
        _write(release / "etc/hostname", "seedsigner-dev\n")
        assert nt.detect_mode(release, force_enforce=True) == nt.ENFORCE
        _write(release / "etc/hostname", "seedsigner-os\n")
        assert nt.detect_mode(release, force_enforce=False) == nt.ENFORCE


# --- gates and the trip -----------------------------------------------------

@pytest.fixture
def armed(release):
    """ The tripwire enforcing over the fake tree, with the trip handler
        recorded instead of drawing and exiting. """
    calls = []
    nt.configure(nt.ENFORCE, root=release, on_trip=calls.append)
    yield release, calls
    nt.configure(nt.OFF)


class TestGates:
    def test_the_exception_cannot_be_swallowed_by_except_exception(self):
        assert issubclass(nt.NetworkTripwireTripped, BaseException)
        assert not issubclass(nt.NetworkTripwireTripped, Exception)


    def test_a_clean_device_passes_the_gate(self, armed):
        nt.boot_gate()
        nt.assert_clean()
        nt.assert_clean(network="mainnet")
        assert not nt.is_tripped()


    def test_the_boot_gate_trips_on_a_network_capable_kernel(self, armed):
        root, calls = armed
        write_config_gz(root, {**RELEASE_KERNEL, "CONFIG_INET": "y"})
        with pytest.raises(nt.NetworkTripwireTripped):
            nt.boot_gate()
        assert codes(calls[0]) == ["kernel_option"]


    def test_the_gate_trips_once_and_stays_tripped(self, armed):
        root, calls = armed
        nt.boot_gate()
        make_iface(root, "eth0")
        with pytest.raises(nt.NetworkTripwireTripped):
            nt.assert_clean()
        shutil.rmtree(root / "sys/class/net/eth0")
        with pytest.raises(nt.NetworkTripwireTripped):
            nt.assert_clean()
        assert len(calls) == 1
        assert nt.is_tripped()


    def test_the_kernel_finding_from_boot_keeps_every_later_gate_closed(self, armed):
        root, calls = armed
        write_config_gz(root, {**RELEASE_KERNEL, "CONFIG_BT": "y"})
        with pytest.raises(nt.NetworkTripwireTripped):
            nt.boot_gate()
        with pytest.raises(nt.NetworkTripwireTripped):
            nt.assert_clean()


    def test_the_gate_before_the_boot_gate_ran_checks_the_kernel_itself(self, armed):
        root, calls = armed
        write_config_gz(root, {**RELEASE_KERNEL, "CONFIG_INET": "y"})
        with pytest.raises(nt.NetworkTripwireTripped):
            nt.assert_clean()
        assert codes(calls[0]) == ["kernel_option"]


    def test_a_stalled_monitor_trips_the_gate(self, armed, monkeypatch):
        root, calls = armed
        nt.boot_gate()
        monkeypatch.setattr(nt._state, "heartbeat", time.monotonic() - nt.MONITOR_STALE_SECONDS - 1)
        with pytest.raises(nt.NetworkTripwireTripped):
            nt.assert_clean()
        assert codes(calls[0]) == ["monitor_stalled"]


    def test_a_second_caller_waits_for_the_trip_handler_before_raising(self, release):
        """ The monitor trips and draws; the main thread hitting a gate
            meanwhile must not unwind (and blank the display) before the
            handler is done (review 2026-10-09). """
        drawing, release_handler = threading.Event(), threading.Event()

        def slow_handler(found):
            drawing.set()
            release_handler.wait(2)
        nt.configure(nt.ENFORCE, root=release, on_trip=slow_handler)
        try:
            make_iface(release, "eth0")
            first = threading.Thread(target=lambda: pytest.raises(nt.NetworkTripwireTripped, nt.assert_clean))
            first.start()
            assert drawing.wait(2)
            raised_at = []
            second = threading.Thread(target=lambda: (pytest.raises(nt.NetworkTripwireTripped, nt.assert_clean),
                                                      raised_at.append(time.monotonic())))
            second.start()
            time.sleep(0.3)
            assert raised_at == []                   # still waiting on the handler
            released = time.monotonic()
            release_handler.set()
            second.join(2)
            first.join(2)
            assert raised_at and raised_at[0] >= released
        finally:
            release_handler.set()
            nt.configure(nt.OFF)


    def test_a_trip_handler_that_fails_still_leaves_the_gate_closed(self, release):
        def failing(findings):
            raise RuntimeError("display gone")
        nt.configure(nt.ENFORCE, root=release, on_trip=failing)
        try:
            make_iface(release, "eth0")
            with pytest.raises(nt.NetworkTripwireTripped):
                nt.assert_clean()
            assert nt.is_tripped()
        finally:
            nt.configure(nt.OFF)


    def test_off_does_nothing(self, release):
        nt.configure(nt.OFF, root=release)
        make_iface(release, "eth0")
        nt.boot_gate()
        nt.assert_clean(network="mainnet")


    def test_the_dev_image_refuses_mainnet_keys_and_allows_test_networks(self, release):
        make_iface(release, "wlan0")
        nt.configure(nt.WARN, root=release, on_trip=lambda f: pytest.fail("WARN never trips"))
        try:
            nt.boot_gate()
            nt.assert_clean(network="testnet")
            nt.assert_clean(network="devnet")
            nt.assert_clean()
            for network in ("mainnet", "", "Testnet", "unknown"):
                with pytest.raises(nt.NetworkCapableImageRefusal):
                    nt.assert_clean(network=network)
        finally:
            nt.configure(nt.OFF)


    def test_the_network_of_a_7f_path_is_its_second_segment(self):
        assert nt.network_of_path("root/testnet/0/ml-dsa/v1") == "testnet"
        assert nt.network_of_path("devfund/mainnet/0/ml-dsa/v1") == "mainnet"
        assert nt.network_of_path("garbage") == ""


class TestMonitor:
    def test_an_interface_appearing_trips_within_the_poll_bound(self, release):
        """ Backlog AC (b): a stated sub-second bound, proven. """
        delays = []
        try:
            for i in range(5):
                tripped = threading.Event()
                nt.configure(nt.ENFORCE, root=release, on_trip=lambda f: tripped.set())
                nt.boot_gate()
                monitor = nt.TripwireMonitor()
                monitor.start()
                time.sleep(0.05)
                started = time.monotonic()
                make_iface(release, f"eth{i}")
                assert tripped.wait(nt.POLL_SECONDS + 0.5)
                delays.append(time.monotonic() - started)
                monitor.join(1)
                assert not monitor.is_alive()
                shutil.rmtree(release / f"sys/class/net/eth{i}")
        finally:
            nt.configure(nt.OFF)
        assert max(delays) <= nt.POLL_SECONDS + 0.1


    def test_the_monitor_keeps_its_heartbeat_while_clean(self, armed):
        nt.boot_gate()
        monitor = nt.TripwireMonitor()
        monitor.start()
        try:
            time.sleep(3 * nt.POLL_SECONDS)
            assert time.monotonic() - nt._state.heartbeat < 2 * nt.POLL_SECONDS
            nt.assert_clean()
        finally:
            monitor.stop()
            monitor.join(1)


# --- where the gates are: one test per gate, so removing one fails ---------

ABANDON_ART = ["abandon"] * 23 + ["art"]


@pytest.fixture
def tripping(release):
    """ ENFORCE over a tree with a network interface: every gate trips. """
    make_iface(release, "eth0")
    calls = []
    nt.configure(nt.ENFORCE, root=release, on_trip=calls.append)
    yield calls
    nt.configure(nt.OFF)


@pytest.fixture
def no_7f_library(monkeypatch):
    from seedsigner.models.sevenf import mldsa

    def must_not_load():
        raise AssertionError("the key was used before the tripwire gate")
    monkeypatch.setattr(mldsa, "_lib_handle", must_not_load)


class TestGatePlacement:
    def test_7f_public_key_derivation(self, tripping, no_7f_library):
        from seedsigner.models.sevenf import mldsa
        with pytest.raises(nt.NetworkTripwireTripped):
            mldsa.derive_pubkey(bytes(64), "root/testnet/0/ml-dsa/v1")
        assert tripping


    def test_7f_signing(self, tripping, no_7f_library):
        from seedsigner.models.sevenf import mldsa
        with pytest.raises(nt.NetworkTripwireTripped):
            mldsa.derive_and_sign(bytes(64), "root/testnet/0/ml-dsa/v1", b"m")


    def test_7f_seed(self, tripping):
        from seedsigner.models.seed import Seed
        from seedsigner.models.sevenf.root_ceremony import seed_for_7f
        seed = object.__new__(Seed)            # made before the trip
        with pytest.raises(nt.NetworkTripwireTripped):
            seed_for_7f(seed)


    def test_every_read_of_seed_bytes(self, release):
        """ Every key a seed yields is derived from seed_bytes (BIP-32 roots,
            xpubs, PSBT, BIP-85, EVM, 7F), so reading them is gated. """
        from seedsigner.models.seed import Seed
        seed = Seed(ABANDON_ART)
        make_iface(release, "eth0")
        nt.configure(nt.ENFORCE, root=release, on_trip=lambda f: None)
        try:
            for use in (lambda: seed.seed_bytes, lambda: seed.get_xpub("m/84h/0h/0h"),
                        lambda: seed.get_bip85_child_mnemonic(0, 12), lambda: seed.get_fingerprint()):
                with pytest.raises(nt.NetworkTripwireTripped):
                    use()
        finally:
            nt.configure(nt.OFF)


    def test_an_electrum_seed(self, tripping):
        from seedsigner.models.seed import ElectrumSeed
        with pytest.raises(nt.NetworkTripwireTripped):
            ElectrumSeed(["abandon"] * 12)


    def test_every_bip39_seed(self, tripping):
        from seedsigner.models.seed import Seed
        with pytest.raises(nt.NetworkTripwireTripped):
            Seed(ABANDON_ART)


    def test_bitcoin_message_signing(self, tripping):
        from seedsigner.helpers import embit_utils
        with pytest.raises(nt.NetworkTripwireTripped):
            embit_utils.sign_message(bytes(64), "m/84h/0h/0h/0/0", b"hello")


    def test_evm_signing(self, tripping):
        from seedsigner.chains.evm.plugin import EvmPlugin
        with pytest.raises(nt.NetworkTripwireTripped):
            EvmPlugin().sign(bytes(64), "m/44'/60'/0'/0/0", b"\x02")


    def test_psbt_signing_is_gated_before_embit_signs(self):
        """ embit's PSBT.sign_with is third-party code: the gate sits on the
            line before it in the view. """
        import inspect
        from seedsigner.views import psbt_views
        source = inspect.getsource(psbt_views)
        gate = source.index("network_tripwire.assert_clean()")
        assert gate < source.index("psbt.sign_with(psbt_parser.root)")
        assert source.count("psbt.sign_with(") == 1


    def test_the_controller_checks_before_every_view(self):
        import inspect
        from seedsigner.controller import Controller
        source = inspect.getsource(Controller.start)
        assert source.index("network_tripwire.boot_gate()") < source.index("OpeningSplashView().run()")
        assert source.index("network_tripwire.assert_clean()") < source.index("next_destination = next_destination.run()")


    def test_a_refusal_handler_cannot_swallow_the_trip(self, tripping):
        """ refuse_on_unexpected_error turns an Exception into a refusal
            screen; the trip is not one. """
        from seedsigner.views.sevenf_views._common import refuse_on_unexpected_error

        @refuse_on_unexpected_error
        def handler(self):
            nt.assert_clean()

        with pytest.raises(nt.NetworkTripwireTripped):
            handler(object())


class TestDevImageMainnet:
    def test_a_7f_scan_wrapper_passes_the_refusal_to_the_controller(self):
        from seedsigner.views.sevenf_views._common import refuse_on_unexpected_error

        @refuse_on_unexpected_error
        def handler(self):
            raise nt.NetworkCapableImageRefusal("dev image")

        with pytest.raises(nt.NetworkCapableImageRefusal):
            handler(object())


    def test_7f_mainnet_keys_are_refused_on_the_dev_image(self, release, no_7f_library):
        from seedsigner.models.sevenf import mldsa
        nt.configure(nt.WARN, root=release)
        try:
            for call in (lambda: mldsa.derive_pubkey(bytes(64), "root/mainnet/0/ml-dsa/v1"),
                         lambda: mldsa.derive_and_sign(bytes(64), "devfund/mainnet/0/ml-dsa/v1", b"m")):
                with pytest.raises(nt.NetworkCapableImageRefusal):
                    call()
        finally:
            nt.configure(nt.OFF)


# --- the trip handler ---------------------------------------------------------

class _Exited(BaseException):
    pass


class TestTripHandler:
    def test_it_wipes_draws_and_exits_without_writing_anything(self, monkeypatch):
        from seedsigner import controller as controller_module
        from seedsigner.controller import Controller
        from seedsigner.gui.renderer import Renderer
        from seedsigner.models.seed import Seed

        controller = Controller.get_instance()
        controller.storage.seeds.append(Seed(ABANDON_ART))
        controller.storage.set_pending_seed(Seed(ABANDON_ART))
        controller.storage._pending_mnemonic = ["abandon"] * 3
        controller.psbt_seed = controller.storage.seeds[0]
        controller.sign_message_data = {"seed": controller.storage.seeds[0]}
        controller.multichain_data = {"seed": controller.storage.seeds[0]}
        controller.back_stack.append(controller_module.Destination(None))

        from seedsigner.gui.screens import network_lockdown
        drawn = []
        monkeypatch.setattr(network_lockdown, "render_network_lockdown", lambda w, h, f: drawn.append(f) or "warning")
        renderer = Renderer.get_instance()
        renderer.show_image.reset_mock()
        exits = []

        def fake_exit(code):
            exits.append(code)
            raise _Exited()
        monkeypatch.setattr(controller_module.os, "_exit", fake_exit)

        def no_writes(*args, **kwargs):
            raise AssertionError("the trip wrote a file")
        monkeypatch.setattr("seedsigner.models.settings.Settings.save", no_writes, raising=False)

        with pytest.raises(_Exited):
            controller._on_network_trip([nt.Finding("usb_device", "1-1 class 03 046d:c31c")])

        assert exits == [controller_module.EXIT_NETWORK_TRIPPED]
        assert controller.storage.seeds == []
        assert controller.storage.pending_seed is None
        assert controller.storage._pending_mnemonic == []
        assert controller.psbt_seed is None and controller.sign_message_data is None and controller.multichain_data is None
        assert len(controller.back_stack) == 0
        assert drawn == [[nt.Finding("usb_device", "1-1 class 03 046d:c31c")]]
        renderer.show_image.assert_called_once_with("warning")
        Renderer.lock.acquire.assert_called()
        Renderer.lock.release.assert_not_called()      # kept: nothing draws over the warning


    def test_it_stops_the_screensaver_and_toast_before_drawing(self, monkeypatch):
        from unittest.mock import MagicMock
        from seedsigner import controller as controller_module
        from seedsigner.controller import Controller
        from seedsigner.gui.screens import network_lockdown

        controller = Controller.get_instance()
        order = []
        controller.screensaver = MagicMock(is_running=True, stop=lambda: order.append("screensaver"))
        controller.toast_notification_thread = MagicMock(stop=lambda: order.append("toast"))
        monkeypatch.setattr(network_lockdown, "render_network_lockdown", lambda w, h, f: order.append("draw"))
        monkeypatch.setattr(controller_module.os, "_exit", lambda code: (_ for _ in ()).throw(_Exited()))
        try:
            with pytest.raises(_Exited):
                controller._on_network_trip([])
        finally:
            controller.screensaver = None
            controller.toast_notification_thread = None
        assert order == ["screensaver", "toast", "draw"]


    def test_it_exits_even_if_drawing_fails(self, monkeypatch):
        from seedsigner import controller as controller_module
        from seedsigner.controller import Controller
        from seedsigner.gui.renderer import Renderer

        from seedsigner.gui.screens import network_lockdown

        def broken(w, h, f):
            raise OSError("display gone")
        monkeypatch.setattr(network_lockdown, "render_network_lockdown", broken)
        monkeypatch.setattr(controller_module.os, "_exit", lambda code: (_ for _ in ()).throw(_Exited()))
        with pytest.raises(_Exited):
            Controller.get_instance()._on_network_trip([])


    def test_the_warning_fits_the_display(self):
        from seedsigner.gui.screens.network_lockdown import render_network_lockdown
        image = render_network_lockdown(240, 240, [nt.Finding("usb_device", "1-1 class ff 0bda:8153")])
        assert image.size == (240, 240)
        # the bottom rows are still background: nothing ran off the screen
        bottom = image.crop((0, 228, 240, 240))
        assert set(bottom.getdata()) == {image.getpixel((0, 239))}
