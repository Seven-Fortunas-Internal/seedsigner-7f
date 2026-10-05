"""
    ChainRegistry -- maps a chain_id to its ChainPlugin instance. See base.py for the
    ChainPlugin contract and docs/multi-chain/README.md (diy-seedsigner repo) for the
    architecture this implements.

    Plugins register themselves via `ChainRegistry.register()`. `ChainRegistry.all()`
    has no current caller (the old multi-chain-picker view that used it was retired
    along with SETTING__MULTICHAIN_ENABLED -- see
    docs/multi-chain/boot-chain-selection-plan.md in the diy-seedsigner repo) but
    stays as a reasonable public surface for a future multi-chain UI (e.g. a settings
    diagnostics screen, or a menu once a 3rd chain makes per-chain-option-block
    hardcoding in ChainChooserView too repetitive) -- adding a chain via
    `ChainRegistry.register()` (see chains/_template/ for a stub to copy) never
    requires touching this file either way.
"""
from .base import ChainPlugin


class ChainRegistry:
    _plugins: dict[str, ChainPlugin] = {}

    @classmethod
    def register(cls, plugin: ChainPlugin) -> None:
        # Both checks added 2026-10-05 (multi-chain-chainregistry-no-security-review):
        # this is the one shared cross-chain trust boundary, so a mistake here must
        # fail loudly at import/boot time, not silently misroute a live signing call.
        if not isinstance(plugin, ChainPlugin):
            raise TypeError(
                f"{type(plugin).__name__} does not implement the full ChainPlugin "
                "contract (base.py) -- a structurally incomplete plugin must not register."
            )
        if plugin.chain_id in cls._plugins:
            raise ValueError(
                f"chain_id {plugin.chain_id!r} is already registered to "
                f"{type(cls._plugins[plugin.chain_id]).__name__} -- refusing to silently "
                f"overwrite it with {type(plugin).__name__}."
            )
        cls._plugins[plugin.chain_id] = plugin

    @classmethod
    def get(cls, chain_id: str) -> ChainPlugin:
        return cls._plugins[chain_id]

    @classmethod
    def all(cls) -> list[ChainPlugin]:
        return list(cls._plugins.values())


def _register_builtin_plugins():
    # Registration happens when `seedsigner.chains` is first imported (by the
    # multi-chain views, on demand) rather than at app boot -- matches the codebase's
    # own "avoid heavy imports until needed" convention (see controller.py's
    # BackgroundImportThread), since chain plugins may eventually pull in
    # chain-specific crypto libs.
    from .evm.plugin import EvmPlugin
    from .sevenf.plugin import SevenFPlugin

    ChainRegistry.register(EvmPlugin())
    ChainRegistry.register(SevenFPlugin())


_register_builtin_plugins()
