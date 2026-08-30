"""
    ChainRegistry -- maps a chain_id to its ChainPlugin instance. See base.py for the
    ChainPlugin contract and docs/multi-chain/README.md (diy-seedsigner repo) for the
    architecture this implements.

    Plugins register themselves via `ChainRegistry.register()`; the multi-chain UI
    (views/multichain_views.py) reads `ChainRegistry.all()` to build its chain-selector
    menu, so adding a chain to the menu never means editing that view -- just
    registering a new plugin (see chains/_template/ for a stub to copy).
"""
from .base import ChainPlugin


class ChainRegistry:
    _plugins: dict[str, ChainPlugin] = {}

    @classmethod
    def register(cls, plugin: ChainPlugin) -> None:
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

    ChainRegistry.register(EvmPlugin())


_register_builtin_plugins()
