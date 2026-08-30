"""
    Multi-chain (Phase 1 UI-walkthrough demo). Chain-selector entry point -- reads
    ChainRegistry to build its menu, so adding a chain never means editing this file.
    See docs/multi-chain/README.md in the diy-seedsigner repo for the full design and
    docs/7f-integration/README.md for the earlier, single-chain version of this same
    "mocked-data walkthrough before any backend work" approach.

    Reached from one gated button on SeedOptionsView (see seed_views.py), behind
    Settings > Advanced > "Multi-chain (demo)" (SETTING__MULTICHAIN_ENABLED, disabled
    by default). Reuses the already-loaded `Seed` object exactly the way every other
    SeedOptionsView destination does.
"""
from gettext import gettext as _

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonListScreen, ButtonOption
from seedsigner.models.seed import Seed
from seedsigner.views.view import BackStackView, Destination, View



class MultiChainOptionsView(View):
    def __init__(self, seed: Seed):
        super().__init__()
        self.seed = seed


    def run(self):
        from seedsigner.chains import ChainRegistry

        plugins = ChainRegistry.all()
        button_data = [ButtonOption(p.display_name) for p in plugins]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Chains (DEMO)"),
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        plugin = plugins[selected_menu_num]
        return Destination(_options_view_for(plugin.chain_id), view_args=dict(seed=self.seed))


def _options_view_for(chain_id: str):
    # One import branch per chain -- deliberately not a generic dispatch table, so
    # each chain's views module is only imported when that chain is actually opened
    # (matches the codebase's own lazy-import convention).
    if chain_id == "evm":
        from seedsigner.views.evm_views import EvmOptionsView
        return EvmOptionsView
    raise NotImplementedError(f"No options view registered for chain_id={chain_id!r}")
