from unittest.mock import patch

# Must import test base before the Controller
from base import FlowTest, FlowStep

from seedsigner.gui.screens.screen import RET_CODE__POWER_BUTTON
from seedsigner.hardware.camera import CameraConnectionError
from seedsigner.models.settings import Settings
from seedsigner.views.scan_views import ScanView
from seedsigner.views.tools_views import ToolsCalcFinalWordNumWordsView, ToolsMenuView
from seedsigner.views.view import CameraConnectionErrorView, ChainChooserView, MainMenuView, NotYetImplementedView, PowerOptionsView, PowerOffView, RestartView, UnhandledExceptionView, View



class TestViewFlows(FlowTest):

    def test_restart_flow(self):
        """
        Basic flow from MainMenuView to RestartView
        """
        with patch('seedsigner.views.view.RestartView.DoResetThread'):
            self.run_sequence([
                FlowStep(MainMenuView, screen_return_value=RET_CODE__POWER_BUTTON),
                FlowStep(PowerOptionsView, button_data_selection=PowerOptionsView.RESET),
                FlowStep(RestartView),
            ])


    def test_power_off_flow(self):
        """
        Basic flow from MainMenuView to PowerOffView
        """
        self.run_sequence([
            FlowStep(MainMenuView, screen_return_value=RET_CODE__POWER_BUTTON),
            FlowStep(PowerOptionsView, button_data_selection=PowerOptionsView.POWER_OFF),
            FlowStep(PowerOffView),  # returns BackStackView
            FlowStep(PowerOptionsView),
        ])


    def test_not_yet_implemented_flow(self):
        """
        Run an incomplete View that returns None and ensure that we get the NotYetImplementedView
        """
        class IncompleteView(View):
            def run(self):
                self.run_screen(None)
                return None

        self.run_sequence([
            FlowStep(IncompleteView),
            FlowStep(NotYetImplementedView),
            FlowStep(MainMenuView),
        ])


    def test_unhandled_exception_flow(self):
        """
        Basic flow from any arbitrary View to the UnhandledExceptionView
        """
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(ToolsMenuView, button_data_selection=ToolsMenuView.KEYBOARD),
            FlowStep(ToolsCalcFinalWordNumWordsView, screen_return_value=Exception("Test exception")),  # <-- force an exception
            FlowStep(UnhandledExceptionView),
            FlowStep(MainMenuView),
        ])


    def test__camera_connection_error__flow(self):
        """
        Simulate a camera connection error and ensure that we get the
        CameraConnectionErrorView.
        """
        # Force a camera exception during `ScanView.run()`
        with patch('seedsigner.views.scan_views.ScanView.run') as mock_run:
            mock_run.side_effect = CameraConnectionError()

            self.run_sequence([
                FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
                FlowStep(ScanView),
                FlowStep(UnhandledExceptionView, is_redirect=True),
                FlowStep(CameraConnectionErrorView),
                FlowStep(MainMenuView),
            ])


    def test_chain_chooser_bitcoin_selection_flow(self):
        """
        Selecting "Bitcoin" on ChainChooserView sets active_chain_id and lands on
        MainMenuView -- see docs/multi-chain/boot-chain-selection-plan.md.
        """
        self.controller.active_chain_id = None
        self.run_sequence([
            FlowStep(ChainChooserView, button_data_selection=ChainChooserView.BITCOIN),
            FlowStep(MainMenuView),
        ])
        assert self.controller.active_chain_id == "bitcoin"


    def test_chain_chooser_evm_selection_flow(self):
        """
        Selecting "Ethereum / EVM" on ChainChooserView sets active_chain_id and lands
        on MainMenuView.
        """
        self.controller.active_chain_id = None
        self.run_sequence([
            FlowStep(ChainChooserView, button_data_selection=ChainChooserView.EVM),
            FlowStep(MainMenuView),
        ])
        assert self.controller.active_chain_id == "evm"


    def test_chain_chooser_sevenf_selection_flow(self):
        """
        Selecting "7F Chain" on ChainChooserView sets active_chain_id and lands on
        MainMenuView -- same pattern as Bitcoin/EVM selection above.
        """
        self.controller.active_chain_id = None
        self.run_sequence([
            FlowStep(ChainChooserView, button_data_selection=ChainChooserView.SEVENF),
            FlowStep(MainMenuView),
        ])
        assert self.controller.active_chain_id == "sevenf"


    def test_chain_chooser_chains_to_microsd_forever_reminder(self):
        """
        Found by execution-stage adversarial review: since active_chain_id never
        persists across a reboot, an operator with MICROSD_TOAST_TIMER_FOREVER enabled
        would otherwise lose that reminder every single boot (Controller.start()'s own
        one-time check always loses to the un-skippable chain chooser). ChainChooserView
        must chain to RemoveMicroSDWarningView instead of going straight to MainMenuView
        when that setting is active.
        """
        from seedsigner.models.settings import SettingsConstants
        from seedsigner.views.view import RemoveMicroSDWarningView

        self.controller.active_chain_id = None
        self.settings.set_value(SettingsConstants.SETTING__MICROSD_TOAST_TIMER, SettingsConstants.MICROSD_TOAST_TIMER_FOREVER)
        self.run_sequence([
            FlowStep(ChainChooserView, button_data_selection=ChainChooserView.BITCOIN),
            FlowStep(RemoveMicroSDWarningView),
        ])
        assert self.controller.active_chain_id == "bitcoin"