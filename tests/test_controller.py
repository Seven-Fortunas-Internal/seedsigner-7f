from unittest.mock import patch

import pytest

# Must import this before the Controller
from base import BaseTest

from seedsigner.controller import Controller, StopFlowBasedTest
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import ChainChooserView, MainMenuView, RemoveMicroSDWarningView


class TestController(BaseTest):

    def test_reset_controller(self):
        """ The reset_controller util should completely reset the Controller singleton """
        controller = Controller.get_instance()
        controller.address_explorer_data = "foo"

        BaseTest.reset_controller()
        controller = Controller.get_instance()
        assert controller.address_explorer_data is None


    def test_singleton_init_fails(self):
        """ The Controller should not allow any code to instantiate it via Controller() """
        with pytest.raises(Exception):
            c = Controller()


    def test_handle_exception(reset_controller):
        """ Handle exceptions that get caught by the controller """

        def process_exception_asserting_valid_error(exception_type, exception_msg=None):
            """
            Exceptions caught by the controller are forwarded to the
            UnhandledExceptionView with view_args["error"] being a list
            of three strings, ie: [exception_type, line_info, exception_msg]
            """
            try:
                if exception_msg:
                    raise exception_type(exception_msg)
                else:
                    raise exception_type()
            except Exception as e:
                error = controller.handle_exception(e).view_args["error"]

            # assert that error structure is valid
            assert len(error) == 3
            assert error[0] in str(exception_type)
            assert type(error[1]) == str
            if exception_msg:
                assert exception_msg in error[2]
            else:
                assert error[2] == ""

        # Initialize the controller
        controller = Controller.get_instance()

        exception_tests = [
            # exceptions with an exception_msg
            (Exception, "foo"),
            (KeyError, "key not found"),
            # exceptions without an exception_msg
            (Exception, ""),
            (Exception, None),
        ]
            
        for exception_type, exception_msg in exception_tests:
            process_exception_asserting_valid_error(exception_type, exception_msg)


    def test_singleton_get_instance_preserves_state(self):
        """ Changes to the Controller singleton should be preserved across calls to get_instance() """

        # Initialize the instance and verify that it read the config settings
        controller = Controller.get_instance()
        assert controller.unverified_address is None

        # Change a value in the instance...
        controller.unverified_address = "123abc"

        # ...get a new copy of the instance and confirm change
        controller = Controller.get_instance()
        assert controller.unverified_address == "123abc"


    def _first_view_cls_from_start(self, controller, initial_destination=None):
        """
            Helper: runs Controller.start() but stops it after the very first
            Destination._run_view() call, returning the View_cls that was about to
            run. Used to test start()'s own destination-selection logic directly,
            without going through the full FlowStep/run_sequence machinery (which
            can't express "the default destination should be something other than
            MainMenuView" -- its own initial_destination convenience shortcut is
            keyed specifically off of MainMenuView).
        """
        captured = {}

        def fake_run_view(destination, *args, **kwargs):
            captured["View_cls"] = destination.View_cls
            raise StopFlowBasedTest()

        with patch("seedsigner.views.view.Destination._run_view", autospec=True, side_effect=fake_run_view):
            controller.start(initial_destination=initial_destination)

        return captured.get("View_cls")


    def test_chain_chooser_shown_on_fresh_boot(self):
        """
            A fresh boot (active_chain_id unset, no test-only initial_destination
            override) must route to ChainChooserView, not straight to MainMenuView --
            see docs/multi-chain/boot-chain-selection-plan.md.
        """
        controller = Controller.get_instance()
        controller.active_chain_id = None

        assert self._first_view_cls_from_start(controller) == ChainChooserView


    def test_no_chain_chooser_once_active_chain_id_is_set(self):
        """ Once active_chain_id is set (any later Home visit this session), boot
            straight to MainMenuView as before -- the chooser only ever fires once
            per power-on session. """
        controller = Controller.get_instance()
        controller.active_chain_id = "bitcoin"

        assert self._first_view_cls_from_start(controller) == MainMenuView


    def test_chain_chooser_wins_over_microsd_forever_reminder(self):
        """
            Regression test for a real bug found by adversarial review before this
            code was written: the MICROSD_TOAST_TIMER_FOREVER branch unconditionally
            overwrites next_destination, which -- if checked before the chain-chooser
            logic -- would let a device with that setting active silently skip the
            chooser for the entire session. The chooser must win.
        """
        controller = Controller.get_instance()
        controller.active_chain_id = None
        controller.settings.set_value(SettingsConstants.SETTING__MICROSD_TOAST_TIMER, SettingsConstants.MICROSD_TOAST_TIMER_FOREVER)

        assert self._first_view_cls_from_start(controller) == ChainChooserView


    def test_microsd_forever_reminder_still_works_once_chain_is_chosen(self):
        """ The microSD-forever reminder itself must still work normally once
            active_chain_id is already set (i.e. this isn't a fresh boot) -- the
            chain-chooser fix must not have broken this pre-existing feature. """
        controller = Controller.get_instance()
        controller.active_chain_id = "bitcoin"
        controller.settings.set_value(SettingsConstants.SETTING__MICROSD_TOAST_TIMER, SettingsConstants.MICROSD_TOAST_TIMER_FOREVER)

        assert self._first_view_cls_from_start(controller) == RemoveMicroSDWarningView


    # Note: ChainChooserView's own button-selection behavior (does picking Bitcoin/EVM
    # actually set active_chain_id and land on MainMenuView) is tested via
    # run_sequence() in test_flows_view.py instead of here -- that needs FlowTest's
    # full pytest lifecycle (setup_class's mock_microsd/LoadingScreenThread patching),
    # which TestController (a plain BaseTest) doesn't have.
