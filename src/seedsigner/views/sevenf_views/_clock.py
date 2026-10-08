"""
    Operator-confirmed date/time for the certificate flows -- see
    models/sevenf/ceremony_clock.py for why the device can't trust its own
    clock. Asked at the start of every "Self-Certify Root" and
    "Cross-Certify Deputy" flow, before the chain picker, and held in memory
    only. Once a date has been confirmed this boot the prompt opens on the
    read-back of the current time, so it is one press -- but a wrongly
    confirmed date can always be corrected without a reboot.
"""
import time
from gettext import gettext as _

from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.helpers.version import Version
from seedsigner.models.sevenf.ceremony_clock import (
    ClockEntryError,
    ConfirmedClock,
    DateTimeFields,
    check_entry,
    floor_timestamp,
    initial_fields,
)
from seedsigner.views.view import BackStackView, Destination, View


def ceremony_now(controller) -> int | None:
    """ The confirmed UTC time now, or None if not confirmed this boot. """
    clock = controller.sevenf_confirmed_clock
    return None if clock is None else clock.now(time.monotonic())


def require_confirmed_clock(view: View) -> Destination | None:
    """ For the first view of a certificate flow: a Destination to the date
        prompt, which returns to this same view with date_confirmed=True, or
        None if the date was confirmed for this flow. `view` must hold
        `seed` and `date_confirmed`. """
    if view.date_confirmed:
        return None
    return Destination(
        SevenFConfirmDateTimeView,
        view_args=dict(next_view_cls=view.__class__, next_view_args=dict(seed=view.seed, date_confirmed=True)),
        skip_current_view=True,
    )


class SevenFConfirmDateTimeView(View):
    """ Edit -> read back with the weekday -> confirm. A date before this
        firmware's build is refused and the editor reopens on it. Back from
        the editor leaves without confirming anything. """
    def __init__(self, next_view_cls: type, next_view_args: dict):
        super().__init__()
        self.next_view_cls = next_view_cls
        self.next_view_args = next_view_args


    def run(self):
        from seedsigner.gui.screens.screen import LargeIconStatusScreen, WarningScreen
        from seedsigner.gui.screens.sevenf_screens import SevenFDateTimeEntryScreen

        floor = floor_timestamp(Version.get_version_timestamp())
        current = ceremony_now(self.controller)
        if current is not None:
            # Confirmed earlier this boot: start on the read-back of that
            # clock's "now" -- one press if it's right.
            fields = DateTimeFields.from_timestamp(current)
            edit = False
        else:
            fields = initial_fields(int(time.time()), floor)
            edit = True

        while True:
            if edit:
                entered = self.run_screen(SevenFDateTimeEntryScreen, fields=fields)
                if entered == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)
                fields = entered
            edit = True

            try:
                check_entry(fields.to_timestamp(), floor)
            except ClockEntryError as e:
                self.run_screen(
                    WarningScreen,
                    title=_("Check the date"),
                    status_headline=_("Not accepted"),
                    text=str(e),
                    show_back_button=False,
                    button_data=[ButtonOption("Edit")],
                )
                continue

            choice = self.run_screen(
                LargeIconStatusScreen,
                title=_("Date & time"),
                status_headline=_("Is this right?"),
                text=fields.describe(),
                show_back_button=False,
                button_data=[ButtonOption("Yes, continue"), ButtonOption("Change")],
            )
            if choice != 0:
                continue

            self.controller.sevenf_confirmed_clock = ConfirmedClock(
                utc=fields.to_timestamp(), monotonic=time.monotonic())
            return Destination(self.next_view_cls, view_args=self.next_view_args, skip_current_view=True)
