#!/usr/bin/env python

import argparse
import logging
import sys

from seedsigner.controller import Controller

logger = logging.getLogger(__name__)

DEFAULT_MODULE_LOG_LEVELS = {
    "PIL": logging.WARNING,
    # "seedsigner.gui.toast": logging.DEBUG,  # example of more specific submodule logging config
}


def main(sys_argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-l",
        "--loglevel",
        choices=list((logging._nameToLevel.keys())),
        default="INFO",
        type=str,
        help=(
            "Set the log level (default: %(default)s), WARNING: changing the log level "
            "to something more verbose than %(default)s may result in unwanted data "
            "being written to stderr"
        ),
    )

    parser.add_argument(
        "--tripwire",
        choices=["auto", "enforce"],
        default="auto",
        help="Network tripwire mode: auto (from the image) or enforce (test it on the dev image). Nothing turns it off.",
    )

    args = parser.parse_args(sys_argv)

    from seedsigner.models import network_tripwire
    network_tripwire.force_enforce_requested = args.tripwire == "enforce"

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.getLevelName(args.loglevel))
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)8s [%(name)s %(funcName)s (%(lineno)d)]: %(message)s")
    )
    root_logger.addHandler(console_handler)

    # Set log levels for specific modules
    for module, level in DEFAULT_MODULE_LOG_LEVELS.items():
        logging.getLogger(module).setLevel(level)

    logger.info(f"Starting SeedSigner with: {args.__dict__}")

    # Get the one and only Controller instance and start our main loop
    Controller.get_instance().start()


if __name__ == "__main__":
    main(sys.argv[1:])
