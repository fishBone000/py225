import argparse
import logging
import sys

import config
import log


def init(obj, name):
    obj.config = None

    parser = argparse.ArgumentParser(
        prog=name,
        description="PyProject 2025"
    )

    parser.add_argument("-c", "--config")
    parser.add_argument("-v", "--verbose", nargs="?", const="INFO")
    parser.add_argument("-l", "--log")

    args = parser.parse_args()

    verbosity = None

    if args.verbose:
        try:
            verbosity = args.verbose.upper()
            logging.root.setLevel(verbosity)
        except Exception as e:
            logging.warning(f"Invalid verbosity: {e}")

    obj.config = config.load(args.config, name)
    if verbosity is None:
        try:
            verbosity = obj.config.verbosity.upper()
            logging.root.setLevel(verbosity)
        except Exception as e:
            logging.warning(f"Invalid verbosity: {e}")

    try:
        logging.root = log.setup(name, args.log, verbosity)
    except Exception as e:
        logging.error("Failed to set up logger.", exc_info=True)
        sys.exit(1)
