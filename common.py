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

    parser.add_argument("-c", "--config", nargs=1)
    parser.add_argument("-v", "--verbose", nargs="?", const="info", default="warning")
    parser.add_argument("-l", "--log", nargs=1)

    args = parser.parse_args()

    if args.verbose:
        try:
            logging.root.setLevel(args.verbose)
        except Exception as e:
            logging.warning(f"Invalid verbosity: {e}")

    obj.config = config.load(args.config, name)
    if not args.verbose:
        try:
            logging.root.setLevel(obj.config.verbosity)
        except Exception as e:
            logging.warning(f"Invalid verbosity: {e}")

    try:
        logging.root = log.setup(name, args.log, args.verbose or obj.config.verbosity)
    except Exception as e:
        logging.error(e)
        sys.exit(1)
