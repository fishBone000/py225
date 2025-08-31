import os
import sys
from datetime import datetime
from logging import Handler, StreamHandler, FileHandler, Logger, DEBUG, Formatter
from logging.handlers import SysLogHandler, NTEventLogHandler


def gen_log_file_name() -> str:
    return f"py225-{os.getpid()}-{datetime.now().strftime("%Y-%m-%d-%H:%M")}.log"


def default_log_handler() -> Handler:
    match sys.platform:
        case "linux":
            if os.getppid() == 1:
                return SysLogHandler(address="/dev/log")
            elif not os.isatty(2):  # stderr
                if os.getenv("XDG_DATA_HOME"):
                    return FileHandler(os.getenv("XDG_DATA_HOME"))
                if os.getenv("HOME"):
                    return FileHandler(os.getenv("HOME") + f"/.local/share/py225/" + gen_log_file_name())
        case "win32":
            if os.getenv("LocalAppData"):
                return FileHandler(os.getenv("LocalAppData") + "\\py225\\" + gen_log_file_name())
    return StreamHandler(stream=sys.stderr)


def setup(name: str, log_path: str | None, lvl: str | int | None) -> Logger:
    fmt = "%(levelname)s %(asctime)s %(message)s"
    match log_path:
        case "stderr":
            handler = StreamHandler(stream=sys.stderr)
        case "syslog":
            if sys.platform != "linux":
                raise RuntimeError("only Linux systems support syslog")
            handler = SysLogHandler(address="/dev/log")
            fmt = "%(message)s"
        case "nt":
            if sys.platform != "win32":
                raise RuntimeError("only Windows systems support NT Event Log")
            handler = NTEventLogHandler(appname="py225")
            fmt = "%(message)s"
        case None:
            handler = default_log_handler()
        case _:
            handler = FileHandler(log_path)
    handler.setFormatter(Formatter(fmt))

    if lvl is not None:
        try:
            handler.setLevel(lvl)
        except Exception as e:
            e.add_note(f"bad logging level: {lvl}")
            raise
    elif isinstance(handler, (NTEventLogHandler, SysLogHandler)):  # Event Viewer and journalctl have level filter
        handler.setLevel(DEBUG)
    if not isinstance(handler, (NTEventLogHandler, SysLogHandler)):
        handler.setFormatter(Formatter(fmt="{levelname} {message}", style="{"))

    l = Logger(name)
    if lvl is not None:
        l.setLevel(lvl)
    elif isinstance(handler, SysLogHandler):
        l.setLevel(DEBUG)
    l.addHandler(handler)

    return l
