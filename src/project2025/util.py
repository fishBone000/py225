from asyncio import StreamReader, StreamWriter, TaskGroup

from .protocol.transport import TCPTransport, TCP_TRANSPORT_MAX_SIZE_BYTES


def join_host_port(addr: tuple[str, int]) -> str:
    host, port = addr
    if ":" in host:
        # Is IPv6
        return f"[{host}]:{port}"
    return f"{host}:{port}"


class __TerminateTaskGroup(Exception):
    pass


async def relay(rw: tuple[StreamReader, StreamWriter], t: TCPTransport):
    try:
        async with TaskGroup() as tg:
            r, w = rw
            t1 = tg.create_task(relay_s2t(r, t))
            t2 = tg.create_task(relay_t2s(t, w))
    except* __TerminateTaskGroup:
        pass


async def relay_s2t(r: StreamReader, t: TCPTransport):
    d = await r.read(4096)
    while d:
        while d:
            snd = d[:min(len(d), TCP_TRANSPORT_MAX_SIZE_BYTES)]
            await t.sendall(snd)
            d = d[len(snd):]
        d = await r.read(4096)
    raise __TerminateTaskGroup


async def relay_t2s(t: TCPTransport, w: StreamWriter):
    d = await t.recv()
    while d:
        w.write(d)
        await w.drain()
        d = await t.recv()
    raise __TerminateTaskGroup

def conn_err_str(e: ConnectionError) -> str:
    match e:
        case ConnectionResetError():
            return "connection reset"
        case ConnectionRefusedError():
            return "connection refused"
        case ConnectionAbortedError():
            return "connection aborted"
        case BrokenPipeError():
            return "broken pipe"
        case _:
            return str(type(e))