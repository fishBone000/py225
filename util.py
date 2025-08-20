from asyncio import StreamReader, StreamWriter, TaskGroup

from protocol.transport import TCPTransport


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
            tg.create_task(relay_s2t(r, t))
            tg.create_task(relay_t2s(t, w))
    except __TerminateTaskGroup:
        pass

async def relay_s2t(r: StreamReader, t: TCPTransport):
    d = await r.read(4096)
    while d:
        await t.sendall(d)
        d = await r.read(4096)
    raise __TerminateTaskGroup


async def relay_t2s(t: TCPTransport, w: StreamWriter):
    d = await t.recv()
    while d:
        w.write(d)
        await w.drain()
        d = await t.recv()
    raise __TerminateTaskGroup
