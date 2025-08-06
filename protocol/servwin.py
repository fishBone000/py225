import struct
from dataclasses import dataclass

@dataclass
class ServiceWindow:
    ports: tuple[int]
    sec_til_expire: int
    sec_til_next_win: int

    def pack(self):
        return struct.pack(f">H{len(self.ports)}HII", len(self.ports), *self.ports, self.sec_til_expire,
                           self.sec_til_next_win)

    @classmethod
    def unpack(cls, data):
        (num_ports,) = struct.unpack(">H", data[:2])
        ports = struct.unpack(f">{num_ports}H", data[2:2 + 2 * num_ports])
        (sec_til_expire, sec_til_next_win) = struct.unpack(">II", data[2 + 2 * num_ports:])
        return cls(ports, sec_til_expire, sec_til_next_win)
