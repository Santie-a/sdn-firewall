"""
SDN Firewall — Traffic Generator
Sends configurable UDP or TCP traffic to a target node for rule testing.

Examples
--------
# 10 UDP packets to port 9000, one every 0.5 s
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --count 10 --interval 0.5

# 5 TCP connections with a custom message
python generator.py --ip 192.168.1.101 --port 9000 --protocol TCP --count 5 --message "hello"

# Continuous flood (Ctrl+C to stop)
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --count 0 --interval 0.1

# Spoof a specific source port (UDP only)
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --src-port 4444

# Announce a VLAN / a specific source MAC (for VLAN and MAC rule tests)
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --vlan 20
python generator.py --ip 192.168.1.101 --port 9000 --protocol UDP --src-mac aa:bb:cc:dd:ee:ff
"""
from __future__ import annotations

import argparse
import socket
import time
import uuid


def _own_mac() -> str:
    """This machine's MAC as lowercase aa:bb:cc:dd:ee:ff."""
    mac = uuid.getnode()
    return ":".join(f"{(mac >> b) & 0xff:02x}" for b in range(40, -1, -8))


def _build_header(src_mac: str, vlan: int | None) -> bytes:
    """SDN metadata header prepended to every packet:  SDN1|k=v;...|

    Lets the receiving client match on a self-reported MAC / VLAN, which a
    socket-based listener cannot otherwise observe.
    """
    parts = [f"src_mac={src_mac}"]
    if vlan is not None:
        parts.append(f"vlan={vlan}")
    return b"SDN1|" + ";".join(parts).encode() + b"|"


def _send_udp(
    dst_ip: str,
    dst_port: int,
    src_port: int | None,
    message: bytes,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src_port:
        sock.bind(("0.0.0.0", src_port))
    try:
        sock.sendto(message, (dst_ip, dst_port))
    finally:
        sock.close()


def _send_tcp(dst_ip: str, dst_port: int, message: bytes) -> str:
    """Returns the server response or an error string."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((dst_ip, dst_port))
        sock.sendall(message)
        response = sock.recv(1024)
        return response.decode(errors="replace").strip()
    except ConnectionRefusedError:
        return "REFUSED"
    except OSError as e:
        return f"ERROR: {e}"
    finally:
        sock.close()


def run(args: argparse.Namespace) -> None:
    protocol = args.protocol.upper()
    src_mac  = args.src_mac or _own_mac()
    header   = _build_header(src_mac, args.vlan)
    message  = header + args.message.encode()
    count    = args.count
    infinite = count == 0
    sent     = 0

    vlan_note = f"vlan={args.vlan}" if args.vlan is not None else "vlan=(none)"
    print(f"[generator] {protocol} -> {args.ip}:{args.port}  "
          f"count={'∞' if infinite else count}  interval={args.interval}s")
    print(f"[generator] announcing src_mac={src_mac}  {vlan_note}")
    print("[generator] Press Ctrl+C to stop.\n")

    try:
        while infinite or sent < count:
            sent += 1
            ts = time.strftime("%H:%M:%S")

            if protocol == "UDP":
                _send_udp(args.ip, args.port, args.src_port, message)
                print(f"[{ts}] UDP #{sent:>4}  {args.ip}:{args.port}  {len(message)} B")

            else:  # TCP
                response = _send_tcp(args.ip, args.port, message)
                print(f"[{ts}] TCP #{sent:>4}  {args.ip}:{args.port}  "
                      f"response='{response}'")

            if infinite or sent < count:
                time.sleep(args.interval)

    except KeyboardInterrupt:
        pass

    print(f"\n[generator] Done. {sent} packet(s) sent.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SDN Firewall traffic generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--ip",       required=True,          help="Destination IP")
    parser.add_argument("--port",     required=True, type=int, help="Destination port")
    parser.add_argument("--protocol", default="UDP",
                        choices=["UDP", "TCP", "udp", "tcp"],  help="Protocol (default: UDP)")
    parser.add_argument("--count",    default=10,   type=int,
                        help="Number of packets to send; 0 = infinite (default: 10)")
    parser.add_argument("--interval", default=1.0,  type=float,
                        help="Seconds between sends (default: 1.0)")
    parser.add_argument("--message",  default="SDN-TEST",
                        help="Payload string (default: 'SDN-TEST')")
    parser.add_argument("--src-port", default=None, type=int,
                        help="Bind to this source port before sending (UDP only)")
    parser.add_argument("--src-mac",  default=None,
                        help="Source MAC to announce (default: this machine's MAC)")
    parser.add_argument("--vlan",     default=None, type=int,
                        help="VLAN ID to announce in the packet header")

    run(parser.parse_args())


if __name__ == "__main__":
    main()
