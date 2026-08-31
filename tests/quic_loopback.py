"""Local QUIC echo with independent UDP byte counts; uses no public server.

Start this first with a fresh absolute report path, then run udpstats_test.exe
--watch REPORT PID elevated using the PID printed here. aioquic 1.3 is required.
"""
import asyncio
import datetime
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import socket
import sys

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class Meter:
    def __init__(self):
        self.sent = self.received = 0
        self.port = 0


class MeteredTransport:
    def __init__(self, transport, meter):
        self.transport, self.meter = transport, meter

    def sendto(self, data, addr=None):
        self.transport.sendto(data, addr)
        self.meter.sent += len(data)

    def __getattr__(self, name):
        return getattr(self.transport, name)


class MeteredProtocol(asyncio.DatagramProtocol):
    def __init__(self, protocol, meter):
        self.protocol, self.meter = protocol, meter

    def connection_made(self, transport):
        self.meter.port = transport.get_extra_info("sockname")[1]
        self.protocol.connection_made(MeteredTransport(transport, self.meter))

    def datagram_received(self, data, addr):
        self.meter.received += len(data)
        self.protocol.datagram_received(data, addr)

    def error_received(self, exc):
        self.protocol.error_received(exc)

    def connection_lost(self, exc):
        self.protocol.connection_lost(exc)


async def wait_marker(report, suffix, timeout=40):
    path = Path(str(report) + "." + suffix)
    async def wait():
        while not path.exists():
            await asyncio.sleep(0.05)
    await asyncio.wait_for(wait(), timeout)


async def main(report):
    print(f"QUIC_PID={os.getpid()}", flush=True)
    await wait_marker(report, "started")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("::1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    server_config = QuicConfiguration(is_client=False, alpn_protocols=["simplewall-test"])
    server_config.certificate, server_config.private_key = certificate, key
    client_config = QuicConfiguration(is_client=True, alpn_protocols=["simplewall-test"], server_name="localhost")
    # Trust only this test's ephemeral certificate, without changing any trust store.
    from cryptography.hazmat.primitives import serialization
    client_config.load_verify_locations(cadata=certificate.public_bytes(serialization.Encoding.PEM))

    async def echo(reader, writer):
        data = await reader.read()
        writer.write(data)
        writer.write_eof()

    server = QuicServer(configuration=server_config, stream_handler=lambda r, w: asyncio.create_task(echo(r, w)))
    client = QuicConnectionProtocol(QuicConnection(configuration=client_config))
    meters = [Meter(), Meter()]
    loop = asyncio.get_running_loop()
    transports = []
    try:
        for protocol, meter in zip([server, client], meters):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.bind(("::1", 0))
            sock.setblocking(False)
            transport, _ = await loop.create_datagram_endpoint(lambda p=protocol, m=meter: MeteredProtocol(p, m), sock=sock)
            transports.append(transport)
        await wait_marker(report, "ready")
        client.connect(("::1", meters[0].port, 0, 0))
        await asyncio.wait_for(client.wait_connected(), 10)
        payload = bytes(range(256)) * 4096
        reader, writer = await client.create_stream()
        writer.write(payload)
        writer.write_eof()
        received = await asyncio.wait_for(reader.read(), 15)
        assert received == payload, "QUIC echo data mismatch"
        await asyncio.sleep(3)
        results = {
            "pid": os.getpid(), "protocol": "QUIC", "echo_bytes": len(received),
            "sha256": hashlib.sha256(received).hexdigest(),
            "endpoints": [vars(m).copy() for m in meters],
        }
        Path(str(report) + ".done").write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(json.dumps(results), flush=True)
        await wait_marker(report, "finished")
        measured = {
            int(port): (int(sent), int(received), int(error))
            for port, sent, received, error in re.findall(
                r"WATCH pid=\d+ af=\d+ port=(\d+) sent=(\d+) received=(\d+) error=(\d+)",
                report.read_text(encoding="utf-8"),
            )
        }
        for endpoint in results["endpoints"]:
            expected = (endpoint["sent"], endpoint["received"], 0)
            assert measured.get(endpoint["port"]) == expected, (endpoint, measured)
        print("QUIC_ACCOUNTING: PASS (both endpoints, both directions)", flush=True)
    finally:
        for transport in transports:
            transport.close()


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]).resolve()))
