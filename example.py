"""Scan for an ES/EFC treadmill, print data, and optionally send one command."""

import argparse
import asyncio
import json

from eqisports_light import Client, Protocol, scan


def show(event):
    print(json.dumps(event, ensure_ascii=False, default=str))


async def run(args):
    target = args.address
    name = args.name or ""

    if not target:
        devices = await scan(
            timeout=args.scan_timeout,
            names=[args.name] if args.name else None,
        )
        if not devices:
            raise RuntimeError("No ES/EFC treadmill found")
        for index, device in enumerate(devices, 1):
            print(
                f"{index}: {device.name or '(unnamed)'}  "
                f"{device.address}  RSSI={device.rssi}"
            )
        selected = devices[0]
        target, name = selected.device, selected.name
        print(f"Using the first device: {name} ({selected.address})")

    async with Client(
        target,
        name=name,
        protocol=Protocol(args.protocol),
        callback=show,
    ) as client:
        print(
            json.dumps(
                await client.read_information(),
                ensure_ascii=False,
                indent=2,
            )
        )
        if args.action:
            await client.command(
                args.action,
                args.value,
                allow_motion=args.allow_motion,
            )
        await asyncio.sleep(max(0, args.monitor))


def arguments():
    parser = argparse.ArgumentParser(description="Minimal ES/EFC Bluetooth example")
    parser.add_argument("--address", help="BLE address; scan when omitted")
    parser.add_argument("--name", help="Device name or name filter")
    parser.add_argument("--protocol", choices=("auto", "es", "efc"), default="auto")
    parser.add_argument("--scan-timeout", type=float, default=8)
    parser.add_argument(
        "--monitor",
        type=float,
        default=30,
        help="Monitoring duration in seconds",
    )
    parser.add_argument(
        "--action",
        choices=("start", "stop", "pause", "resume", "speed", "incline"),
    )
    parser.add_argument("--value", type=float, help="Value for speed or incline")
    parser.add_argument(
        "--allow-motion",
        action="store_true",
        help="Explicitly allow a command that may move the treadmill belt",
    )
    return parser.parse_args()


if __name__ == "__main__":
    try:
        asyncio.run(run(arguments()))
    except KeyboardInterrupt:
        pass
