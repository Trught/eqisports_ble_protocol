"""Small educational ES/EFC Bluetooth treadmill example."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import enum
import logging
import math
import random
from collections.abc import Callable, Iterable, Sequence
from typing import Any

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    BleakClient = None
    BleakScanner = None


LOG = logging.getLogger(__name__)


def uuid16(value: str) -> str:
    return f"0000{value.lower()}-0000-1000-8000-00805f9b34fb"


FTMS_SERVICE = uuid16("1826")  # detection only; FTMS is not implemented
FTMS_GUIDANCE = (
    "FTMS device detected. This example supports only ES/EFC; "
    "use the pyftms library for FTMS support."
)
ES_SERVICE, ES_NOTIFY, ES_WRITE = map(uuid16, ("fff0", "fff1", "fff2"))
EFC_SERVICE = "ffeeddcc-bbaa-9988-7766-554433221100"
EFC_WRITE = "ffeeddcc-bbaa-9988-7766-554433221101"
EFC_NOTIFY = "ffeeddcc-bbaa-9988-7766-554433221102"

DEFAULT_NAME_FILTERS = (
    "ESLinker",
    "ESBRLinker",
    "ESLinkerHR",
    "ESangLinker",
    "EsangLinker",
    "Superfit Linker",
    "SuperfitLinker",
    "GearStoneLinker",
    "CITYSPORTS",
    "N3601-A_GEARSTONE",
    "CITYSPORTS-Linker",
    "EQI-Treadmill-V1",
    "Mobvoi TM Pro",
    "GearStoneLinker-V1",
    "CITYSPORTS-V1",
    "GEARSTONE-Linker",
    "WELLFIT TM Linker",
    "POPFIT TM Linker",
    "AKSO TM Linker",
    "EQi TM Linker",
    "Treadmill Linker",
    "treadmill link",
    "treadmill linker",
    "TML25-0941",
    "WS200",
    "WS300",
    "EQiSports",
    "EQisports",
    "Moovv SmartStep",
    "Linker",
    "FitSmile Linker",
    "THERUN",
    "Blue Lion Simba",
    "Moovv SmartStep Incl",
    "Moovv SmartStep Pro",
    "Moovv 2 Pro+",
    "Moovv 2 Pro",
    "Moovv 2",
    "Cybergoing T10",
    "Cybergoing T12",
    "Cybergoing T16",
)

# Static EQI API snapshot retrieved on 2026-07-26.
DOWNLOADED_NAME_FILTERS = (
    "ESLinker",
    "ESBRLinker",
    "ESLinkerHR",
    "ESangLinker",
    "EsangLinker",
    "Superfit Linker",
    "SuperfitLinker",
    "GearStoneLinker",
    "CITYSPORTS",
    "N3601-A_GEARSTONE",
    "CITYSPORTS-Linker",
    "EQI-Treadmill-V1",
    "Mobvoi TM Pro",
    "GearStoneLinker-V1",
    "CITYSPORTS-V1",
    "GEARSTONE-Linker",
    "WELLFIT TM Linker",
    "POPFIT TM Linker",
    "AKSO TM Linker",
    "EQi TM Linker",
    "Treadmill Linker",
    "treadmill link",
    "treadmill linker",
    "WS200",
    "WS300",
    "EQiSports",
    "EQisports",
    "Linker",
    "FitSmile Linker",
    "TML25-0941",
    "THERUN",
    "Blue Lion Simba",
    "Moovv SmartStep Incl",
    "Moovv SmartStep",
    "Moovv SmartStep Pro",
    "Moovv 2",
    "Moovv 2 Pro",
    "Moovv 2 Pro+",
    "Cybergoing T10",
    "Cybergoing T12",
    "Cybergoing T16",
    "LiyLou",
    "Moov Run Plus",
    "Moov Run",
    "Moov Walk",
    "Moov Walk Plus",
    "Moveal-T",
    "Moveal-N",
    "EsangLinker FT",
    "T767",
    "SIMBA-1",
    "Xplorer JAGUAR",
    "T3844",
    "Xplorer TIGER",
    "New York S1",
    "New York S2",
    "FITT MILL",
    "T3895",
    "T4268B",
    "Xplorer Panther",
    "Xplorer PREDATOR",
    "Xplorer PUMA",
)


class Protocol(str, enum.Enum):
    AUTO = "auto"
    ES = "es"
    EFC = "efc"


class Error(RuntimeError):
    pass


class ProtocolError(Error):
    pass


class SafetyError(Error):
    pass


@dataclasses.dataclass
class Device:
    name: str
    address: str
    rssi: int | None
    device: Any = dataclasses.field(repr=False)
    advertised_services: tuple[str, ...] = ()


class CounterNormalizer:
    def __init__(self) -> None:
        self.elapsed_raw: int | None = None
        self.elapsed_offset = 0
        self.steps_raw: int | None = None
        self.steps_offset = 0

    @staticmethod
    def _value(
        raw: int,
        previous: int | None,
        offset: int,
        modulus: int,
    ) -> tuple[int, int, int]:
        if previous is not None and raw < previous:
            window = max(10, modulus // 100)
            offset = offset + modulus if previous >= modulus - window else 0
        return offset + raw, raw, offset

    def elapsed(self, raw: int) -> int:
        value, self.elapsed_raw, self.elapsed_offset = self._value(
            raw, self.elapsed_raw, self.elapsed_offset, 6000
        )
        return value

    def steps(self, raw: int) -> int:
        value, self.steps_raw, self.steps_offset = self._value(
            raw, self.steps_raw, self.steps_offset, 10000
        )
        return value

    @staticmethod
    def energy(distance: int, raw: int) -> int:
        candidate = raw + 1_000_000
        if raw and distance > 0 and distance * 29 > raw:
            if 25 < candidate / distance < 38:
                return candidate
        return raw


def xor_checksum(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value


def with_xor(data: bytes) -> bytes:
    return data + bytes([xor_checksum(data)])


def valid_xor(data: bytes) -> bool:
    return len(data) >= 2 and xor_checksum(data[:-1]) == data[-1]


def _need(data: bytes, offset: int, size: int) -> None:
    if offset + size > len(data):
        raise ProtocolError("Truncated packet")


def _ube(data: bytes, offset: int, size: int) -> int:
    return int.from_bytes(data[offset : offset + size], "big")


def _speed_from_byte(value: int, imperial: bool) -> float:
    return value * (16.09344 if imperial else 10.0) / 100.0


def _speed_to_byte(speed_kmh: float, imperial: bool) -> int:
    value = round(speed_kmh * 100 / (16.09344 if imperial else 10.0))
    if not 0 <= value <= 255:
        raise ValueError("Speed cannot be encoded")
    return value


ES_STATES = {
    0: "idle",
    1: "pre_workout",
    2: "running",
    3: "pausing",
    4: "paused",
    5: "post_workout",
    6: "stopped",
}
EFC_STATES = {
    1: "pre_workout",
    2: "running",
    3: "pausing",
    4: "paused",
    5: "post_workout",
    6: "idle",
}
ES_ERRORS = {
    1: "Control and display communication error",
    2: "Motor or motor cable disconnected",
    3: "Missing speed feedback signal",
    4: "Motor overcurrent",
    5: "Overload protection",
    6: "Inverter overheating",
    7: "Safety key disconnected",
    8: "Upper and lower control board communication error",
    9: "Bluetooth disconnected",
}
EFC_ERRORS = {
    17: "Console and control board communication error",
    18: "Sudden uncontrolled acceleration",
    20: "Incline motor cable disconnected",
    21: "Overcurrent protection",
    23: "Safety key disconnected",
    25: "Upper and lower control board communication error",
}


def parse_es(
    data: bytes,
    *,
    imperial: bool = False,
    counters: CounterNormalizer | None = None,
) -> dict[str, Any]:
    _need(data, 0, 3)
    prefix = data[:3].hex()
    result: dict[str, Any] = {
        "type": "unknown",
        "raw_hex": data.hex(),
        "checksum_valid": valid_xor(data),
    }
    counters = counters or CounterNormalizer()

    if prefix in {"a9020d", "a9020e"}:
        expected = 17 if prefix == "a9020d" else 18
        if len(data) != expected or not valid_xor(data):
            raise ProtocolError("Invalid ES heartbeat")
        distance = _ube(data, 7, 2)
        raw_energy = _ube(data, 4, 3) * 10
        result.update(
            type="telemetry",
            distance_m=distance,
            calories_kcal=counters.energy(distance, raw_energy) / 1000.0,
            steps=counters.steps(_ube(data, 9, 3)),
            elapsed_seconds=counters.elapsed(_ube(data, 12, 2)),
        )
    elif prefix == "a90901":
        _need(data, 3, 1)
        result.update(type="status", training_status=ES_STATES.get(data[3], "unknown"))
    elif prefix in {"a9f401", "a9e001"}:
        _need(data, 3, 1)
        result.update(type="speed", speed_kmh=_speed_from_byte(data[3], imperial))
    elif prefix == "a9e101":
        _need(data, 3, 1)
        result.update(type="incline", incline_percent=float(data[3]))
    elif prefix == "a90a04":
        _need(data, 3, 4)
        result.update(
            type="ranges",
            min_speed_kmh=_speed_from_byte(data[3], imperial),
            max_speed_kmh=_speed_from_byte(data[4], imperial),
            min_incline_percent=float(data[5]),
            max_incline_percent=float(data[6]),
        )
    elif prefix in {"a90301", "a90302"}:
        index = 3 if prefix == "a90301" else 4
        _need(data, index, 1)
        code = data[index]
        result.update(
            type="error",
            error_code=code,
            error_text=ES_ERRORS.get(code, f"Unknown ES error {code}"),
        )
    elif prefix in {"a91e05", "a91e0c"}:
        if len(data) < (9 if prefix == "a91e05" else 16):
            raise ProtocolError("Truncated ES device information")
        result.update(
            type="device_info",
            manufacturer=f"{data[3]:02x}",
            model=f"{data[4]:02x}",
            serial=f"{data[3]:02x}{data[4]:02x}",
            hardware_revision=f"{data[5]:02x}",
            firmware_revision=f"{data[6]:02x}",
            software_revision=f"{data[7]:02x}",
            system_id=(
                str(int.from_bytes(data[8:15], "big"))
                if prefix == "a91e0c"
                else "0"
            ),
        )
    elif prefix == "a9f203":
        _need(data, 3, 1)
        packet_imperial = data[3] == 2
        result.update(type="units", imperial=packet_imperial)
        if len(data) > 5:
            result.update(
                speed_kmh=_speed_from_byte(data[4], packet_imperial),
                incline_percent=float(data[5]),
            )
    elif prefix == "a9f301":
        _need(data, 3, 1)
        result.update(type="incline_support", incline_supported=data[3] != 0)
    elif prefix in {"a9f505", "a9f506"}:
        size = 5 if prefix == "a9f505" else 6
        _need(data, 3, size)
        result.update(
            type="sport_id",
            sport_id=str(int.from_bytes(data[3 : 3 + size], "big")),
        )
    elif prefix == "a90804":
        result["type"] = "pairing_challenge"
    elif data.hex().startswith("a90801ff5f"):
        result["type"] = "handshake_retry"
    return result


def parse_efc(
    data: bytes,
    *,
    counters: CounterNormalizer | None = None,
) -> dict[str, Any]:
    _need(data, 0, 3)
    if not valid_xor(data):
        raise ProtocolError("Invalid EFC XOR checksum")
    prefix = data[:3].hex()
    result: dict[str, Any] = {
        "type": "unknown",
        "raw_hex": data.hex(),
        "checksum_valid": True,
    }
    counters = counters or CounterNormalizer()

    if prefix == "1a050c":
        _need(data, 3, 12)
        revision = data[7:9].hex()
        result.update(
            type="device_info",
            manufacturer=data[3:5].hex(),
            model=data[5:7].hex(),
            serial=data[5:7].hex(),
            hardware_revision=revision,
            firmware_revision=revision,
            software_revision=revision,
            system_id=data[9:15].hex(),
        )
    elif prefix == "1a0109":
        _need(data, 3, 7)
        imperial = bool(data[9] & 0x80)
        state = data[9] & 0x1F
        result.update(
            type="state",
            imperial=imperial,
            max_speed_kmh=_speed_from_byte(data[3], imperial),
            min_speed_kmh=_speed_from_byte(data[4], imperial),
            max_incline_percent=float(data[5]),
            min_incline_percent=float(data[6]),
            speed_kmh=_speed_from_byte(data[7], imperial),
            incline_percent=float(data[8]),
            training_status=EFC_STATES.get(state, "unknown"),
            error_code=None,
            error_text=None,
        )
        if state in EFC_ERRORS:
            result.update(
                error_code=state,
                error_text=EFC_ERRORS[state],
                machine_status="equipment_fault",
            )
    elif prefix == "1a020c":
        _need(data, 3, 9)
        distance = _ube(data, 5, 2)
        raw_energy = _ube(data, 7, 2) * 100
        result.update(
            type="telemetry",
            elapsed_seconds=counters.elapsed(_ube(data, 3, 2)),
            distance_m=distance,
            calories_kcal=counters.energy(distance, raw_energy) / 1000.0,
            steps=counters.steps(_ube(data, 9, 2)),
            heart_rate_bpm=data[11],
        )
    elif prefix == "1a0410":
        _need(data, 9, 2)
        result.update(type="sport_id", sport_id=str(_ube(data, 9, 2)))
    return result


def es_command(action: str, value: float | None = None, *, imperial=False) -> bytes:
    action = action.replace("-", "_").lower()
    fixed = {
        "start": "a9a30101",
        "stop": "a9a30100",
        "pause": "a9a30103",
        "resume": "a9a30102",
        "device_info": "a91e01fe",
        "units": "a9f2012f",
        "sport_id": "a9b201fe",
        "current_speed": "a9ae01fe",
        "incline_support": "a99e01fe",
    }
    if action in fixed:
        return with_xor(bytes.fromhex(fixed[action]))
    if action == "ranges":
        return with_xor(bytes.fromhex("a90a01") + bytes([random.randrange(256)]))
    if action == "speed" and value is not None:
        return with_xor(
            bytes.fromhex("a90101") + bytes([_speed_to_byte(value, imperial)])
        )
    if action == "incline" and value is not None:
        raw = round(value)
        if 0 <= raw <= 255:
            return with_xor(bytes.fromhex("a90401") + bytes([raw]))
    raise ValueError(f"Invalid ES command: {action}")


def efc_command(action: str, value: float | None = None, *, imperial=False) -> bytes:
    action = action.replace("-", "_").lower()
    fixed = {
        "start": "a1030101",
        "resume": "a1030101",
        "pause": "a1030103",
        "stop": "a1030105",
        "device_info": "a10500",
        "sport_id": "a104050100000001",
    }
    if action in fixed:
        return with_xor(bytes.fromhex(fixed[action]))
    if action == "speed" and value is not None:
        return with_xor(
            bytes.fromhex("a1010201") + bytes([_speed_to_byte(value, imperial)])
        )
    if action == "incline" and value is not None:
        raw = round(value)
        if 0 <= raw <= 255:
            return with_xor(bytes.fromhex("a1020201") + bytes([raw]))
    raise ValueError(f"Invalid EFC command: {action}")


def es_handshake(*, hr=False) -> bytes:
    if not hr:
        return with_xor(bytes.fromhex("a90801") + bytes([random.randrange(255)]))
    mode, x, y = random.randrange(168), random.randrange(1, 255), random.randrange(1, 255)
    formulas = (
        [x, y, ((x + y + 1) << 1) % 256, (((x + 1) % y) << 2) % 256],
        [x, y, (((x + 2) % y) << 1) % 256, ((x + y + 2) << 2) % 256],
        [((x + y + 3) << 1) % 256, x, y, (((x + 3) % y) << 2) % 256],
        [(((x + 4) % y) << 1) % 256, x, y, ((x + y + 4) << 2) % 256],
        [((x + y + 5) << 1) % 256, (((x + 5) % y) << 2) % 256, x, y],
        [(((x + 6) % y) << 1) % 256, ((x + y + 6) << 2) % 256, x, y],
        [y, x, ((x + y + 7) << 1) % 256, (((x + 7) % y) << 2) % 256],
        [y, x, (((x + 8) % y) << 1) % 256, ((x + y + 8) << 2) % 256],
    )
    return with_xor(bytes([0xA9, 0x80, 0x05, mode, *formulas[mode % 8]]))


def es_pairing_response(challenge: int) -> bytes:
    x, y = random.randrange(1, 16), random.randrange(1, 16)
    layouts = (
        [x, y, x + y, x * y],
        [x, y, x * y, x + y],
        [x + y, x, y, x * y],
        [x * y, x, y, x + y],
        [x + y, x * y, x, y],
        [x * y, x + y, x, y],
    )
    return with_xor(
        bytes.fromhex("a90804")
        + bytes(value & 0xFF for value in layouts[challenge % 6])
    )


def all_name_filters() -> tuple[str, ...]:
    return tuple(dict.fromkeys((*DEFAULT_NAME_FILTERS, *DOWNLOADED_NAME_FILTERS)))


async def scan(
    timeout: float = 8.0,
    *,
    names: Sequence[str] | None = None,
) -> list[Device]:
    if BleakScanner is None:
        raise Error("Install bleak: python -m pip install -r requirements.txt")
    try:
        found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    except TypeError:
        found = await BleakScanner.discover(timeout=timeout)
    filters = tuple(names) if names is not None else all_name_filters()
    rows = []
    if isinstance(found, dict):
        for device, advertisement in found.values():
            services = tuple(
                uuid.lower()
                for uuid in (getattr(advertisement, "service_uuids", None) or ())
            )
            rows.append((device, getattr(advertisement, "rssi", None), services))
    else:
        rows = [
            (device, getattr(device, "rssi", None), ())
            for device in found
        ]
    result = []
    for device, rssi, services in rows:
        name = getattr(device, "name", None) or ""
        supports_es_efc = ES_SERVICE in services or EFC_SERVICE in services
        ftms_only = FTMS_SERVICE in services and not supports_es_efc
        if ftms_only:
            address = getattr(device, "address", str(device))
            label = f"{name} ({address})" if name else address
            print(f"{FTMS_GUIDANCE} Device: {label}")
            continue
        if not (
            supports_es_efc or any(fragment in name for fragment in filters)
        ):
            continue
        result.append(
            Device(
                name,
                getattr(device, "address", str(device)),
                rssi,
                device,
                services,
            )
        )
    return sorted(result, key=lambda item: item.rssi or -999, reverse=True)


class Client:
    """Connect, read state, and send explicitly authorized ES/EFC commands."""

    def __init__(
        self,
        target: Any,
        *,
        protocol: Protocol | str = Protocol.AUTO,
        name: str = "",
        callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.target = target
        self.protocol_hint = Protocol(protocol)
        self.name = name or getattr(target, "name", "") or ""
        self.address = getattr(target, "address", None) or str(target)
        self.callback = callback
        self.protocol = Protocol.AUTO
        self.telemetry: dict[str, Any] = {"training_status": "unknown"}
        self.capabilities: dict[str, Any] = {"imperial": False}
        self.information: dict[str, Any] = {}
        self._ble: Any = None
        self._characteristics: set[str] = set()
        self._write_lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._information_received = asyncio.Event()
        self._counters = CounterNormalizer()
        self._paired = False
        self._queries_sent = False

    async def __aenter__(self) -> "Client":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.disconnect()

    @property
    def connected(self) -> bool:
        return bool(self._ble and self._ble.is_connected)

    def _emit(self, event: str, **values: Any) -> None:
        if not self.callback:
            return
        try:
            self.callback(
                {
                    "event": event,
                    "protocol": self.protocol.value,
                    "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                    **values,
                }
            )
        except Exception:
            LOG.exception("Callback failed")

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)

        def finished(done: asyncio.Task[Any]) -> None:
            self._tasks.discard(done)
            if done.cancelled():
                return
            error = done.exception()
            if error:
                self._emit("background_error", error=str(error))

        task.add_done_callback(finished)

    async def connect(self) -> None:
        if BleakClient is None:
            raise Error("Install bleak: python -m pip install -r requirements.txt")
        self._ble = BleakClient(self.target)
        try:
            await self._ble.connect()
            services = self._ble.services
            if services is None and hasattr(self._ble, "get_services"):
                services = await self._ble.get_services()
            service_ids = set()
            for service in services:
                service_ids.add(service.uuid.lower())
                self._characteristics.update(
                    item.uuid.lower() for item in service.characteristics
                )
            if self.protocol_hint is Protocol.AUTO:
                if EFC_SERVICE in service_ids:
                    self.protocol = Protocol.EFC
                elif ES_SERVICE in service_ids:
                    self.protocol = Protocol.ES
                elif FTMS_SERVICE in service_ids:
                    raise ProtocolError(FTMS_GUIDANCE)
                else:
                    raise ProtocolError("Device does not provide an ES or EFC service")
            else:
                expected = (
                    ES_SERVICE
                    if self.protocol_hint is Protocol.ES
                    else EFC_SERVICE
                )
                if expected not in service_ids:
                    if FTMS_SERVICE in service_ids:
                        raise ProtocolError(FTMS_GUIDANCE)
                    raise ProtocolError(
                        f"Device does not provide the "
                        f"{self.protocol_hint.value.upper()} service"
                    )
                self.protocol = self.protocol_hint
            notify = ES_NOTIFY if self.protocol is Protocol.ES else EFC_NOTIFY
            if notify not in self._characteristics:
                raise ProtocolError("Notification characteristic is missing")
            await self._ble.start_notify(notify, self._notification)
            self._emit("connected", address=self.address, name=self.name)
            if self.protocol is Protocol.ES:
                await self._write(ES_WRITE, es_handshake(hr=self.name == "ESLinkerHR"))
                self._spawn(self._retry_es_handshake())
            else:
                await self._send("device_info")
                await self._send("sport_id")
        except BaseException:
            await self.disconnect()
            raise

    async def disconnect(self) -> None:
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        if self._ble and self._ble.is_connected:
            await self._ble.disconnect()

    async def _write(self, uuid: str, data: bytes) -> None:
        if uuid not in self._characteristics:
            raise ProtocolError(f"Write characteristic is missing: {uuid}")
        async with self._write_lock:
            await self._ble.write_gatt_char(uuid, data, response=True)
            await asyncio.sleep(0.15)

    async def _send(self, action: str, value: float | None = None) -> None:
        imperial = bool(self.capabilities.get("imperial"))
        if self.protocol is Protocol.ES:
            await self._write(ES_WRITE, es_command(action, value, imperial=imperial))
        elif self.protocol is Protocol.EFC:
            await self._write(EFC_WRITE, efc_command(action, value, imperial=imperial))
        else:
            raise Error("Client is not connected")

    async def command(
        self,
        action: str,
        value: float | None = None,
        *,
        allow_motion: bool = False,
    ) -> None:
        action = action.replace("-", "_").lower()
        if action in {"start", "resume", "speed", "incline"} and not allow_motion:
            raise SafetyError(
                "Motion commands require allow_motion=True and physical "
                "supervision of the treadmill"
            )
        if value is not None and not math.isfinite(value):
            raise SafetyError("Value must be a finite number")
        if action == "speed":
            if value is None or not 0 <= value <= 20:
                raise SafetyError("Speed must be between 0 and 20 km/h")
            minimum = self.capabilities.get("min_speed_kmh")
            maximum = self.capabilities.get("max_speed_kmh")
            if value > 0 and minimum is not None and value < minimum:
                raise SafetyError(f"Device minimum is {minimum:g} km/h")
            if maximum is not None and value > maximum:
                raise SafetyError(f"Device maximum is {maximum:g} km/h")
        if action == "incline":
            if value is None or not 0 <= value <= 20:
                raise SafetyError("Incline must be between 0 and 20%")
            if self.capabilities.get("incline_supported") is False:
                raise SafetyError("Device does not support incline")
        await self._send(action, value)

    async def read_information(self, timeout: float = 3.0) -> dict[str, Any]:
        self._information_received.clear()
        if self.protocol is Protocol.ES:
            if self._paired:
                await self._query_es()
            else:
                await self._write(
                    ES_WRITE, es_handshake(hr=self.name == "ESLinkerHR")
                )
        elif self.protocol is Protocol.EFC:
            await self._send("device_info")
            await self._send("sport_id")
        if timeout > 0:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._information_received.wait(), timeout)
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol.value,
            "address": self.address,
            "name": self.name,
            "capabilities": dict(self.capabilities),
            "information": dict(self.information),
            "telemetry": dict(self.telemetry),
        }

    async def _retry_es_handshake(self) -> None:
        for _ in range(4):
            await asyncio.sleep(3)
            if self._paired or not self.connected:
                return
            await self._write(
                ES_WRITE, es_handshake(hr=self.name == "ESLinkerHR")
            )

    async def _pair_es(self, challenge: int) -> None:
        if self._paired:
            return
        await self._write(ES_WRITE, es_pairing_response(challenge))
        self._paired = True
        await self._query_es()

    async def _query_es(self) -> None:
        self._queries_sent = True
        for action in (
            "units",
            "device_info",
            "ranges",
            "incline_support",
            "sport_id",
            "current_speed",
        ):
            await self._send(action)

    def _notification(self, _: Any, raw: bytearray) -> None:
        data = bytes(raw)
        try:
            decoded = (
                parse_es(
                    data,
                    imperial=bool(self.capabilities.get("imperial")),
                    counters=self._counters,
                )
                if self.protocol is Protocol.ES
                else parse_efc(data, counters=self._counters)
            )
            kind = decoded["type"]
            if kind == "pairing_challenge":
                challenge = data[-2] if valid_xor(data) else data[-1]
                self._spawn(self._pair_es(challenge))
            elif kind == "handshake_retry":
                self._spawn(
                    self._write(
                        ES_WRITE,
                        es_handshake(hr=self.name == "ESLinkerHR"),
                    )
                )
            elif kind == "device_info":
                self.information.update(
                    {
                        key: value
                        for key, value in decoded.items()
                        if key
                        in {
                            "manufacturer",
                            "model",
                            "serial",
                            "hardware_revision",
                            "firmware_revision",
                            "software_revision",
                            "system_id",
                        }
                    }
                )
                self._information_received.set()
                self._emit("device_info", information=dict(self.information))
            elif kind in {"ranges", "units", "incline_support", "state"}:
                for key in (
                    "imperial",
                    "min_speed_kmh",
                    "max_speed_kmh",
                    "min_incline_percent",
                    "max_incline_percent",
                    "incline_supported",
                ):
                    if key in decoded:
                        self.capabilities[key] = decoded[key]
                self._emit("capabilities", capabilities=dict(self.capabilities))
                if kind == "state":
                    self._update_telemetry(decoded, data)
            elif kind in {
                "telemetry",
                "status",
                "speed",
                "incline",
                "sport_id",
                "error",
            }:
                self._update_telemetry(decoded, data)
            else:
                self._emit("notification", decoded=decoded)
        except Exception as exc:
            self._emit("parse_error", raw_hex=data.hex(), error=str(exc))

    def _update_telemetry(self, decoded: dict[str, Any], raw: bytes) -> None:
        for key in (
            "speed_kmh",
            "distance_m",
            "incline_percent",
            "calories_kcal",
            "heart_rate_bpm",
            "elapsed_seconds",
            "steps",
            "training_status",
            "machine_status",
            "error_code",
            "error_text",
            "sport_id",
        ):
            if key in decoded:
                self.telemetry[key] = decoded[key]
        self.telemetry["raw_hex"] = raw.hex()
        self.telemetry["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        self._emit("telemetry", telemetry=dict(self.telemetry))
