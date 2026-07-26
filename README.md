# ES/EFC Bluetooth example

A small educational Python example for direct communication with treadmills
using the proprietary ES or EFC protocol. It is based on static analysis of the
EQiSports application.

The project can:

- discover BLE devices by ES/EFC service or a known device name,
- use an embedded snapshot of the public EQI device-name list,
- automatically detect ES and EFC,
- read device information, telemetry, and training status,
- repair observed time, energy, and step-counter rollovers,
- send start, stop, pause, resume, speed, and incline commands.

It has no database, history, GUI, FTMS implementation, tests, or installation
package. This is a readable example, not a production-ready library.

## Run

Python 3.10+ and Bluetooth Low Energy are required:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python example.py
```

The example connects to the first discovered ES/EFC treadmill and prints JSON
events for 30 seconds. A device and monitoring duration can also be specified:

```powershell
python example.py --address "AA:BB:CC:DD:EE:FF" --protocol es --monitor 60
python example.py --name "ESLinker"
```

Control examples:

```powershell
python example.py --action stop
python example.py --action speed --value 3 --allow-motion
python example.py --action incline --value 2 --allow-motion
```

`start`, `resume`, `speed`, and `incline` require `--allow-motion`. Before
sending them, keep the treadmill under physical supervision, make sure it is
empty or safely occupied, and keep the emergency stop available.

## FTMS devices

The embedded EQI list contains device names, not protocol information, so a name
alone cannot reliably distinguish FTMS from ES/EFC. During scanning, the
example reports devices that advertise only the FTMS service and skips them:

```text
FTMS device detected. This example supports only ES/EFC; use the pyftms library for FTMS support.
```

The same guidance is returned when connecting directly to an FTMS device. Use
the `pyftms` library if FTMS support is required.

## Notes

`eqisports_light.py` contains all protocol logic. `example.py` is only a small
usage example. The implementation was derived from the analyzed app version
and may not cover every firmware variant.

## License

MIT, see `LICENSE`.
