# Packet Sniffer

A simple packet sniffer built with [Scapy](https://scapy.readthedocs.io/en/latest/) in Python.  
**Use this tool responsibly and only on networks you have explicit permission to monitor.**

## Features

- Captures packets on a specified interface (default is `en0` on macOS).
- Prints out detailed packet information on the screen.
- Stops automatically after capturing a certain number of packets (default is `10`).

## Requirements

- Python 3.6+ (ideally 3.8+)
- [Scapy](https://scapy.readthedocs.io/en/latest/)

You can install Scapy using:

```bash
pip install scapy
