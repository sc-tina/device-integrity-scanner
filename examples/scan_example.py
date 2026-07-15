#!/usr/bin/env python3
"""Example: device integrity scan."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.scanner import DeviceIntegrityScanner

s = DeviceIntegrityScanner()
r = s.scan()
print(f"Emulator: {r['is_emulator']}, Rooted: {r['root_check']['is_rooted']}, Risk: {r['risk_score']}/100")
