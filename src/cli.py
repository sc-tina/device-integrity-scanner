#!/usr/bin/env python3
"""CLI for Device Integrity Scanner."""
import argparse, json, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
logger = logging.getLogger(__name__)
from typing import Any, Optional
from src.scanner import DeviceIntegrityScanner

def main():
    parser = argparse.ArgumentParser(description='Device Integrity Scanner')
    parser.add_argument('--device', '-d', default='')
    parser.add_argument('--json', action='store_true')
    sub = parser.add_subparsers(dest='command')
    scan_p = sub.add_parser('scan')
    scan_p.add_argument('--report', '-r')
    sub.add_parser('emulator')
    sub.add_parser('root')
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    s = DeviceIntegrityScanner(device_serial=args.device)
    if args.command == 'scan':
        result = s.scan()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Is Emulator: {result['is_emulator']}")
            print(f"Risk Score: {result['risk_score']}/100")
            print(f"Rooted: {result['root_check']['is_rooted']}")
            print(f"Debug: {result['debug_mode']}")
            print(f"SELinux: {result['selinux']}")
        if args.report:
            with open(args.report, 'w') as f:
                json.dump(result, f, indent=2)
    elif args.command == 'emulator':
        print(f"Is Emulator: {s.is_emulator()}")
    elif args.command == 'root':
        print(s.check_root())

if __name__ == '__main__':
    main()
