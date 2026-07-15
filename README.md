# Device Integrity Scanner

Android device integrity scanner that detects emulators, root access, and security vulnerabilities via ADB.

## Features
- Emulator detection via build properties, files, and sensors
- Root detection (su binaries, Magisk)
- SELinux enforcement check
- Debug mode flag detection
- Risk scoring (0-100)

## Usage
```bash
python src/cli.py scan
python src/cli.py scan --report report.json
python src/cli.py emulator
python src/cli.py root
```

## Contact
- Website: https://www.qtphone.com/
