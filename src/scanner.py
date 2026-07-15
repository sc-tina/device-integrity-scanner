"""Device integrity scanner - detects emulators, root, tampering."""
import logging, subprocess

log = logging.getLogger(__name__)

class DeviceIntegrityScanner:
    SUSPECT_BUILD = ['generic', 'vbox', 'qemu', 'emu', 'test']
    EMULATOR_FILES = [
        '/system/lib/libc_malloc_debug_qemu.so', '/system/xbin/qemu-props',
        '/system/bin/qemu-props'
    ]

    def __init__(self, device_serial=None):
        self._adb = ['adb']
        if device_serial:
            self._adb += ['-s', device_serial]

    def _run(self, cmd):
        try:
            r = subprocess.run(self._adb + cmd, capture_output=True, text=True, timeout=10)
            return r.stdout.strip()
        except:
            return ''

    def check_build(self):
        findings = []
        props = ['ro.build.user', 'ro.product.name', 'ro.product.device', 'ro.build.product',
                 'ro.kernel.qemu', 'ro.hardware']
        for p in props:
            val = self._run(['shell', 'getprop', p])
            for sus in self.SUSPECT_BUILD:
                if sus in val.lower():
                    findings.append({'property': p, 'value': val})
                    break
        return findings

    def check_sensors(self):
        result = {}
        for s in ['gsensor', 'lightsensor', 'proximitysensor']:
            v = self._run(['shell', 'dumpsys', 'sensorservice', '|', 'grep', '-i', s])
            result[s] = 'detected' if v else 'missing'
        return result

    def check_emulator_files(self):
        found = []
        for f in self.EMULATOR_FILES:
            out = self._run(['shell', 'ls', f])
            if out and 'No such file' not in out:
                found.append(f)
        return found

    def check_root(self):
        su_paths = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su']
        magisk = self._run(['shell', 'which', 'magisk'])
        found = [p for p in su_paths if 'No such file' not in self._run(['shell', 'ls', p])]
        return {'su_binaries': found, 'magisk': bool(magisk), 'is_rooted': bool(found) or bool(magisk)}

    def check_debug(self):
        return self._run(['shell', 'getprop', 'ro.debuggable']) == '1'

    def check_selinux(self):
        return self._run(['shell', 'getenforce'])

    def is_emulator(self):
        flags = self.check_build()
        sensor = any(v == 'missing' for v in self.check_sensors().values())
        emu_files = bool(self.check_emulator_files())
        return len(flags) >= 2 or sensor or emu_files

    def scan(self):
        return {
            'build_flags': self.check_build(),
            'sensors': self.check_sensors(),
            'emulator_files': self.check_emulator_files(),
            'root_check': self.check_root(),
            'debug_mode': self.check_debug(),
            'selinux': self.check_selinux(),
            'is_emulator': self.is_emulator(),
            'risk_score': self._calc_risk(),
        }

    def _calc_risk(self):
        score = 0
        if self.check_debug(): score += 20
        if self.check_root()['is_rooted']: score += 30
        if self.is_emulator(): score += 25
        return min(score, 100)
