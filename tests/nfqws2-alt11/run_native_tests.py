#!/usr/bin/env python3
"""Run ALT11 fixtures with an offline executable containing the real C Lua API.

GPL-2.0-or-later. Uses only Python's standard library; sends no packets.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: run_native_tests.py /path/to/native_lua_check')
    root = Path(__file__).resolve().parents[2]
    strategy = (root / 'files/strategies/nfqws2/alt11_nfqws2_full.txt').read_text()
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix='alt11-native-tests-') as temporary:
        blobs = Path(temporary) / 'blobs.lua'
        lines = []
        for alias, resource in re.findall(r'--blob=(\w+):@\$\{bin:([^}]+)\}', strategy):
            data = (root / 'files/bin' / (resource + '.bin')).read_bytes()
            chunks = ['string.char(' + ','.join(map(str, data[i:i+64])) + ')'
                      for i in range(0, len(data), 64)]
            lines.append(alias + '=' + (' .. '.join(chunks) if chunks else "''"))
        blobs.write_text('\n'.join(lines) + '\n')
        scripts = [blobs,
                   root / 'files/lua/alt11_zapret_lib_v0947.lua',
                   root / 'files/lua/alt11_zapret_antidpi_v0947.lua',
                   root / 'files/lua/alt11_port.lua',
                   root / 'tests/nfqws2-alt11/test_alt11.lua']
        result = subprocess.run([str(binary), *('@' + str(p) for p in scripts)],
                                text=True, capture_output=True)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        output = result.stdout + result.stderr
        if result.returncode or 'ALT11 offline packet tests: PASS' not in output or 'LUA ERROR' in output:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
