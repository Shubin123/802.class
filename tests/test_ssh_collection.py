"""Critical collection checks: authentication evidence and cleanup on failure."""
import subprocess
import sys
from pathlib import Path

import pytest

from data.real import collect_ssh

LINK = 'Connected to 02:00:00:00:00:01 (on wlan0)\n\tSSID: James\n\tfreq: 2412.0\n'
SCAN = 'BSS 02:00:00:00:00:01(on wlan0) -- associated\n\tRSN:\n\t * Pairwise ciphers: CCMP\n\t * Authentication suites: PSK\n'


def fake_run(calls, *, fail_capture=False, scan=SCAN):
    def run(command, **kwargs):
        calls.append(command)
        out = ''
        if command[0] == 'ssh':
            remote = command[-1]
            if remote.startswith('iw dev wlan0 link'):
                out = LINK
            elif remote.startswith('cat /sys/'):
                out = '02:00:00:00:00:11\n'
            elif remote.endswith('scan dump'):
                out = scan
        elif command[0] == 'dumpcap':
            if '-L' in command:
                out = 'IEEE802_11_RADIO\n'
            elif fail_capture:
                raise subprocess.CalledProcessError(1, command, stderr='capture failed')
        return subprocess.CompletedProcess(command, 0, out, '')
    return run


def arguments(monkeypatch, out: Path, security='wpa2'):
    monkeypatch.setattr(sys, 'argv', ['collect_ssh', '--dut-host', 'cm4', '--security', security,
        '--label', 'test', '--url', 'https://example.com', '--sessions', '1', '--duration', '5',
        '--out', str(out), '--prepare-monitor', 'prepare {interface} {frequency}',
        '--restore-network', 'restore {interface} James'])


def test_restore_james_even_when_dumpcap_fails(monkeypatch, tmp_path):
    calls = []
    arguments(monkeypatch, tmp_path)
    monkeypatch.setattr(collect_ssh.subprocess, 'run', fake_run(calls, fail_capture=True))
    def fail(command, timeout):
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(collect_ssh, 'run_capture', fail)
    with pytest.raises(subprocess.CalledProcessError):
        collect_ssh.main()
    assert ['prepare', 'en0', '2412'] in calls
    assert calls[-1] == ['restore', 'en0', 'James']
    assert not (tmp_path / 'manifest.csv').exists()


def test_wpa3_rejects_psk_evidence_before_any_traffic(monkeypatch, tmp_path):
    calls = []
    arguments(monkeypatch, tmp_path, security='wpa3')
    monkeypatch.setattr(collect_ssh.subprocess, 'run', fake_run(calls))
    with pytest.raises(SystemExit) as exc:
        collect_ssh.main()
    assert exc.value.code == 2
    assert not any(command[0] == 'dumpcap' or 'nohup' in command[-1] for command in calls)
    assert not (tmp_path / 'manifest.csv').exists()


def test_sae_only_gcmp_evidence_reaches_capture_and_restores(monkeypatch, tmp_path):
    calls = []
    arguments(monkeypatch, tmp_path, security='wpa3')
    scan = SCAN.replace('CCMP', 'GCMP').replace('PSK', 'SAE')
    monkeypatch.setattr(collect_ssh.subprocess, 'run', fake_run(calls, fail_capture=True, scan=scan))
    def fail(command, timeout):
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(collect_ssh, 'run_capture', fail)
    with pytest.raises(subprocess.CalledProcessError):
        collect_ssh.main()
    assert ['prepare', 'en0', '2412'] in calls
    assert calls[-1] == ['restore', 'en0', 'James']


def test_cancelled_capture_releases_device_before_recovery(monkeypatch):
    events = []
    class Process:
        running = True
        def wait(self, timeout=None):
            if self.running:
                raise KeyboardInterrupt
            events.append('reaped')
            return 0
        def poll(self):
            return None if self.running else 0
        def terminate(self):
            events.append('terminate')
            self.running = False
    monkeypatch.setattr(collect_ssh.subprocess, 'Popen', lambda *a, **kw: Process())
    with pytest.raises(KeyboardInterrupt):
        collect_ssh.run_capture(['dumpcap'], timeout=5)
    assert events == ['terminate', 'reaped']
