"""
Frida runner wrapper (safe, minimal).

This wrapper calls the `frida` CLI. It returns findings as a list of dicts.
IMPORTANT: Do NOT run frida scripts against apps/devices without explicit authorization.
"""
import subprocess
import shlex
import os
from typing import List, Dict

FRIDA_BIN = "frida"  # assumes frida CLI available (frida-tools)

def run_frida_script(package: str, script_path: str, timeout: int = 30) -> List[Dict]:
    findings = []
    if not os.path.exists(script_path):
        return [{"type": "error", "message": f"Frida script not found: {script_path}"}]

    # prefer attaching to running process if possible (-n). We'll try -n then fallback to -f spawn.
    cmds = [
        f"{FRIDA_BIN} -U -n {package} -l {script_path} --no-pause",   # attach if process exists
        f"{FRIDA_BIN} -U -f {package} -l {script_path} --no-pause"    # spawn+attach
    ]

    for cmd in cmds:
        try:
            proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate(timeout=timeout)
            if out:
                findings.append({"type": "info", "message": f"frida output (cmd: {cmd})", "evidence": out})
            if err:
                findings.append({"type": "warning", "message": f"frida stderr (cmd: {cmd})", "evidence": err})
            # If we got any stdout, probably succeeded; stop trying further cmds
            if out:
                break
        except subprocess.TimeoutExpired:
            proc.kill()
            findings.append({"type": "warning", "message": f"frida command timed out: {cmd}"})
        except FileNotFoundError:
            return [{"type": "error", "message": "frida CLI not found. Install frida-tools with `pip install frida-tools`"}]
        except Exception as e:
            findings.append({"type": "error", "message": f"frida run failed: {e}"})

    if not findings:
        findings.append({"type": "warning", "message": "No frida output captured; confirm frida-server and device connection."})
    return findings
