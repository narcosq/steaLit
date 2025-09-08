"""
Installed Software Collector Module
Refactored from installed.py for better integration
"""

import os
import sys
import ctypes
import itertools
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import winreg
except ImportError:
    print("This script must be run on Windows (winreg not available).")
    sys.exit(1)


def get_file_version_via_ctypes(path: str) -> Optional[str]:
    """Return file version as 'major.minor.build.revision' using WinAPI (ctypes)."""
    try:
        path_w = ctypes.c_wchar_p(path)
        size = ctypes.windll.version.GetFileVersionInfoSizeW(path_w, None)
        if not size:
            return None
        res = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(path_w, 0, size, res):
            return None
        lptr = ctypes.c_void_p()
        lsize = ctypes.c_uint()
        if not ctypes.windll.version.VerQueryValueW(res, ctypes.c_wchar_p(r"\VarFileInfo\Translation"), ctypes.byref(lptr), ctypes.byref(lsize)):
            ffi_ptr = ctypes.c_void_p()
            ffi_len = ctypes.c_uint()
            if ctypes.windll.version.VerQueryValueW(res, ctypes.c_wchar_p("\\"), ctypes.byref(ffi_ptr),
                                                    ctypes.byref(ffi_len)):
                VS_FIXEDFILEINFO = ctypes.c_uint * (ffi_len.value // ctypes.sizeof(ctypes.c_uint))
                ffi = VS_FIXEDFILEINFO.from_address(ffi_ptr.value)
                ms = ffi[2]
                ls = ffi[3]
                major = (ms >> 16) & 0xFFFF
                minor = ms & 0xFFFF
                build = (ls >> 16) & 0xFFFF
                rev = ls & 0xFFFF
                return f"{major}.{minor}.{build}.{rev}"
            return None

        trans = (ctypes.c_ushort * (lsize.value // ctypes.sizeof(ctypes.c_ushort))).from_address(lptr.value)
        lang, codepage = trans[0], trans[1]
        sub_block = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileVersion"
        buf = ctypes.c_wchar_p()
        blen = ctypes.c_uint()
        if ctypes.windll.version.VerQueryValueW(res, ctypes.c_wchar_p(sub_block), ctypes.byref(buf), ctypes.byref(blen)) and buf.value:
            return buf.value.strip().split(" ")[0]
        return None
    except Exception:
        return None

def get_file_version(path: str) -> Optional[str]:
    """Try to get a sane version string for an executable file."""
    if not os.path.exists(path):
        return None
    v = get_file_version_via_ctypes(path)
    if v:
        return v
    return None


def read_reg_str(hive, subkey: str, value: str) -> Optional[str]:
    try:
        with winreg.OpenKey(hive, subkey) as k:
            return winreg.QueryValueEx(k, value)[0]
    except OSError:
        return None

def enum_uninstall_keys() -> List[Tuple[object, str]]:
    """Return list of (hive, subkey) to scan for installed software."""
    keys = []
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, root in roots:
        try:
            with winreg.OpenKey(hive, root) as k:
                n = winreg.QueryInfoKey(k)[0]
                for i in range(n):
                    try:
                        sub = winreg.EnumKey(k, i)
                        keys.append((hive, root + "\\" + sub))
                    except OSError:
                        continue
        except OSError:
            continue
    return keys

def read_display_info(hive, subkey: str) -> Optional[Tuple[str, Optional[str]]]:
    """Return (DisplayName, DisplayVersion) for an uninstall entry."""
    try:
        with winreg.OpenKey(hive, subkey) as k:
            name = None
            ver = None
            try:
                name = winreg.QueryValueEx(k, "DisplayName")[0]
            except OSError:
                return None
            try:
                ver = winreg.QueryValueEx(k, "DisplayVersion")[0]
            except OSError:
                ver = None
            if not name:
                return None
            return (str(name), str(ver) if ver else None)
    except OSError:
        return None

def discover_browsers() -> List[Tuple[str, str, Optional[str]]]:
    """
    Return list of (Name, Path, Version) for known browsers if present.
    We check common App Paths registry entries and well-known install locations.
    """
    candidates: List[Tuple[str, List[str]]] = [
        ("Google Chrome", [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
        ]),
        ("Microsoft Edge", [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
        ]),
        ("Mozilla Firefox", [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
        ]),
        ("Opera", [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\opera.exe",
        ]),
        ("Opera GX", [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\opera_gx.exe",
        ]),
        ("Brave", [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe",
        ]),
        ("Vivaldi", [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\vivaldi.exe",
        ]),
        ("Yandex Browser", [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\browser.exe",
        ]),
        ("Internet Explorer", []),  # handled specially
    ]

    paths_extra = [
        ( "Google Chrome",   r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        ( "Google Chrome",   r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        ( "Microsoft Edge",  r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        ( "Microsoft Edge",  r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        ( "Mozilla Firefox", r"C:\Program Files\Mozilla Firefox\firefox.exe"),
        ( "Mozilla Firefox", r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"),
        ( "Opera",           r"C:\Program Files\Opera\launcher.exe"),
        ( "Opera",           r"C:\Program Files\Opera\opera.exe"),
        ( "Brave",           r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"),
        ( "Vivaldi",         r"C:\Program Files\Vivaldi\Application\vivaldi.exe"),
        ( "Yandex Browser",  r"C:\Users\%USERNAME%\AppData\Local\Yandex\YandexBrowser\Application\browser.exe"),
    ]

    discovered: Dict[str, Tuple[str, Optional[str]]] = {}

    for name, subkeys in candidates:
        if name == "Internet Explorer":
            continue
        exe_path = None
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for sub in subkeys:
                p = read_reg_str(hive, sub, "")
                if p and os.path.exists(p):
                    exe_path = p
                    break
            if exe_path:
                break
        if exe_path:
            discovered[name] = (exe_path, get_file_version(exe_path))

    for name, p in paths_extra:
        p_exp = os.path.expandvars(p)
        if os.path.exists(p_exp) and name not in discovered:
            discovered[name] = (p_exp, get_file_version(p_exp))

    ie_paths = [
        r"C:\Program Files\Internet Explorer\iexplore.exe",
        r"C:\Program Files (x86)\Internet Explorer\iexplore.exe",
    ]
    for p in ie_paths:
        if os.path.exists(p):
            discovered["Internet Explorer"] = (p, get_file_version(p))
            break

    items = [(n, discovered[n][0], discovered[n][1]) for n in sorted(discovered.keys())]
    return items


def write_browsers_file(path: Path, rows: List[Tuple[str, str, Optional[str]]]) -> None:
    """
    Write InstalledBrowsers.txt in the format:
    1) Name: <Name>, Path: <Path>, Version: <Version>
    """
    with open(path, "w", encoding="utf-8") as f:
        for idx, (name, exe, ver) in enumerate(rows, start=1):
            f.write(f"{idx}) Name: {name}, Path: {exe}, Version: {ver or 'Unknown'}\n")

def write_software_file(path: Path, entries: List[Tuple[str, Optional[str]]]) -> None:
    """
    Write InstalledSoftware.txt in the format:
    1) <DisplayName> [<DisplayVersion>]
    """
    with open(path, "w", encoding="utf-8") as f:
        for idx, (name, ver) in enumerate(entries, start=1):
            ver_str = ver if (ver and ver.strip()) else "Unknown"
            f.write(f"{idx}) {name} [{ver_str}]\n")


def collect_installed_software(output_dir: str):
    """Collect installed software and browsers information"""
    browsers = discover_browsers()

    raw = []
    for hive, subkey in enum_uninstall_keys():
        info = read_display_info(hive, subkey)
        if info:
            raw.append(info)

    seen = set()
    soft: List[Tuple[str, Optional[str]]] = []
    for name, ver in raw:
        key = (name.strip(), (ver or "").strip())
        if key in seen:
            continue
        seen.add(key)
        soft.append((name.strip(), (ver or None)))
    soft.sort(key=lambda x: x[0].lower())

    output_path = Path(output_dir)
    out_browsers = output_path / "InstalledBrowsers.txt"
    out_software = output_path / "InstalledSoftware.txt"
    
    write_browsers_file(out_browsers, browsers)
    write_software_file(out_software, soft)

    print(f"[Done] Wrote {out_browsers.resolve()}")
    print(f"[Done] Wrote {out_software.resolve()}")
    return True
