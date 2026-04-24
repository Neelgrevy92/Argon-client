"""
src/invites.py - PGP Encrypted Invite System for Argon Messenger

Handles:
  - Creating signed+encrypted invite blobs (export)
  - Parsing and validating invite blobs (import)
  - Anti-replay via nonce tracking (in-RAM session cache)
  - Timestamp enforcement
  - Trust model (Trusted / Known / Unknown)
  - Secure memory hygiene via bytearray
  - Deletion after usage

Format: JSON blob signed+encrypted with PGP
"""

import os
import json
import gc
import time
import secrets
from datetime import datetime, timezone, timedelta
from pgpy import PGPKey, PGPMessage
from .tui import (
    console, render_info, render_success, render_error, render_warning,
    confirm_action, INQUIRER_STYLE, ACCENT, OK, WARN, ERR, CYAN
)
from .keychain import load_register, PUBLIC_DIR

# ─── Paths ────────────────────────────────────────────────────────────────────
DYNAMIC_DIR  = "./storage/DEST/dynamic"
CONTACTS_DIR = "./storage/DEST/contacts"

# ─── Supported format version ─────────────────────────────────────────────────
INVITE_VERSION = 1

# ─── Timing parameters ────────────────────────────────────────────────────────
MAX_PAST_SECONDS   = 600   # 10 minutes
MAX_FUTURE_SECONDS = 120   # 2 minutes (clock skew tolerance)

# ─── Trust levels ─────────────────────────────────────────────────────────────
TRUST_UNKNOWN  = "UNKNOWN"
TRUST_KNOWN    = "KNOWN"
TRUST_TRUSTED  = "TRUSTED"

# ─── In-RAM nonce cache (cleared on exit) ─────────────────────────────────────
_seen_nonces: set = set()

os.makedirs(DYNAMIC_DIR,  exist_ok=True)
os.makedirs(CONTACTS_DIR, exist_ok=True)


# ──────────────────────────────────────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _wipe_bytearray(ba: bytearray):
    """Overwrite mutable bytearray with zeros before deletion."""
    ba[:] = b'\x00' * len(ba)


def _delete_invite(filepath: str):
    """Delete an invite file. Logs the action but never the content."""
    try:
        os.remove(filepath)
        render_info(f"Invite file deleted: {os.path.basename(filepath)}")
    except Exception as e:
        render_warning(f"Could not delete invite file: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# JSON Validation
# ──────────────────────────────────────────────────────────────────────────────

_REQUIRED_FIELDS = {
    "version":            (int,  None),
    "type":               (str,  32),
    "nonce":              (str,  128),
    "sender_alias":       (str,  64),
    "sender_fingerprint": (str,  128),
    "timestamp":          (str,  32),
    "dest":               (str,  2048),
}

def _validate_payload(payload: dict) -> str | None:
    """
    Validate the decrypted JSON payload.
    Returns None on success, or an error string on failure.
    """
    for field, (ftype, maxlen) in _REQUIRED_FIELDS.items():
        if field not in payload:
            return f"Missing required field: '{field}'"
        val = payload[field]
        if not isinstance(val, ftype):
            return f"Field '{field}' has wrong type (expected {ftype.__name__})"
        if maxlen and isinstance(val, str) and len(val) > maxlen:
            return f"Field '{field}' exceeds max length ({maxlen})"

    if payload["version"] != INVITE_VERSION:
        return f"Unsupported invite version: {payload['version']}"

    if payload["type"] not in ("dynamic", "static"):
        return f"Unknown invite type: {payload['type']}"

    # Validate ISO timestamp format
    try:
        datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        return f"Invalid timestamp format: {payload['timestamp']}"

    # Validate DEST is non-empty and looks like base64-ish I2P address
    dest = payload["dest"]
    if len(dest) < 300:
        return f"DEST too short to be valid ({len(dest)} chars)"

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Anti-Replay: Nonce
# ──────────────────────────────────────────────────────────────────────────────

def _check_and_register_nonce(nonce: str) -> bool:
    """
    Returns True if nonce is fresh (never seen), registers it.
    Returns False if already seen (replay attack).
    """
    if nonce in _seen_nonces:
        return False
    _seen_nonces.add(nonce)
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Timestamp Enforcement
# ──────────────────────────────────────────────────────────────────────────────

def _check_timestamp(ts_str: str) -> tuple[bool, str]:
    """
    Returns (ok: bool, reason: str).
    ok=True means timestamp is within acceptable window.
    """
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return False, "Invalid timestamp"

    now = _now_utc()
    delta = (now - ts).total_seconds()

    if delta < -MAX_FUTURE_SECONDS:
        return False, f"Invite is in the future by {abs(delta):.0f}s (clock skew?)"
    if delta > MAX_PAST_SECONDS:
        return False, f"Invite expired {delta:.0f}s ago (max {MAX_PAST_SECONDS}s)"

    return True, "OK"


# ──────────────────────────────────────────────────────────────────────────────
# PGP Trust Model
# ──────────────────────────────────────────────────────────────────────────────

def _verify_signature(decrypted_msg, claimed_fingerprint: str) -> tuple[str, str]:
    """
    Verify the PGP signature against our keychain.

    Returns (trust_level, signer_label):
      - TRUSTED  : key marked as alias in keychain, signature valid
      - KNOWN    : key present in keychain, signature valid, no alias
      - UNKNOWN  : signature invalid or key not in keychain
    """
    if not decrypted_msg.is_signed:
        return TRUST_UNKNOWN, "No signature present"

    entries = load_register()
    pub_entries = [e for e in entries if e["Type"] == "public"]

    for e in pub_entries:
        pub_path = os.path.join(PUBLIC_DIR, e["Filename"])
        if not os.path.exists(pub_path):
            continue
        try:
            pub_key, _ = PGPKey.from_file(pub_path)
            try:
                pub_key.verify(decrypted_msg)
                # Signature verified — determine trust level
                alias = e.get("Alias", "").strip()
                if alias:
                    return TRUST_TRUSTED, alias
                else:
                    return TRUST_KNOWN, e["Filename"]
            except Exception:
                continue
        except Exception:
            continue

    return TRUST_UNKNOWN, claimed_fingerprint[:16] + "..." if len(claimed_fingerprint) > 16 else claimed_fingerprint


# ──────────────────────────────────────────────────────────────────────────────
# Core Parser
# ──────────────────────────────────────────────────────────────────────────────

def parse_invite(private_key, filepath: str) -> tuple[dict | None, str, str]:
    """
    Full pipeline: read → decrypt → validate → anti-replay → trust-check.

    Returns:
      (payload, trust_level, signer_label)
      or (None, TRUST_UNKNOWN, error_message) on any failure.
    """
    # Step 1: Read in memory
    try:
        with open(filepath, "r") as f:
            encrypted_data = f.read()
    except Exception as e:
        return None, TRUST_UNKNOWN, f"Cannot read file: {e}"

    # Step 2: Decrypt (purely in RAM)
    try:
        encrypted_msg = PGPMessage.from_blob(encrypted_data)
        decrypted = private_key.decrypt(encrypted_msg)
    except Exception as e:
        return None, TRUST_UNKNOWN, f"Decryption failed: {e}"

    # Step 3: Verify signature (trust model)
    trust_level, signer_label = _verify_signature(decrypted, "")

    if trust_level == TRUST_UNKNOWN:
        return None, TRUST_UNKNOWN, f"Signature unknown or invalid: {signer_label}"

    # Step 4: Parse and strictly validate JSON
    try:
        payload = json.loads(str(decrypted.message))
    except json.JSONDecodeError as e:
        return None, trust_level, f"Invalid JSON payload: {e}"

    validation_error = _validate_payload(payload)
    if validation_error:
        return None, trust_level, f"Payload validation failed: {validation_error}"

    # Step 5: Anti-replay — nonce check
    nonce = payload["nonce"]
    if not _check_and_register_nonce(nonce):
        return None, trust_level, "Replay attack detected: nonce already used"

    # Step 6: Timestamp enforcement
    ts_ok, ts_reason = _check_timestamp(payload["timestamp"])
    if not ts_ok:
        return None, trust_level, f"Timestamp rejected: {ts_reason}"

    return payload, trust_level, signer_label


# ──────────────────────────────────────────────────────────────────────────────
# UX: Invite Display & Confirmation
# ──────────────────────────────────────────────────────────────────────────────

def _display_invite(payload: dict, trust_level: str, signer_label: str):
    """Render the invite details panel."""
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    trust_color = {
        TRUST_TRUSTED: OK,
        TRUST_KNOWN:   WARN,
        TRUST_UNKNOWN: ERR,
    }.get(trust_level, ERR)

    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column(style=f"bold {CYAN}", width=20)
    table.add_column(style="white")

    table.add_row("From (signed)",   f"[bold {trust_color}]{signer_label}[/]")
    table.add_row("Claimed alias",   payload.get("sender_alias", "Unknown"))
    table.add_row("Trust level",     f"[bold {trust_color}]{trust_level}[/]")
    table.add_row("Created",         payload.get("timestamp", "Unknown"))
    table.add_row("Type",            payload.get("type", "Unknown").capitalize())

    console.print()
    console.print(Panel(
        table,
        title=f"[bold {WARN}]Dynamic Invite Detected[/]",
        border_style=WARN,
        box=box.ROUNDED,
        padding=(1, 2),
    ))
    console.print()


def _prompt_view_dest(dest: str):
    """Let the user view the raw DEST if they want."""
    from InquirerPy import inquirer
    if inquirer.confirm(
        message="View raw I2P Destination?",
        default=False,
        style=INQUIRER_STYLE,
        qmark=">",
    ).execute():
        console.print(f"\n[dim]{dest}[/dim]\n")


# ──────────────────────────────────────────────────────────────────────────────
# Public API: Check Dynamic Invites
# ──────────────────────────────────────────────────────────────────────────────

def check_dynamic_invites(private_key) -> bytearray | None:
    """
    Scan dynamic/ for invites. For each:
      - Decrypt + verify + validate
      - Display context to user
      - Let user decide (connect / skip / delete)

    Returns a bytearray of the DEST (caller must wipe after use), or None.
    """
    invite_files = [
        f for f in os.listdir(DYNAMIC_DIR)
        if f.endswith(".txt")
    ]

    if not invite_files:
        return None

    render_info(f"{len(invite_files)} dynamic invite(s) found in storage")

    for fname in invite_files:
        filepath = os.path.join(DYNAMIC_DIR, fname)

        payload, trust_level, signer_label = parse_invite(private_key, filepath)

        if payload is None:
            render_error(f"Invite rejected ({fname}): {signer_label}")
            if confirm_action("Delete this invalid/suspicious invite?", default=True):
                _delete_invite(filepath)
            continue

        _display_invite(payload, trust_level, signer_label)

        if trust_level == TRUST_UNKNOWN:
            render_error("Cannot connect: signature is untrusted.")
            if confirm_action("Delete this invite?", default=True):
                _delete_invite(filepath)
            continue

        # Ask user with full context
        from InquirerPy import inquirer
        from InquirerPy.separator import Separator

        action = inquirer.select(
            message="What do you want to do?",
            choices=[
                {"name": "  Connect to this room", "value": "connect"},
                {"name": "  View raw DEST first",  "value": "view"},
                {"name": "  Skip (keep file)",      "value": "skip"},
                {"name": "  Delete invite",         "value": "delete"},
            ],
            pointer=">",
            qmark=">",
            instruction="(arrows to navigate, Enter to select)",
            style=INQUIRER_STYLE,
        ).execute()

        if action == "view":
            _prompt_view_dest(payload["dest"])
            if not confirm_action("Connect now?", default=True):
                _delete_invite(filepath)
                continue

        if action == "connect" or action == "view":
            # Store DEST as mutable bytearray for memory hygiene
            dest_ba = bytearray(payload["dest"].encode("utf-8"))
            _delete_invite(filepath)
            return dest_ba

        elif action == "delete":
            _delete_invite(filepath)

        # skip: do nothing

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Public API: Address Book (Static)
# ──────────────────────────────────────────────────────────────────────────────

def load_address_book(private_key) -> bytearray | None:
    """
    Scan contacts/ for static entries, let user pick one with arrows.
    Returns bytearray of DEST (caller must wipe after use), or None.
    """
    contact_files = [
        f for f in os.listdir(CONTACTS_DIR)
        if f.endswith(".txt")
    ]

    if not contact_files:
        render_warning("Address book is empty.")
        return None

    # Decrypt metadata from each file to build the list
    choices = []
    parsed_cache = {}

    for fname in contact_files:
        filepath = os.path.join(CONTACTS_DIR, fname)
        payload, trust_level, signer_label = parse_invite(private_key, filepath)

        if payload is None:
            render_warning(f"Could not read contact: {fname}")
            continue

        trust_color = {TRUST_TRUSTED: "[+]", TRUST_KNOWN: "[~]"}.get(trust_level, "[?]")
        display = f"{trust_color} {payload.get('sender_alias', fname)}"
        choices.append({"name": display, "value": fname})
        parsed_cache[fname] = payload

    if not choices:
        render_error("No readable contacts in address book.")
        return None

    from InquirerPy import inquirer
    from InquirerPy.separator import Separator

    choices.append(Separator())
    choices.append({"name": "  <- Cancel", "value": None})

    selected = inquirer.select(
        message="Select contact",
        choices=choices,
        pointer=">",
        qmark=">>",
        instruction="(arrows to navigate, Enter to select)",
        style=INQUIRER_STYLE,
    ).execute()

    if selected is None:
        return None

    payload = parsed_cache.get(selected)
    if not payload:
        render_error("Could not retrieve contact data.")
        return None

    dest_ba = bytearray(payload["dest"].encode("utf-8"))
    return dest_ba


# ──────────────────────────────────────────────────────────────────────────────
# Public API: Export Invite
# ──────────────────────────────────────────────────────────────────────────────

def export_invite(
    sender_priv_key,
    sender_alias: str,
    sender_fingerprint: str,
    recipient_pub_key,
    dest: str,
    invite_type: str = "dynamic",
) -> str:
    """
    Create a PGP signed+encrypted invite blob.
    Returns the file path of the saved invite.
    """
    payload = {
        "version":            INVITE_VERSION,
        "type":               invite_type,
        "nonce":              secrets.token_hex(16),
        "sender_alias":       sender_alias[:64],
        "sender_fingerprint": sender_fingerprint[:128],
        "timestamp":          _now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dest":               dest,
    }

    json_str = json.dumps(payload)
    message  = PGPMessage.new(json_str)

    # Sign first, then encrypt
    message |= sender_priv_key.sign(message)
    encrypted = recipient_pub_key.encrypt(message)

    # Save to appropriate directory with opaque filename
    target_dir = DYNAMIC_DIR if invite_type == "dynamic" else CONTACTS_DIR
    fname = f"inv_{secrets.token_hex(4)}.txt"
    filepath = os.path.join(target_dir, fname)

    with open(filepath, "w") as f:
        f.write(str(encrypted))

    # Wipe json_str from memory (best effort — str is immutable, but clears reference)
    del json_str
    gc.collect()

    render_success(f"Invite exported: {filepath}")
    return filepath
