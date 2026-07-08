"""
Discord bot — /symbols slash command

Upload a libil2cpp.so → get back a Frida-Map.js. That's it.

Setup:
    pip install discord.py pyelftools aiohttp
    Put your bot token in config.py (TOKEN = "...")
"""

import discord
from discord import app_commands
from discord.ext import commands
from discord.ext import tasks
import aiohttp
import asyncio
import json
import os
import re
import time
import uuid
import urllib.parse
import zipfile
import tempfile
import shutil
import subprocess
from datetime import datetime
from elftools.elf.elffile import ELFFile

import os

def _clean_token(raw: str) -> str:
    """Defends against tokens copy-pasted straight out of a browser URL bar,
    which often drag along trailing query params like '&state=...' or a
    leading '?'. Only the token itself (up to the first stray '&') is kept.
    Also strips whitespace/newlines that sneak in from copy-paste."""
    if not raw:
        return raw
    cleaned = raw.strip().lstrip("?")
    cleaned = cleaned.split("&")[0]  # drop any trailing &key=value junk
    return cleaned

TOKEN = os.environ["TOKEN"]
META_TOKEN = _clean_token(os.environ["META_TOKEN"])  # user token for binary downloads
GQL_TOKEN = _clean_token(os.environ.get("GQL_TOKEN", "OC|660728964057742|"))  # public token for GraphQL
KEYSTORE_PASSWORD = os.environ["KEYSTORE_PASSWORD"]

# --- Auto-refresh for the short-lived META_TOKEN/GQL_TOKEN ---------------
OC_RT = _clean_token(os.environ.get("OC_RT", ""))  # long-lived Oculus refresh cookie
# Optional companion session cookies. Some Meta auth flows validate oc_rt
# against a bound session fingerprint (commonly the 'sb' cookie) rather than
# accepting oc_rt in total isolation — if refresh keeps failing with a fresh
# oc_rt, try setting these too from the same browser capture.
OC_SB = _clean_token(os.environ.get("OC_SB", ""))
OC_AC_AT = _clean_token(os.environ.get("OC_AC_AT", ""))
OC_WWW_AT = _clean_token(os.environ.get("OC_WWW_AT", ""))
OC_OA = _clean_token(os.environ.get("OC_OA", ""))
OC_RS_AT = _clean_token(os.environ.get("OC_RS_AT", ""))
OC_LOCALE = _clean_token(os.environ.get("OC_LOCALE", "en_US"))
OC_WD = _clean_token(os.environ.get("OC_WD", ""))
RAILWAY_API_TOKEN = os.environ.get("RAILWAY_API_TOKEN", "")
RAILWAY_PROJECT_ID = "c4205da6-ceac-471b-b5af-c076fec2cf47"
RAILWAY_ENVIRONMENT_ID = "8f34eb7c-da05-4fb8-be35-0cc180cb084b"
RAILWAY_SERVICE_ID = "0cee8a02-a2c6-42b8-8054-be244ec29a9c"
RAILWAY_API_URL = "https://backboard.railway.com/graphql/v2"
AC_CLIENT_TOKEN = "OC|660728964057742|"  # public web-app client id used by the refresh flow
TOKEN_REFRESH_MINUTES = 10  # observed token lifetime is ~15-20 min — refresh well before that

print(f"[startup] META_TOKEN loaded, length={len(META_TOKEN)}, starts='{META_TOKEN[:8]}...'", flush=True)
print(f"[startup] GQL_TOKEN loaded, length={len(GQL_TOKEN)}, starts='{GQL_TOKEN[:8]}...'", flush=True)
print(f"[startup] OC_RT loaded, length={len(OC_RT)}, starts='{OC_RT[:8] if OC_RT else '(empty)'}...'", flush=True)

# Full canonical IL2CPP API name list (Map4 order first, then Map3-only extras)
CANONICAL = [
    'il2cpp_init',
    'il2cpp_init_utf16',
    'il2cpp_shutdown',
    'il2cpp_set_config_dir',
    'il2cpp_set_data_dir',
    'il2cpp_set_temp_dir',
    'il2cpp_set_commandline_arguments',
    'il2cpp_set_commandline_arguments_utf16',
    'il2cpp_set_config_utf16',
    'il2cpp_set_config',
    'il2cpp_set_memory_callbacks',
    'il2cpp_memory_pool_set_region_size',
    'il2cpp_memory_pool_get_region_size',
    'il2cpp_get_corlib',
    'il2cpp_add_internal_call',
    'il2cpp_resolve_icall',
    'il2cpp_alloc',
    'il2cpp_free',
    'il2cpp_array_class_get',
    'il2cpp_array_length',
    'il2cpp_array_get_byte_length',
    'il2cpp_array_new',
    'il2cpp_array_new_specific',
    'il2cpp_array_new_full',
    'il2cpp_bounded_array_class_get',
    'il2cpp_array_element_size',
    'il2cpp_assembly_get_image',
    'il2cpp_class_enum_basetype',
    'il2cpp_class_from_system_type',
    'il2cpp_class_is_inited',
    'il2cpp_class_is_generic',
    'il2cpp_class_is_inflated',
    'il2cpp_class_is_assignable_from',
    'il2cpp_class_is_subclass_of',
    'il2cpp_class_has_parent',
    'il2cpp_class_from_il2cpp_type',
    'il2cpp_class_from_name',
    'il2cpp_class_get_element_class',
    'il2cpp_class_get_events',
    'il2cpp_class_get_fields',
    'il2cpp_class_get_nested_types',
    'il2cpp_class_get_interfaces',
    'il2cpp_class_get_properties',
    'il2cpp_class_get_property_from_name',
    'il2cpp_class_get_field_from_name',
    'il2cpp_class_get_methods',
    'il2cpp_class_get_method_from_name',
    'il2cpp_class_get_name',
    'il2cpp_class_get_namespace',
    'il2cpp_class_get_parent',
    'il2cpp_class_get_declaring_type',
    'il2cpp_class_instance_size',
    'il2cpp_class_num_fields',
    'il2cpp_class_is_valuetype',
    'il2cpp_class_is_blittable',
    'il2cpp_class_value_size',
    'il2cpp_class_get_flags',
    'il2cpp_class_is_abstract',
    'il2cpp_class_is_interface',
    'il2cpp_class_array_element_size',
    'il2cpp_class_from_type',
    'il2cpp_class_get_type',
    'il2cpp_class_get_type_token',
    'il2cpp_class_has_attribute',
    'il2cpp_class_has_references',
    'il2cpp_class_is_enum',
    'il2cpp_class_get_image',
    'il2cpp_class_get_assemblyname',
    'il2cpp_class_get_rank',
    'il2cpp_class_get_data_size',
    'il2cpp_class_get_static_field_data',
    'il2cpp_stats_dump_to_file',
    'il2cpp_stats_get_value',
    'il2cpp_domain_get',
    'il2cpp_domain_assembly_open',
    'il2cpp_domain_get_assemblies',
    'il2cpp_raise_exception',
    'il2cpp_exception_from_name_msg',
    'il2cpp_get_exception_argument_null',
    'il2cpp_format_exception',
    'il2cpp_format_stack_trace',
    'il2cpp_unhandled_exception',
    'il2cpp_native_stack_trace',
    'il2cpp_field_get_name',
    'il2cpp_field_get_flags',
    'il2cpp_field_get_from_reflection',
    'il2cpp_field_get_parent',
    'il2cpp_field_get_object',
    'il2cpp_field_get_offset',
    'il2cpp_field_get_type',
    'il2cpp_field_get_value',
    'il2cpp_field_get_value_object',
    'il2cpp_field_has_attribute',
    'il2cpp_field_set_value',
    'il2cpp_field_set_value_object',
    'il2cpp_field_static_get_value',
    'il2cpp_field_static_set_value',
    'il2cpp_field_is_literal',
    'il2cpp_gc_collect',
    'il2cpp_gc_collect_a_little',
    'il2cpp_gc_start_incremental_collection',
    'il2cpp_gc_enable',
    'il2cpp_gc_disable',
    'il2cpp_gc_is_disabled',
    'il2cpp_gc_set_mode',
    'il2cpp_gc_is_incremental',
    'il2cpp_gc_get_max_time_slice_ns',
    'il2cpp_gc_set_max_time_slice_ns',
    'il2cpp_gc_get_used_size',
    'il2cpp_gc_get_heap_size',
    'il2cpp_gc_foreach_heap',
    'il2cpp_stop_gc_world',
    'il2cpp_start_gc_world',
    'il2cpp_gc_alloc_fixed',
    'il2cpp_gc_free_fixed',
    'il2cpp_gchandle_new',
    'il2cpp_gchandle_new_weakref',
    'il2cpp_gchandle_get_target',
    'il2cpp_gchandle_foreach_get_target',
    'il2cpp_gc_wbarrier_set_field',
    'il2cpp_gc_has_strict_wbarriers',
    'il2cpp_gc_set_external_allocation_tracker',
    'il2cpp_gc_set_external_wbarrier_tracker',
    'il2cpp_gchandle_free',
    'il2cpp_object_header_size',
    'il2cpp_array_object_header_size',
    'il2cpp_offset_of_array_length_in_array_object_header',
    'il2cpp_offset_of_array_bounds_in_array_object_header',
    'il2cpp_allocation_granularity',
    'il2cpp_unity_liveness_allocate_struct',
    'il2cpp_unity_liveness_calculation_from_root',
    'il2cpp_unity_liveness_calculation_from_statics',
    'il2cpp_unity_liveness_finalize',
    'il2cpp_unity_liveness_free_struct',
    'il2cpp_method_get_return_type',
    'il2cpp_method_get_from_reflection',
    'il2cpp_method_get_object',
    'il2cpp_method_get_name',
    'il2cpp_method_is_generic',
    'il2cpp_method_is_inflated',
    'il2cpp_method_is_instance',
    'il2cpp_method_get_param_count',
    'il2cpp_method_get_param',
    'il2cpp_method_get_class',
    'il2cpp_method_has_attribute',
    'il2cpp_method_get_declaring_type',
    'il2cpp_method_get_flags',
    'il2cpp_method_get_token',
    'il2cpp_method_get_param_name',
    'il2cpp_profiler_install',
    'il2cpp_profiler_set_events',
    'il2cpp_profiler_install_enter_leave',
    'il2cpp_profiler_install_allocation',
    'il2cpp_profiler_install_gc',
    'il2cpp_profiler_install_fileio',
    'il2cpp_profiler_install_thread',
    'il2cpp_property_get_name',
    'il2cpp_property_get_get_method',
    'il2cpp_property_get_set_method',
    'il2cpp_property_get_parent',
    'il2cpp_property_get_flags',
    'il2cpp_object_get_class',
    'il2cpp_object_get_size',
    'il2cpp_object_get_virtual_method',
    'il2cpp_object_new',
    'il2cpp_object_unbox',
    'il2cpp_value_box',
    'il2cpp_monitor_enter',
    'il2cpp_monitor_try_enter',
    'il2cpp_monitor_exit',
    'il2cpp_monitor_pulse',
    'il2cpp_monitor_pulse_all',
    'il2cpp_monitor_wait',
    'il2cpp_monitor_try_wait',
    'il2cpp_runtime_invoke_convert_args',
    'il2cpp_runtime_invoke',
    'il2cpp_runtime_class_init',
    'il2cpp_runtime_object_init',
    'il2cpp_runtime_object_init_exception',
    'il2cpp_runtime_unhandled_exception_policy_set',
    'il2cpp_string_length',
    'il2cpp_string_chars',
    'il2cpp_string_new',
    'il2cpp_string_new_wrapper',
    'il2cpp_string_new_utf16',
    'il2cpp_string_new_len',
    'il2cpp_string_intern',
    'il2cpp_string_is_interned',
    'il2cpp_thread_current',
    'il2cpp_thread_attach',
    'il2cpp_thread_detach',
    'il2cpp_is_vm_thread',
    'il2cpp_current_thread_walk_frame_stack',
    'il2cpp_thread_walk_frame_stack',
    'il2cpp_current_thread_get_top_frame',
    'il2cpp_thread_get_top_frame',
    'il2cpp_current_thread_get_frame_at',
    'il2cpp_thread_get_frame_at',
    'il2cpp_current_thread_get_stack_depth',
    'il2cpp_thread_get_stack_depth',
    'il2cpp_set_default_thread_affinity',
    'il2cpp_override_stack_backtrace',
    'il2cpp_type_get_object',
    'il2cpp_type_get_type',
    'il2cpp_type_get_class_or_element_class',
    'il2cpp_type_get_name',
    'il2cpp_type_get_assembly_qualified_name',
    'il2cpp_type_get_reflection_name',
    'il2cpp_type_is_byref',
    'il2cpp_type_get_attrs',
    'il2cpp_type_equals',
    'il2cpp_type_is_static',
    'il2cpp_type_is_pointer_type',
    'il2cpp_image_get_assembly',
    'il2cpp_image_get_name',
    'il2cpp_image_get_filename',
    'il2cpp_image_get_entry_point',
    'il2cpp_image_get_class_count',
    'il2cpp_image_get_class',
    'il2cpp_capture_memory_snapshot',
    'il2cpp_free_captured_memory_snapshot',
    'il2cpp_set_find_plugin_callback',
    'il2cpp_register_log_callback',
    'il2cpp_debugger_set_agent_options',
    'il2cpp_is_debugger_attached',
    'il2cpp_register_debugger_agent_transport',
    'il2cpp_debug_foreach_method',
    'il2cpp_debug_get_method_info',
    'il2cpp_unity_install_unitytls_interface',
    'il2cpp_custom_attrs_from_class',
    'il2cpp_custom_attrs_from_method',
    'il2cpp_custom_attrs_from_field',
    'il2cpp_custom_attrs_has_attr',
    'il2cpp_custom_attrs_get_attr',
    'il2cpp_custom_attrs_construct',
    'il2cpp_custom_attrs_free',
    'il2cpp_type_get_name_chunked',
    'il2cpp_class_set_userdata',
    'il2cpp_class_get_userdata_offset',
    'il2cpp_class_for_each',
    'il2cpp_unity_set_android_network_up_state_func'
]

NOISE_EXACT = {
    "Flush", "CloseNLSocket", "CreateNLSocket", "CloseZStream", "CreateZStream",
    "ReadEvents", "WriteEvents", "WriteZStream", "ReadZStream",
    "JNI_OnLoad", "JNI_OnUnload", "mono_pal_init",
}

NOISE_EXACT = {
    "Flush", "CloseNLSocket", "CreateNLSocket", "CloseZStream", "CreateZStream",
    "ReadEvents", "WriteEvents", "WriteZStream", "ReadZStream",
    "JNI_OnLoad", "JNI_OnUnload", "mono_pal_init",
}

def is_noise(name: str) -> bool:
    if not name:
        return True
    if name.startswith("_Z") or name.startswith("_GLOBAL"):
        return True
    # Note: removed "__" filter because obfuscated IL2CPP hashes starting with __
    # (like __uCWQCjgHT) are legitimate exports and should NOT be filtered
    noise_prefixes = (
        "SystemNative_", "GlobalizationNative_", "CryptoNative_", "Dll",
        "UnityAdsEngine", "JNI_",
    )
    return name.startswith(noise_prefixes) or name in NOISE_EXACT


def extract_sorted_exports(so_path: str) -> list[str]:
    """Address-sorted filtered IL2CPP exports from .dynsym."""
    syms = []
    with open(so_path, "rb") as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is None:
            return syms
        for sym in dynsym.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC":
                continue
            if sym["st_shndx"] == "SHN_UNDEF":
                continue
            if is_noise(sym.name):
                continue
            syms.append((sym["st_value"], sym.name))
    syms.sort(key=lambda x: x[0])
    return [name for _, name in syms]


async def download_streamed(url: str, dest: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as f:
                async for chunk in resp.content.iter_chunked(1 << 20):
                    f.write(chunk)


ANNOUNCE_CHANNEL_ID   = 1513070567190822992
LOGGER_CHANNEL_ID     = 1516731535833829407
AC_APP_ID             = "7190422614401072"
META_CDN              = "https://securecdn.oculus.com/binaries/download/"
VERSION_FILE          = "version_state.json"
POLL_SECONDS          = 60
GQL_URL               = os.environ.get("GQL_URL", "https://graph.oculus.com/graphql")
VERSION_DOC_ID        = os.environ.get("VERSION_DOC_ID", "3828663700542720")

MANAGED_DIR           = "managed_files"          # registered .ts files live here
MANAGED_CONFIG_FILE   = "managed_files_config.json"  # {channel_id, files: [...]}

# Auto-APK: inject libbunimod.so + loader smali, repack, sign, host on gofile
APK_CHANNEL_ID        = 1513074622852239363   # finished modded APKs get posted here
LIB_DIR               = "managed_lib"
LIB_FILENAME          = "libbunimod.so"
LIB_PATH              = os.path.join(LIB_DIR, LIB_FILENAME)
TARGET_ABI            = "arm64-v8a"

APKTOOL_CMD           = "apktool"      # must resolve on PATH
ZIPALIGN_CMD          = "zipalign"     # from Android SDK build-tools, must be on PATH
APKSIGNER_CMD         = "apksigner"    # from Android SDK build-tools, must be on PATH
KEYTOOL_CMD           = "keytool"      # bundled with the JDK, must be on PATH

KEYSTORE_PATH         = "bunimod.keystore"
KEYSTORE_ALIAS        = "bunimod"
# KEYSTORE_PASSWORD is imported from config.py — add e.g. KEYSTORE_PASSWORD = "..." there


# ---------------------------------------------------------------------------
# Version state
# ---------------------------------------------------------------------------

def load_version() -> dict:
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE) as f:
            return json.load(f)
    return {}


def save_version(data: dict):
    with open(VERSION_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Managed .ts files (auto-patched exports block on every AC update)
# ---------------------------------------------------------------------------

# Matches:  Il2Cpp.$config.exports = {\n ... \n};
# Non-greedy + DOTALL so it stops at the FIRST closing "};" line, which is
# always the end of the exports object since none of the generated entries
# contain a "{" of their own.
EXPORTS_BLOCK_RE = re.compile(
    r'(Il2Cpp\.\$config\.exports\s*=\s*\{)\r?\n.*?\r?\n(\};)',
    re.DOTALL,
)


def load_managed_config() -> dict:
    if os.path.exists(MANAGED_CONFIG_FILE):
        with open(MANAGED_CONFIG_FILE) as f:
            return json.load(f)
    return {"channel_id": None, "files": []}


def save_managed_config(data: dict):
    with open(MANAGED_CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)


def patch_exports_block(content: str, pairs: list[tuple[str, str]]) -> str | None:
    """Replace just the Il2Cpp.$config.exports = {...}; block with freshly
    generated symbols, leaving every hook/menu/etc. below it untouched.
    Returns None if the file has no exports block."""
    newline = "\r\n" if "\r\n" in content else "\n"
    body_lines = [
        f'    {canon}: () => Il2Cpp.module.findExportByName("{obf}"),'
        for canon, obf in pairs
    ]
    new_body = newline.join(body_lines)

    match = EXPORTS_BLOCK_RE.search(content)
    if not match:
        return None

    replacement = match.group(1) + newline + new_body + newline + match.group(2)
    return content[:match.start()] + replacement + content[match.end():]


def update_managed_files(pairs: list[tuple[str, str]]) -> tuple[list, list[str]]:
    """Patch every registered .ts file on disk with the new symbol pairs.
    Returns (discord.File list ready to send, list of error strings)."""
    config = load_managed_config()
    updated_files = []
    errors = []

    for filename in config.get("files", []):
        path = os.path.join(MANAGED_DIR, filename)
        if not os.path.exists(path):
            errors.append(f"`{filename}` is registered but missing on disk — re-run `/setupfiles`.")
            continue

        with open(path, "r", encoding="utf-8", newline="") as f:
            content = f.read()

        patched = patch_exports_block(content, pairs)
        if patched is None:
            errors.append(f"`{filename}` has no `Il2Cpp.$config.exports` block — skipped.")
            continue

        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(patched)

        updated_files.append(discord.File(path, filename=filename))

    return updated_files, errors


# ---------------------------------------------------------------------------
# Meta GraphQL — app metadata, images, AND live version/binary info.
# This is Meta's own store data (graph.oculus.com/graphql), not OculusDB.
# ---------------------------------------------------------------------------

async def _post_app_meta(app_id: str, access_token: str) -> dict | None:
    payload = {
        "access_token": access_token,
        "variables": json.dumps({"applicationID": app_id}),
        "doc_id": str(VERSION_DOC_ID),
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://www.meta.com",
        "Referer": "https://www.meta.com/",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
        ),
        "sec-ch-ua": '"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "priority": "u=1, i",
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(
            GQL_URL, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            body = await resp.text()
            if resp.status != 200:
                print(f"[watcher] GraphQL fetch error ({access_token[:6]}...): {resp.status} — {body[:500]}", flush=True)
                return None
            return json.loads(body)


async def fetch_app_meta(app_id: str) -> dict | None:
    """Hits Meta's GraphQL endpoint for the app's current store metadata
    (images, live channel info, binary list, etc.). Tries the public
    GQL_TOKEN first; if Meta rejects it (e.g. OAuthException/invalid
    parameter — seen when the doc_id starts requiring an authenticated
    caller), falls back to the real user META_TOKEN."""
    try:
        result = await _post_app_meta(app_id, GQL_TOKEN)
        if result is not None:
            return result

        print("[watcher] GQL_TOKEN request failed — retrying with META_TOKEN", flush=True)
        return await _post_app_meta(app_id, META_TOKEN)
    except Exception as e:
        print(f"[watcher] GraphQL fetch error: {e}", flush=True)
        return None


def _parse_latest_version(meta: dict) -> dict | None:
    """Pulls {version_code, binary_id} for the current LIVE build straight
    out of a fetch_app_meta() response. Returns None if the shape doesn't
    match what we expect (e.g. Meta changed their schema)."""
    try:
        node = meta["data"]["node"]

        # Current shape (as of the 2026-07-02 doc_id): node.release_channels.nodes[]
        # Each entry has channel_name (e.g. "LIVE") and its own
        # latest_supported_binary with version_code already included.
        channels = node.get("release_channels", {}).get("nodes", [])
        live_channel = next((c for c in channels if c.get("channel_name") == "LIVE"), None)
        if live_channel is None and channels:
            live_channel = channels[0]  # fall back to first channel if none named LIVE

        if live_channel:
            live_binary = live_channel.get("latest_supported_binary")
            if live_binary and live_binary.get("id") and live_binary.get("version_code") is not None:
                return {
                    "version_code": str(live_binary["version_code"]),
                    "binary_id": str(live_binary["id"]),
                }

        # Legacy shape fallback (older doc_id): node.liveChannel.nodes[]
        live_nodes = node.get("liveChannel", {}).get("nodes", [])
        if not live_nodes:
            print("[watcher] Meta response has no release_channels/liveChannel entry", flush=True)
            return None

        live_binary = live_nodes[0].get("latest_supported_binary")
        if not live_binary or not live_binary.get("id"):
            print("[watcher] Meta liveChannel entry has no latest_supported_binary", flush=True)
            return None

        binary_id = live_binary["id"]

        # primary_binaries carries the integer version_code alongside the id
        version_code = None
        for b in node.get("primary_binaries", {}).get("nodes", []):
            if b.get("id") == binary_id:
                version_code = b.get("version_code")
                break

        if version_code is None:
            # Fall back to the dotted version string, e.g. "1.78.1.3091" -> 3091
            version_str = live_binary.get("version", "")
            tail = version_str.rsplit(".", 1)[-1]
            if tail.isdigit():
                version_code = int(tail)

        if version_code is None:
            print(f"[watcher] Could not extract version_code for binary {binary_id}", flush=True)
            return None

        return {"version_code": str(version_code), "binary_id": str(binary_id)}
    except (KeyError, TypeError) as e:
        print(f"[watcher] Unexpected Meta response shape: {e}", flush=True)
        return None


# Delays (seconds) between retry attempts for Meta's GraphQL endpoint.
META_RETRY_DELAYS = [10, 30]


async def fetch_latest_version() -> dict | None:
    """Returns {version_code, binary_id, meta} for the current LIVE Animal
    Company build, straight from Meta's own GraphQL — no OculusDB involved.
    Retries through brief network hiccups before giving up for this poll."""
    attempts = len(META_RETRY_DELAYS) + 1
    for attempt in range(1, attempts + 1):
        meta = await fetch_app_meta(AC_APP_ID)
        result = _parse_latest_version(meta) if meta else None

        if result is not None:
            result["meta"] = meta
            print(f"[watcher] version_code={result['version_code']} binary_id={result['binary_id']}", flush=True)
            return result

        if attempt < attempts:
            delay = META_RETRY_DELAYS[attempt - 1]
            print(f"[watcher] Meta fetch attempt {attempt}/{attempts} failed — retrying in {delay}s", flush=True)
            await asyncio.sleep(delay)

    print(f"[watcher] Meta unreachable after {attempts} attempts", flush=True)
    return None


def _extract_image(meta, priorities: list[str]) -> str | None:
    """Walks the GraphQL response and returns the highest-priority image URI found."""
    best: tuple[int, str] | None = None

    def walk(obj):
        nonlocal best
        if isinstance(obj, dict):
            uri = obj.get("uri")
            if isinstance(uri, str) and uri:
                t = obj.get("image_type") or obj.get("imageType") or ""
                score = priorities.index(t) if t in priorities else len(priorities)
                if best is None or score < best[0]:
                    best = (score, uri)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(meta)
    return best[1] if best else None


def get_banner_url(meta) -> str | None:
    return _extract_image(meta, [
        "APP_IMG_HERO", "APP_IMG_COVER_LANDSCAPE", "APP_IMG_COVER_PORTRAIT",
        "APP_IMG_COVER_SQUARE", "APP_IMG_ICON", "APP_IMG_LOGO_TRANSPARENT",
    ])


def get_icon_url(meta) -> str | None:
    return _extract_image(meta, [
        "APP_IMG_ICON", "APP_IMG_COVER_SQUARE", "APP_IMG_LOGO_TRANSPARENT",
    ])


async def download_apk(binary_id: str, dest: str):
    """Download APK from Meta CDN using the stored Meta token."""
    url = f"{META_CDN}?id={binary_id}&access_token={META_TOKEN}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=600)) as resp:
            if resp.status != 200:
                body_preview = (await resp.text())[:300]
                if resp.status in (401, 403):
                    raise RuntimeError(
                        f"Meta rejected META_TOKEN (HTTP {resp.status}) — token is expired or malformed. "
                        f"Refresh oc_ac_at / META_TOKEN in Railway. Body: {body_preview}"
                    )
                raise RuntimeError(f"Download failed (HTTP {resp.status}): {body_preview}")
            with open(dest, "wb") as f:
                async for chunk in resp.content.iter_chunked(1 << 20):
                    f.write(chunk)


def extract_so_from_apk(apk_path: str, dest_dir: str) -> str:
    """Unzip APK and return path to arm64-v8a libil2cpp.so."""
    with zipfile.ZipFile(apk_path, "r") as z:
        candidates = [n for n in z.namelist() if n.endswith("libil2cpp.so") and "arm64" in n]
        if not candidates:
            candidates = [n for n in z.namelist() if n.endswith("libil2cpp.so")]
        if not candidates:
            raise FileNotFoundError("libil2cpp.so not found in APK")
        z.extract(candidates[0], dest_dir)
        return os.path.join(dest_dir, candidates[0])


def build_all_files(exports: list[str], now: str, out_dir: str):
    pairs = list(zip(CANONICAL, exports))

    # 1. Frida-Map.js
    frida_path = os.path.join(out_dir, "Frida-Map.js")
    lines = [f"// Generated by amblock at {now}  [Frida-Map]", "", "Il2Cpp.$config.exports = {"]
    for canon, obf in pairs:
        lines.append(f'    {canon}: () => Il2Cpp.module.findExportByName("{obf}"),')
    lines.append("};")
    with open(frida_path, "w") as f:
        f.write("\n".join(lines))

    # 2. Il2CppMethodNames.hpp
    hpp_method_path = os.path.join(out_dir, "Il2CppMethodNames.hpp")
    lines = ["#pragma once", "", f"// Generated by amblock at {now}  [Il2CppMethodNames]", ""]
    for canon, obf in pairs:
        lines.append(f'#define BNM_IL2CPP_API_{canon} "{obf}"')
    with open(hpp_method_path, "w") as f:
        f.write("\n".join(lines))

    # 3. Il2Cpp-Headers.hpp
    hpp_header_path = os.path.join(out_dir, "Il2Cpp-Headers.hpp")
    lines = ["#pragma once", "", f"// Generated by amblock at {now}  [Il2Cpp-Headers]", ""]
    for canon, obf in pairs:
        lines.append(f'#define symbol_{canon} "{obf}"')
    with open(hpp_header_path, "w") as f:
        f.write("\n".join(lines))

    # 4. SymbolMap.json
    symbol_map_path = os.path.join(out_dir, "SymbolMap.json")
    symbol_map = {"__header": f"// Generated by amblock at {now}  [Symbol-Map]"}
    for canon, obf in pairs:
        symbol_map[canon] = obf
    with open(symbol_map_path, "w") as f:
        json.dump(symbol_map, f, indent=4)

    return [frida_path, hpp_method_path, hpp_header_path, symbol_map_path], len(pairs), pairs


# ---------------------------------------------------------------------------
# Auto-APK: patch UnityPlayerActivity.smali to loadLibrary("bunimod"),
# drop libbunimod.so into lib/arm64-v8a, repack, sign, host on gofile.io
# ---------------------------------------------------------------------------

# Matches the onCreate(Landroid/os/Bundle;)V signature line through its
# .locals declaration, regardless of access-modifier wording (protected /
# public / public final / etc.) — we anchor on the signature + .locals only.
ONCREATE_RE = re.compile(
    r'(onCreate\(Landroid/os/Bundle;\)V\s*\n\s*\.locals\s+\d+\s*\n)'
)

BUNIMOD_SMALI = (
    '\n'
    '    const-string v0, "bunimod"\n'
    '\n'
    '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
)


def _find_unity_player_activity(decoded_dir: str) -> str:
    for root, _, files in os.walk(decoded_dir):
        if "UnityPlayerActivity.smali" in files:
            return os.path.join(root, "UnityPlayerActivity.smali")
    raise FileNotFoundError("UnityPlayerActivity.smali not found in decoded APK")


def _patch_smali(decoded_dir: str) -> bool:
    """Inserts the bunimod loadLibrary call right after .locals in onCreate.
    Returns False if it's already patched (so re-runs are safe/idempotent)."""
    smali_path = _find_unity_player_activity(decoded_dir)
    with open(smali_path, "r", encoding="utf-8") as f:
        content = f.read()

    if 'const-string v0, "bunimod"' in content:
        return False

    match = ONCREATE_RE.search(content)
    if not match:
        raise RuntimeError(f"Could not find onCreate()/.locals header in {smali_path}")

    insert_at = match.end()
    new_content = content[:insert_at] + BUNIMOD_SMALI + content[insert_at:]
    with open(smali_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    return True


def _inject_native_lib(decoded_dir: str, so_src: str, abi: str = TARGET_ABI) -> None:
    lib_dir = os.path.join(decoded_dir, "lib", abi)
    os.makedirs(lib_dir, exist_ok=True)
    shutil.copy(so_src, os.path.join(lib_dir, LIB_FILENAME))


def _ensure_keystore() -> None:
    if os.path.exists(KEYSTORE_PATH):
        return
    subprocess.run(
        [
            KEYTOOL_CMD, "-genkeypair", "-v",
            "-keystore", KEYSTORE_PATH,
            "-alias", KEYSTORE_ALIAS,
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-storepass", KEYSTORE_PASSWORD, "-keypass", KEYSTORE_PASSWORD,
            "-dname", "CN=bunimod,O=bunimod,C=US",
        ],
        check=True, capture_output=True, text=True,
    )


def build_modded_apk_sync(apk_path: str, work_dir: str) -> str:
    """Blocking pipeline: decode -> patch smali -> inject lib -> rebuild ->
    zipalign -> sign. Returns the path to the final signed APK.

    This must be called via asyncio.to_thread() — apktool decoding a
    multi-hundred-MB Quest APK can take minutes and would stall the bot's
    Discord heartbeat if run directly on the event loop.

    Uses `apktool d -r` (skip resource-table decoding) since we only ever
    touch smali + raw lib/ files — this is both much faster and avoids
    needing a matching Android framework .apk for resource decoding.
    """
    if not os.path.exists(LIB_PATH):
        raise FileNotFoundError(
            f"No `{LIB_FILENAME}` registered yet — upload one with /setlib first."
        )

    decoded_dir = os.path.join(work_dir, "decoded")
    apktool_env = {**os.environ, "JAVA_OPTS": "-Xmx512m"}
    subprocess.run(
        [APKTOOL_CMD, "d", "-r", "-f", "-o", decoded_dir, apk_path],
        check=True, capture_output=True, text=True, env=apktool_env,
    )

    _patch_smali(decoded_dir)
    _inject_native_lib(decoded_dir, LIB_PATH)

    unsigned_apk = os.path.join(work_dir, "unsigned.apk")
    subprocess.run(
        [APKTOOL_CMD, "b", decoded_dir, "-o", unsigned_apk],
        check=True, capture_output=True, text=True,
    )

    # zipalign MUST happen before signing — apksigner's v2/v3 scheme covers
    # the whole archive, so aligning afterward would invalidate the signature.
    aligned_apk = os.path.join(work_dir, "aligned.apk")
    subprocess.run(
        [ZIPALIGN_CMD, "-f", "-p", "4", unsigned_apk, aligned_apk],
        check=True, capture_output=True, text=True,
    )

    _ensure_keystore()
    final_apk = os.path.join(work_dir, "AnimalCompany-bunimod.apk")
    subprocess.run(
        [
            APKSIGNER_CMD, "sign",
            "--ks", KEYSTORE_PATH,
            "--ks-pass", f"pass:{KEYSTORE_PASSWORD}",
            "--ks-key-alias", KEYSTORE_ALIAS,
            "--out", final_apk,
            aligned_apk,
        ],
        check=True, capture_output=True, text=True,
    )

    return final_apk


async def upload_to_gofile(file_path: str) -> str:
    """Uploads a file to gofile.io and returns the share-page URL.

    Current (2026) gofile API: GET https://api.gofile.io/servers for a
    server list, then POST the file to https://{server}.gofile.io/contents/uploadfile.
    No account/token needed for a plain anonymous upload — gofile spins up
    a guest folder automatically.
    """
    async with aiohttp.ClientSession() as session:
        async with session.get("https://api.gofile.io/servers") as resp:
            resp.raise_for_status()
            servers = await resp.json()

        candidates = servers.get("data", {}).get("servers", [])
        if not candidates:
            raise RuntimeError(f"gofile returned no servers: {servers}")
        server = candidates[0]["name"]

        with open(file_path, "rb") as f:
            form = aiohttp.FormData()
            form.add_field("file", f, filename=os.path.basename(file_path))
            async with session.post(
                f"https://{server}.gofile.io/contents/uploadfile", data=form
            ) as resp:
                resp.raise_for_status()
                result = await resp.json()

        if result.get("status") != "ok":
            raise RuntimeError(f"gofile upload failed: {result}")
        return result["data"]["downloadPage"]


async def build_and_post_modded_apk(apk_path: str, version_code: str, channel):
    """Builds the bunimod-patched APK from an already-downloaded original
    APK, uploads it to gofile.io, and posts the link to APK_CHANNEL_ID."""
    apk_channel = bot.get_channel(APK_CHANNEL_ID) or await bot.fetch_channel(APK_CHANNEL_ID)

    if not os.path.exists(LIB_PATH):
        await apk_channel.send(
            f"⚠️ Version `{version_code}` — skipping auto-APK, no `{LIB_FILENAME}` "
            f"registered. Use `/setlib` to upload one."
        )
        return

    with tempfile.TemporaryDirectory() as work_dir:
        t0 = time.monotonic()
        try:
            modded_path = await asyncio.to_thread(build_modded_apk_sync, apk_path, work_dir)
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.stdout or str(e))[-1500:]
            await apk_channel.send(f"⚠️ Version `{version_code}` — APK build failed:\n```{err}```")
            return
        except Exception as e:
            await apk_channel.send(f"⚠️ Version `{version_code}` — APK build failed: `{e}`")
            return
        print(f"[autoapk] TIMING build modded apk: {time.monotonic() - t0:.1f}s", flush=True)

        t0 = time.monotonic()
        try:
            link = await upload_to_gofile(modded_path)
        except Exception as e:
            await apk_channel.send(
                f"⚠️ Version `{version_code}` — built fine but gofile upload failed: `{e}`"
            )
            return
        print(f"[autoapk] TIMING gofile upload: {time.monotonic() - t0:.1f}s", flush=True)

    await apk_channel.send(
        f"@everyone 📦 **Animal Company `{version_code}`** — bunimod-patched APK ready:\n{link}"
    )


async def run_pipeline(version_code: str, binary_id: str, channel):
    """Full pipeline: download APK → extract .so → generate files → post."""
    t_start = time.monotonic()
    print(f"[watcher] Running pipeline for version {version_code}, binary {binary_id}", flush=True)
    with tempfile.TemporaryDirectory() as tmp:
        apk_path = os.path.join(tmp, "AnimalCompany.apk")

        t0 = time.monotonic()
        try:
            await download_apk(binary_id, apk_path)
        except Exception as e:
            await channel.send(f"⚠️ New AC version `{version_code}` detected but APK download failed: `{e}`")
            return
        download_elapsed = time.monotonic() - t0
        apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
        speed_mbps = apk_size_mb / download_elapsed if download_elapsed > 0 else 0
        print(f"[watcher] TIMING download: {download_elapsed:.1f}s for {apk_size_mb:.1f}MB ({speed_mbps:.2f} MB/s)", flush=True)

        t0 = time.monotonic()
        try:
            so_path = extract_so_from_apk(apk_path, tmp)
        except Exception as e:
            await channel.send(f"⚠️ Version `{version_code}` — failed to extract libil2cpp.so: `{e}`")
            return
        print(f"[watcher] TIMING extract .so from APK: {time.monotonic() - t0:.1f}s", flush=True)

        t0 = time.monotonic()
        try:
            exports = extract_sorted_exports(so_path)
        except Exception as e:
            await channel.send(f"⚠️ Version `{version_code}` — failed to parse ELF: `{e}`")
            return
        print(f"[watcher] TIMING parse ELF exports: {time.monotonic() - t0:.1f}s", flush=True)

        now = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        out_dir = os.path.join(tmp, "out")
        os.makedirs(out_dir)

        t0 = time.monotonic()
        file_paths, count, pairs = build_all_files(exports, now, out_dir)

        await channel.send(
            content=f"@everyone 🆕 **Animal Company updated** — version `{version_code}`\n**{count}** symbols mapped from **{len(exports)}** exports.",
            files=[discord.File(p, filename=os.path.basename(p)) for p in file_paths],
        )
        print(f"[watcher] TIMING build + post symbol files: {time.monotonic() - t0:.1f}s", flush=True)

        t0 = time.monotonic()
        managed_files, managed_errors = update_managed_files(pairs)
        managed_config = load_managed_config()
        target_channel_id = managed_config.get("channel_id")

        if target_channel_id and managed_files:
            target_channel = bot.get_channel(target_channel_id) or await bot.fetch_channel(target_channel_id)
            await target_channel.send(
                content=f"🔄 Auto-updated **{len(managed_files)}** registered file(s) for version `{version_code}`.",
                files=managed_files,
            )
        if managed_errors:
            await channel.send("\n".join(f"⚠️ {e}" for e in managed_errors))
        print(f"[watcher] TIMING patch + post managed files: {time.monotonic() - t0:.1f}s", flush=True)

        t0 = time.monotonic()
        try:
            await build_and_post_modded_apk(apk_path, version_code, channel)
        except Exception as e:
            await channel.send(f"⚠️ Version `{version_code}` — auto-APK step crashed: `{e}`")
        print(f"[watcher] TIMING auto-apk build+upload: {time.monotonic() - t0:.1f}s", flush=True)

        total_elapsed = time.monotonic() - t_start
        print(f"[watcher] TIMING total pipeline: {total_elapsed:.1f}s ({total_elapsed / 60:.1f} min) — version {version_code}", flush=True)


# ---------------------------------------------------------------------------
# Bot + watcher loop
# ---------------------------------------------------------------------------

async def download_streamed(url: str, dest: str):
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as f:
                async for chunk in resp.content.iter_chunked(1 << 20):
                    f.write(chunk)


intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

_meta_outage = {"down": False}
_oc_rt_dead = {"flagged": False}


async def push_railway_variables(vars_to_set: dict):
    """Persists updated env vars to Railway via the public GraphQL API so
    they survive a restart. skipDeploys=True so this doesn't bounce the
    whole bot every refresh cycle — the running process already has the
    fresh token in memory via the global reassignment in refresh_meta_token()."""
    if not RAILWAY_API_TOKEN:
        print("[refresh] RAILWAY_API_TOKEN not set — skipping persist to Railway", flush=True)
        return

    mutation = "mutation variableUpsert($input: VariableUpsertInput!) { variableUpsert(input: $input) }"
    headers = {"Authorization": f"Bearer {RAILWAY_API_TOKEN}", "Content-Type": "application/json"}

    async with aiohttp.ClientSession() as session:
        for name, value in vars_to_set.items():
            payload = {
                "query": mutation,
                "variables": {
                    "input": {
                        "projectId": RAILWAY_PROJECT_ID,
                        "environmentId": RAILWAY_ENVIRONMENT_ID,
                        "serviceId": RAILWAY_SERVICE_ID,
                        "name": name,
                        "value": value,
                        "skipDeploys": True,
                    }
                },
            }
            try:
                async with session.post(
                    RAILWAY_API_URL, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    body = await resp.text()
                    if resp.status != 200 or '"errors"' in body:
                        print(f"[refresh] Railway variableUpsert failed for {name}: {resp.status} — {body[:300]}", flush=True)
                    else:
                        print(f"[refresh] Persisted {name} to Railway", flush=True)
            except Exception as e:
                print(f"[refresh] Railway variableUpsert error for {name}: {e}", flush=True)


def _build_session_cookies() -> dict:
    """Assembles whichever session cookies are set via env vars. oc_rt is
    the only one that's meaningfully long-lived; the rest are captured
    alongside it in case Meta validates the session as a bundle rather
    than accepting oc_rt in isolation."""
    cookies = {"oc_rt": OC_RT}
    if OC_SB:
        cookies["sb"] = OC_SB
    if OC_AC_AT:
        cookies["oc_ac_at"] = OC_AC_AT
    if OC_WWW_AT:
        cookies["oc_www_at"] = OC_WWW_AT
    if OC_OA:
        cookies["oa"] = OC_OA
    if OC_RS_AT:
        cookies["oc_rs_at"] = OC_RS_AT
    if OC_LOCALE:
        cookies["locale"] = OC_LOCALE
    if OC_WD:
        cookies["wd"] = OC_WD
    return cookies


async def refresh_meta_token() -> bool:
    """Uses the long-lived oc_rt cookie to silently mint a fresh short-lived
    access_token from Meta (the same implicit-auth redirect the website
    itself uses on reload), then updates both the in-memory globals (takes
    effect immediately) and Railway's stored vars (survives a restart)."""
    global META_TOKEN

    if not OC_RT:
        print("[refresh] OC_RT not set — skipping token refresh", flush=True)
        return False

    url = "https://graph.oculus.com/authenticate_web_application/"
    params = {
        "access_token": AC_CLIENT_TOKEN,
        "method": "post",
        "redirect_uri": "https://secure.oculus.com/auth/",
        "state": uuid.uuid4().hex,
    }
    cookies = _build_session_cookies()

    try:
        async with aiohttp.ClientSession(cookies=cookies) as session:
            async with session.get(
                url, params=params, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                location = resp.headers.get("Location", "")
                if resp.status not in (301, 302, 303, 307, 308) or "access_token=" not in location:
                    body = await resp.text()
                    print(f"[refresh] Refresh failed — status={resp.status} location={location!r} body={body[:300]}", flush=True)
                    # A 400/OAuthException here specifically means the oc_rt
                    # session cookie itself is dead — no amount of retrying
                    # will fix this, it needs a human to grab a fresh oc_rt
                    # from a logged-in browser session. Alert once so this
                    # doesn't just sit silently in Railway logs.
                    await _alert_oc_rt_dead(body[:300])
                    return False

        # Location looks like: https://secure.oculus.com/auth/#access_token=NEW_TOKEN&...
        fragment = location.split("#", 1)[-1]
        frag_params = dict(p.split("=", 1) for p in fragment.split("&") if "=" in p)
        new_token_raw = frag_params.get("access_token")
        if not new_token_raw:
            print(f"[refresh] No access_token in redirect fragment: {location}", flush=True)
            await _alert_oc_rt_dead("redirect had no access_token fragment")
            return False

        new_token = urllib.parse.unquote(new_token_raw)
        META_TOKEN = new_token
        print(f"[refresh] Refreshed OK — length={len(new_token)}, starts='{new_token[:8]}...'", flush=True)

        if _oc_rt_dead["flagged"]:
            _oc_rt_dead["flagged"] = False
            logger = bot.get_channel(LOGGER_CHANNEL_ID) or await bot.fetch_channel(LOGGER_CHANNEL_ID)
            embed = discord.Embed(color=0x2ecc71)
            embed.set_author(name="AMB Symbols", icon_url=bot.user.display_avatar.url)
            embed.add_field(name="🟢  Auth recovered", value="META_TOKEN refresh is working again.", inline=False)
            await logger.send(embed=embed)

        await push_railway_variables({"META_TOKEN": new_token})
        return True
    except Exception as e:
        print(f"[refresh] Error refreshing token: {e}", flush=True)
        return False


async def _alert_oc_rt_dead(detail: str):
    """Fires once (not every 10-min cycle) when OC_RT itself is rejected by
    Meta — this means a human needs to grab a fresh oc_rt cookie from a
    logged-in browser session and update the Railway env var. Retrying
    won't fix it."""
    if _oc_rt_dead["flagged"]:
        return
    _oc_rt_dead["flagged"] = True
    try:
        logger = bot.get_channel(LOGGER_CHANNEL_ID) or await bot.fetch_channel(LOGGER_CHANNEL_ID)
        embed = discord.Embed(color=0xff0000)
        embed.set_author(name="AMB Symbols", icon_url=bot.user.display_avatar.url)
        embed.add_field(
            name="🔴  OC_RT is dead",
            value=(
                "Meta rejected the oc_rt refresh cookie — this can't self-heal.\n"
                "Log into meta.com/oculus.com in a browser, grab a fresh `oc_rt` "
                "cookie from DevTools, and update `OC_RT` in Railway, then run "
                "`/refreshtoken`.\n"
                f"```{detail}```"
            ),
            inline=False,
        )
        await logger.send(embed=embed)
    except Exception as e:
        print(f"[refresh] Failed to post oc_rt-dead alert: {e}", flush=True)


@tasks.loop(minutes=TOKEN_REFRESH_MINUTES)
async def token_refresher():
    await refresh_meta_token()


@token_refresher.before_loop
async def before_token_refresher():
    await bot.wait_until_ready()


@token_refresher.error
async def token_refresher_error(error: Exception):
    print(f"[refresh] Unhandled error, restarting loop: {error!r}", flush=True)
    if not token_refresher.is_running():
        token_refresher.restart()


@tasks.loop(seconds=POLL_SECONDS)
async def version_watcher():
    latest = await fetch_latest_version()
    logger = bot.get_channel(LOGGER_CHANNEL_ID) or await bot.fetch_channel(LOGGER_CHANNEL_ID)

    if not latest:
        # Only post once when Meta FIRST goes unreachable — not on every
        # single poll while it stays down. Otherwise an outage/network blip
        # floods this channel with a duplicate red embed every POLL_SECONDS.
        if not _meta_outage["down"]:
            _meta_outage["down"] = True
            embed = discord.Embed(color=0xff0000)
            embed.set_author(name="AMB Symbols", icon_url=bot.user.display_avatar.url)
            embed.add_field(
                name="🔴  Status",
                value="Could not reach Meta's GraphQL endpoint. Retrying quietly in the background.",
                inline=False,
            )
            embed.set_footer(text=f"Checked at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            await logger.send(embed=embed)
        else:
            print("[watcher] Meta still unreachable — suppressing duplicate alert", flush=True)
        return

    if _meta_outage["down"]:
        _meta_outage["down"] = False
        embed = discord.Embed(color=0x2ecc71)
        embed.set_author(name="AMB Symbols", icon_url=bot.user.display_avatar.url)
        embed.add_field(name="🟢  Status", value="Meta is reachable again.", inline=False)
        embed.set_footer(text=f"Checked at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        await logger.send(embed=embed)

    state = load_version()
    last_version = state.get("version_code", "")
    print(f"[watcher] last={last_version!r}  latest={latest['version_code']!r}", flush=True)

    if latest["version_code"] != last_version:
        save_version({"version_code": latest["version_code"], "binary_id": latest["binary_id"]})
        if last_version:
            # New update found
            embed = discord.Embed(title="@AC UPDATE", color=0x00ff00)
            embed.set_author(name="AMB Symbols", icon_url=bot.user.display_avatar.url)
            embed.add_field(
                name="🟢  Updated Version:",
                value=f"```{latest['version_code']}```",
                inline=False,
            )
            embed.add_field(
                name="🔴  Last Logged:",
                value=f"```{last_version}```",
                inline=False,
            )
            meta = latest.get("meta")
            banner = get_banner_url(meta) if meta else None
            embed.set_image(url=banner or "https://queststoredb.com/media/7190422614401072_cover_landscape.webp")
            embed.set_footer(text=f"Checked at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            await logger.send(embed=embed)

            channel = bot.get_channel(ANNOUNCE_CHANNEL_ID) or await bot.fetch_channel(ANNOUNCE_CHANNEL_ID)
            await run_pipeline(latest["version_code"], latest["binary_id"], channel)
        else:
            print(f"[watcher] Seeded initial version: {latest['version_code']}", flush=True)
            embed = discord.Embed(color=0x3498db)
            embed.set_author(name="AMB Symbols", icon_url=bot.user.display_avatar.url)
            embed.add_field(name="🔵  Watcher Started", value=f"```{latest['version_code']}```", inline=False)
            embed.set_footer(text=f"Checked at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            await logger.send(embed=embed)
    else:
        embed = discord.Embed(color=0xffffff)
        embed.set_author(name="AMB Symbols", icon_url=bot.user.display_avatar.url)
        embed.add_field(name="⚪  No New Update Found", value=f"```{latest['version_code']}```", inline=False)
        embed.set_footer(text=f"Checked at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        await logger.send(embed=embed)


@version_watcher.before_loop
async def before_watcher():
    await bot.wait_until_ready()


@version_watcher.error
async def watcher_error(error: Exception):
    # Without this, an unhandled exception in version_watcher() just kills
    # the loop forever with no further polling and no Discord message —
    # it would look "stuck" rather than crashed. Log it and restart instead.
    print(f"[watcher] Unhandled error, restarting loop: {error!r}", flush=True)
    if not version_watcher.is_running():
        version_watcher.restart()


@bot.event
async def on_ready():
    await bot.tree.sync()
    version_watcher.start()
    token_refresher.start()
    print(f"Logged in as {bot.user} — polling every {POLL_SECONDS}s, refreshing token every {TOKEN_REFRESH_MINUTES}m", flush=True)


@bot.tree.command(name="setupfiles", description="Register .ts files to auto-update with new symbols, and pick where updates get posted")
@app_commands.describe(
    channel="Channel where updated files get posted whenever AC updates",
    file1="A .ts file containing an Il2Cpp.$config.exports block",
    file2="Optional second .ts file",
    file3="Optional third .ts file",
    file4="Optional fourth .ts file",
)
async def setupfiles(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    file1: discord.Attachment,
    file2: discord.Attachment = None,
    file3: discord.Attachment = None,
    file4: discord.Attachment = None,
):
    attachments = [a for a in (file1, file2, file3, file4) if a is not None]

    for a in attachments:
        if not a.filename.endswith(".ts"):
            await interaction.response.send_message(f"`{a.filename}` isn't a `.ts` file.", ephemeral=True)
            return

    await interaction.response.defer(ephemeral=True)
    os.makedirs(MANAGED_DIR, exist_ok=True)

    saved_names = []
    skipped = []

    for a in attachments:
        dest = os.path.join(MANAGED_DIR, a.filename)
        await download_streamed(a.url, dest)

        with open(dest, "r", encoding="utf-8", newline="") as f:
            content = f.read()

        if not EXPORTS_BLOCK_RE.search(content):
            os.remove(dest)
            skipped.append(a.filename)
            continue

        saved_names.append(a.filename)

    if not saved_names:
        await interaction.followup.send(
            "None of those files had an `Il2Cpp.$config.exports = { ... };` block, so nothing was registered.",
            ephemeral=True,
        )
        return

    # This setup replaces any previous one — re-run /setupfiles any time you
    # want to change which files are tracked or where updates get posted.
    config = {"channel_id": channel.id, "files": saved_names}
    save_managed_config(config)

    msg = (
        f"✅ Registered **{len(saved_names)}** file(s): "
        f"{', '.join(f'`{n}`' for n in saved_names)}\n"
        f"Updates will be posted to {channel.mention} every time AC updates."
    )
    if skipped:
        msg += f"\n⚠️ Skipped (no exports block found): {', '.join(f'`{n}`' for n in skipped)}"
    await interaction.followup.send(msg, ephemeral=True)


@bot.tree.command(name="listfiles", description="Show which .ts files are registered for auto symbol updates")
async def listfiles(interaction: discord.Interaction):
    config = load_managed_config()
    files = config.get("files", [])
    channel_id = config.get("channel_id")
    if not files:
        await interaction.response.send_message("No files are registered. Use `/setupfiles` to add some.", ephemeral=True)
        return
    channel_mention = f"<#{channel_id}>" if channel_id else "*not set*"
    await interaction.response.send_message(
        f"Registered files: {', '.join(f'`{n}`' for n in files)}\nPosting to: {channel_mention}",
        ephemeral=True,
    )


@bot.tree.command(name="clearfiles", description="Stop auto-updating any registered files")
async def clearfiles(interaction: discord.Interaction):
    config = load_managed_config()
    for filename in config.get("files", []):
        path = os.path.join(MANAGED_DIR, filename)
        if os.path.exists(path):
            os.remove(path)
    save_managed_config({"channel_id": None, "files": []})
    await interaction.response.send_message("🗑️ Cleared all registered files.", ephemeral=True)


@bot.tree.command(name="setlib", description="Register the current libbunimod.so build used for auto-APK patching")
@app_commands.describe(file="libbunimod.so to embed in every future auto-patched APK")
async def setlib(interaction: discord.Interaction, file: discord.Attachment):
    if not file.filename.endswith(".so"):
        await interaction.response.send_message("That doesn't look like a `.so` file.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    os.makedirs(LIB_DIR, exist_ok=True)
    await download_streamed(file.url, LIB_PATH)
    await interaction.followup.send(
        f"✅ Registered `{file.filename}` as the active `{LIB_FILENAME}` for auto-APK builds.",
        ephemeral=True,
    )


@bot.tree.command(name="buildapk", description="Manually rebuild + upload a bunimod-patched APK for the last known AC version")
async def buildapk(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    # Always pull a FRESH binary_id from Meta instead of trusting the
    # possibly-stale version_state.json — the watcher can flag a version as
    # live before Meta finishes attaching the actual binary artifact to it,
    # which causes 404s on the id that was saved at detection time.
    latest = await fetch_latest_version()
    if latest:
        binary_id = latest["binary_id"]
        version_code = latest["version_code"]
        save_version({"version_code": version_code, "binary_id": binary_id})
    else:
        # Meta unreachable right now — fall back to last known good state.
        state = load_version()
        binary_id = state.get("binary_id")
        version_code = state.get("version_code", "unknown")

    if not binary_id:
        await interaction.followup.send(
            "No known binary_id yet — wait for the watcher to find a version first.", ephemeral=True
        )
        return

    with tempfile.TemporaryDirectory() as tmp:
        apk_path = os.path.join(tmp, "AnimalCompany.apk")
        try:
            await download_apk(binary_id, apk_path)
        except Exception as e:
            await interaction.followup.send(
                f"APK download failed: `{e}`\n"
                f"(binary_id={binary_id}, version={version_code} — if this keeps 404ing "
                f"on a freshly-fetched id, the binary likely isn't propagated on Meta's "
                f"CDN yet — retry in a bit.)",
                ephemeral=True,
            )
            return
        channel = bot.get_channel(APK_CHANNEL_ID) or await bot.fetch_channel(APK_CHANNEL_ID)
        await build_and_post_modded_apk(apk_path, version_code, channel)

    await interaction.followup.send(f"Done — check <#{APK_CHANNEL_ID}>.", ephemeral=True)


@bot.tree.command(name="symbols", description="Generate Frida-Map.js from a libil2cpp.so")
@app_commands.describe(file="The libil2cpp.so to analyse")
async def symbols(interaction: discord.Interaction, file: discord.Attachment):
    if not file.filename.endswith(".so"):
        await interaction.response.send_message("That doesn't look like a `.so` file.", ephemeral=True)
        return

    await interaction.response.defer()

    so_path = f"/tmp/{file.filename}"
    await download_streamed(file.url, so_path)

    try:
        exports = extract_sorted_exports(so_path)
    except Exception as e:
        await interaction.followup.send(f"Failed to parse ELF: {e}")
        return
    finally:
        os.remove(so_path)

    if not exports:
        await interaction.followup.send("No IL2CPP exports found — is this the right `.so`?")
        return

    now = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    with tempfile.TemporaryDirectory() as tmp:
        file_paths, count, pairs = build_all_files(exports, now, tmp)
        channel = bot.get_channel(ANNOUNCE_CHANNEL_ID) or await bot.fetch_channel(ANNOUNCE_CHANNEL_ID)
        await channel.send(
            content=f"@everyone **{count}** symbols mapped from **{len(exports)}** exports.",
            files=[discord.File(p, filename=os.path.basename(p)) for p in file_paths],
        )

        managed_files, managed_errors = update_managed_files(pairs)
        managed_config = load_managed_config()
        target_channel_id = managed_config.get("channel_id")

        if target_channel_id and managed_files:
            target_channel = bot.get_channel(target_channel_id) or await bot.fetch_channel(target_channel_id)
            await target_channel.send(
                content=f"🔄 Auto-updated **{len(managed_files)}** registered file(s).",
                files=managed_files,
            )

    followup_msg = f"Done! Posted to <#{ANNOUNCE_CHANNEL_ID}>."
    if managed_files:
        followup_msg += f" Also updated {len(managed_files)} registered file(s) in <#{target_channel_id}>."
    for e in managed_errors:
        followup_msg += f"\n⚠️ {e}"

    await interaction.followup.send(content=followup_msg, ephemeral=True)


@bot.tree.command(name="refreshtoken", description="Manually trigger a META_TOKEN/GQL_TOKEN refresh using oc_rt")
async def refreshtoken(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    ok = await refresh_meta_token()
    if ok:
        await interaction.followup.send(
            f"✅ Token refreshed — length={len(META_TOKEN)}, starts=`{META_TOKEN[:8]}...`", ephemeral=True
        )
    else:
        await interaction.followup.send(
            "❌ Refresh failed — check deploy logs for `[refresh]` lines for details.", ephemeral=True
        )


@bot.tree.command(name="checkversion", description="Check current Animal Company version on Meta")
async def checkversion(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    latest = await fetch_latest_version()
    state = load_version()
    if not latest:
        await interaction.followup.send("⚠️ Could not reach Meta's GraphQL endpoint.", ephemeral=True)
        return
    last = state.get("version_code", "none")
    status = "✅ Up to date" if latest["version_code"] == last else "🆕 New version available!"
    await interaction.followup.send(
        f"Last known: `{last}`\nLatest on Meta: `{latest['version_code']}`\n{status}",
        ephemeral=True,
    )


@bot.tree.command(name="metaraw", description="Debug: dump Meta's direct GraphQL app response (no OculusDB involved)")
async def metaraw(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    meta = await fetch_app_meta(AC_APP_ID)
    if not meta:
        await interaction.followup.send("Could not reach Meta's GraphQL endpoint.", ephemeral=True)
        return

    path = "/tmp/meta_raw_dump.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    await interaction.followup.send(
        content=(
            "This is the raw response from Meta's own GraphQL endpoint "
            "(`graph.oculus.com/graphql`) — no OculusDB involved. Send this "
            "file back so we can check whether it already contains a "
            "version code / binary id we could use instead of OculusDB."
        ),
        file=discord.File(path, filename="meta_raw_dump.json"),
        ephemeral=True,
    )


@bot.tree.command(name="refreshdebug", description="Debug: run the raw META_TOKEN refresh request and show status/location/body")
async def refreshdebug(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    if not OC_RT:
        await interaction.followup.send("OC_RT is not set.", ephemeral=True)
        return

    url = "https://graph.oculus.com/authenticate_web_application/"
    params = {
        "access_token": AC_CLIENT_TOKEN,
        "method": "post",
        "redirect_uri": "https://secure.oculus.com/auth/",
        "state": uuid.uuid4().hex,
    }
    cookies = _build_session_cookies()
    cookie_names = ", ".join(cookies.keys())

    try:
        async with aiohttp.ClientSession(cookies=cookies) as session:
            async with session.get(
                url, params=params, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                location = resp.headers.get("Location", "")
                body = await resp.text()
    except Exception as e:
        await interaction.followup.send(f"Request errored: `{e}`", ephemeral=True)
        return

    msg = (
        f"**Cookies sent:** `{cookie_names}`\n"
        f"**AC_CLIENT_TOKEN:** `{AC_CLIENT_TOKEN}`\n"
        f"**Status:** `{resp.status}`\n"
        f"**Location:** `{location or '(none)'}`\n"
        f"**Body:** ```{body[:500]}```"
    )
    await interaction.followup.send(msg, ephemeral=True)


bot.run(TOKEN)
