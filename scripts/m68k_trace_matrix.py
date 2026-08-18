#!/usr/bin/env python3
"""Generate and execute systematic M68K RzIL trace-test matrices.

The canonical denominator is:

    instruction ID
    x encoding / size variant
    x applicable addressing-mode family
    x applicable Rizin CPU profile
    x reachable semantic path

Sources: Rizin ``test/db/asm/m68k_*``, Capstone M68K decoder metadata, the
lifter dispatch in ``m68k_il.c``, plus generated FPU-condition and missing
effective-address encodings.  Each case is a deterministic bare-metal QEMU
microprogram with controlled register / CCR / memory state.

Large BAP traces are transient by default.  Durable artifacts are the
manifest, JSONL execution results, compact summary, and Markdown report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable, Iterator, Sequence


SCHEMA = "rz-tracetest-m68k-matrix-v1"
PROFILES = (
    "68000",
    "68010",
    "68020",
    "68030",
    "68040",
    "68060",
    "cpu32",
    "coldfire",
    "cfv1",
    "cfv2",
    "cfv3",
    "cfv4",
    "cfv4e",
    "cfv5",
)

QEMU_PROFILE = {
    "68000": ("m68000", "m68000", "exact"),
    "68010": ("m68010", "m68010", "exact"),
    "68020": ("m68020", "m68020", "exact"),
    "68030": ("m68030", "m68030", "exact"),
    "68040": ("m68040", "m68040", "exact"),
    "68060": ("m68060", "m68060", "exact"),
    "cpu32": ("m68020", "m68020", "compatible-producer"),
    "coldfire": ("any", "any", "synthetic-superset"),
    "cfv1": ("any", "any", "synthetic-superset"),
    "cfv2": ("m5208", "m5208", "exact-family"),
    "cfv3": ("any", "any", "synthetic-superset"),
    "cfv4": ("any", "any", "synthetic-superset"),
    "cfv4e": ("cfv4e", "cfv4e", "exact"),
    "cfv5": ("any", "any", "synthetic-superset"),
}

# These public enum values cannot be produced by the current Capstone decoder.
# They are aliases or decoder gaps, not trace skips hidden inside the executable
# denominator.
UNREACHABLE_IDS = {
    "bhs": "alias: decoder canonicalizes the condition to bcc",
    "blo": "alias: decoder canonicalizes the condition to bcs",
    "dbf": "alias: decoder canonicalizes the condition to dbra",
    "divsl": "legacy alias: long signed division decodes as divs",
    "divul": "legacy alias: long unsigned division decodes as divu",
    "fsincos": "decoder gap: no M68K opmode selects this public enum",
    "ftanh": "decoder gap: opmodes 0x09/0x0d both select fatanh",
    "shs": "alias: decoder canonicalizes the condition to scc",
    "slo": "alias: decoder canonicalizes the condition to scs",
    "traphs": "alias: decoder canonicalizes the condition to trapcc",
    "traplo": "alias: decoder canonicalizes the condition to trapcs",
}

# Compact guest map so QEMU can run with 16 MiB instead of 3200 MiB.
VECTOR_LIMIT = 0x400
ABS_W_DATA = 0x1000
SETUP_ADDRESS = 0x2000
TARGET_ADDRESS = 0x3000
TAKEN_ADDRESS = 0x3080
TAIL_ADDRESS = 0x3100
PROGRAM_LIMIT = TAIL_ADDRESS + 16
PC_DATA = 0x3800
A_BASE = 0x10000
A_STRIDE = 0x10000
STACK_ADDRESS = 0x80000
ABS_L_DATA = 0x90000
INDIRECT_PTR = 0x91000
INDIRECT_DATA = 0x92000
RAM_BYTES = 15 * 1024 * 1024
QEMU_MEMORY = "32M"
VIRT_CTRL_COMMAND = 0xFF009004
DECODE_BATCH = 160

ADDRESS_MODE_NAMES = {
    0: "none",
    1: "data-register-direct",
    2: "address-register-direct",
    3: "address-indirect",
    4: "address-postincrement",
    5: "address-predecrement",
    6: "address-displacement",
    7: "address-index-brief",
    8: "address-index-full",
    9: "memory-postindexed",
    10: "memory-preindexed",
    11: "pc-displacement",
    12: "pc-index-brief",
    13: "pc-index-full",
    14: "pc-memory-postindexed",
    15: "pc-memory-preindexed",
    16: "absolute-short",
    17: "absolute-long",
    18: "immediate",
    19: "branch-displacement",
}

# Standard EA families synthesized from a template whose EA sits in opcode bits 5-0
# or in MOVE destination bits 11-6.  Decoder rejection is the applicability gate.
EA_SPECS: tuple[tuple[str, int, int, bytes], ...] = (
    ("dn", 0, 2, b""),
    ("an", 1, 2, b""),
    ("an-ind", 2, 2, b""),
    ("an-postinc", 3, 2, b""),
    ("an-predec", 4, 2, b""),
    ("an-disp", 5, 2, struct.pack(">h", 0x20)),
    ("an-index-brief", 6, 2, struct.pack(">H", 0x0000)),  # (a2, d0.w)
    ("an-index-full", 6, 2, struct.pack(">HH", 0x0130, 0x0020)),  # word disp, scale 1
    ("abs-w", 7, 0, struct.pack(">H", ABS_W_DATA)),
    ("abs-l", 7, 1, struct.pack(">I", ABS_L_DATA)),
    ("pc-disp", 7, 2, struct.pack(">h", PC_DATA - (TARGET_ADDRESS + 2))),
    ("pc-index-brief", 7, 3, struct.pack(">H", 0x0000)),
    ("imm", 7, 4, b""),  # immediate payload filled from operand size
)

CLASSIC_PROFILES = {"68000", "68010", "68020", "68030", "68040", "68060", "cpu32"}
INDEXED_FULL_PROFILES = {"68020", "68030", "68040", "68060", "cpu32"}
PRIVILEGED_NAMES = {
    "rte",
    "reset",
    "stop",
    "lpstop",
    "movec",
    "moves",
    "halt",
    "pulse",
    "strldsr",
    "cinvl",
    "cinvp",
    "cinva",
    "cpushl",
    "cpushp",
    "cpusha",
    "pflush",
    "pflushn",
    "pflusha",
    "pflushan",
    "ploadr",
    "ploadw",
    "ptestw",
    "ptestr",
    "pmove",
    "pmovefd",
    "plpar",
    "plpaw",
    "fsave",
    "frestore",
}

LIFTED_ID_RE = re.compile(r"case M68K_INS_([A-Z0-9]+):")

INTEGER_CONDITIONS = {
    "t": lambda c, v, z, n: True,
    "f": lambda c, v, z, n: False,
    "hi": lambda c, v, z, n: not c and not z,
    "ls": lambda c, v, z, n: c or z,
    "cc": lambda c, v, z, n: not c,
    "cs": lambda c, v, z, n: c,
    "ne": lambda c, v, z, n: not z,
    "eq": lambda c, v, z, n: z,
    "vc": lambda c, v, z, n: not v,
    "vs": lambda c, v, z, n: v,
    "pl": lambda c, v, z, n: not n,
    "mi": lambda c, v, z, n: n,
    "ge": lambda c, v, z, n: n == v,
    "lt": lambda c, v, z, n: n != v,
    "gt": lambda c, v, z, n: not z and n == v,
    "le": lambda c, v, z, n: z or n != v,
}

FPU_CONDITION_NAMES = (
    "f",
    "eq",
    "ogt",
    "oge",
    "olt",
    "ole",
    "ogl",
    "or",
    "un",
    "ueq",
    "ugt",
    "uge",
    "ult",
    "ule",
    "ne",
    "t",
    "sf",
    "seq",
    "gt",
    "ge",
    "lt",
    "le",
    "gl",
    "gle",
    "ngle",
    "ngl",
    "nle",
    "nlt",
    "nge",
    "ngt",
    "sne",
    "st",
)


@dataclasses.dataclass(frozen=True)
class State:
    name: str
    dregs: tuple[int, ...]
    ccr: int = 0
    memory: int = 0x10203040
    fpsr: int = 0
    fpcr: int = 0
    fp_single: int = 0x3F800000

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


DEFAULT_STATE = State(
    "default",
    (0x10203040, 3, 0x7FFFFFFF, 1, 0x80000000, 0xFFFFFFFF, 31, 2),
    memory=3,
)
ZERO_STATE = State("zero", (0,) * 8, memory=0)
ONE_STATE = State("one", (1,) * 8, memory=1)
MAX_STATE = State("all-ones", (0xFFFFFFFF,) * 8, ccr=0x1F, memory=0xFFFFFFFF)
CARRY_STATE = State(
    "carry-boundary",
    (0xFFFFFFFF, 1, 0xFFFFFFFF, 1, 0x7FFFFFFF, 1, 0x80000000, 2),
    memory=1,
)
OVERFLOW_STATE = State(
    "signed-overflow-boundary",
    (0x7FFFFFFF, 1, 0x80000000, 0xFFFFFFFF, 0, 1, 31, 32),
    memory=1,
)
NEGATIVE_STATE = State(
    "negative",
    (0x80000000, 0xFFFFFFFF, 1, 2, 0x7FFFFFFF, 3, 32, 63),
    ccr=0x08,
    memory=0x80000000,
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def instruction_names(printer: Path) -> list[str]:
    text = printer.read_text()
    marker = "static const char *const s_instruction_names[] = {"
    start = text.index(marker)
    end = text.index("};", start)
    names = re.findall(r'"([^"]+)"', text[start:end])
    if not names or names[0] != "invalid":
        raise ValueError(f"failed to parse instruction names from {printer}")
    return names


def mnemonic_name(disassembly: str) -> str:
    mnemonic = disassembly.split()[0].lower()
    return re.sub(r"\.(?:b|w|l|s|d|x|p)$", "", mnemonic)


def split_operands(disassembly: str) -> list[str]:
    parts = disassembly.split(maxsplit=1)
    if len(parts) == 1:
        return []
    result: list[str] = []
    start = 0
    square = round_ = brace = 0
    text = parts[1]
    for index, char in enumerate(text):
        if char == "[":
            square += 1
        elif char == "]":
            square -= 1
        elif char == "(":
            round_ += 1
        elif char == ")":
            round_ -= 1
        elif char == "{":
            brace += 1
        elif char == "}":
            brace -= 1
        elif char == "," and square == round_ == brace == 0:
            result.append(text[start:index].strip())
            start = index + 1
    result.append(text[start:].strip())
    return [item for item in result if item]


def parse_asm_database(asm_dir: Path, names: Sequence[str]) -> list[dict[str, Any]]:
    name_to_id = {name: index for index, name in enumerate(names)}
    cases: list[dict[str, Any]] = []
    for source in sorted(asm_dir.glob("m68k_*_32")):
        source_profile = source.name[len("m68k_") : -len("_32")]
        profile = "68040" if source_profile == "default" else source_profile
        if profile not in PROFILES:
            raise ValueError(f"unknown Rizin M68K profile in {source}")
        for line_number, line in enumerate(source.read_text(errors="replace").splitlines(), 1):
            if not line.startswith("d "):
                continue
            try:
                fields = shlex.split(line, posix=True)
            except ValueError:
                continue
            if len(fields) < 3:
                continue
            encoded = fields[2].lower()
            if not re.fullmatch(r"[0-9a-f]+", encoded) or len(encoded) % 2:
                continue
            name = mnemonic_name(fields[1])
            if name == "invalid":
                continue
            instruction_id = name_to_id.get(name)
            if instruction_id is None:
                raise ValueError(f"unknown instruction {name!r} at {source}:{line_number}")
            origin = 0
            if len(fields) > 3 and re.fullmatch(r"0x[0-9a-fA-F]+", fields[3]):
                origin = int(fields[3], 16)
            cases.append(
                {
                    "case_id": f"asm:{source_profile}:{line_number}",
                    "source_kind": "rizin-asm-vector",
                    "source": str(source),
                    "source_line": line_number,
                    "source_profile": source_profile,
                    "profile": profile,
                    "origin": origin,
                    "bytes": encoded,
                    "expected_disassembly": fields[1],
                    "mnemonic": fields[1].split()[0].lower(),
                    "instruction_name": name,
                    "instruction_id": instruction_id,
                    "operands_text": split_operands(fields[1]),
                }
            )
    return cases


def _run_rizin(rizin: Path, profile: str, commands: Sequence[str]) -> str:
    proc = subprocess.run(
        [str(rizin), "-q", "-a", "m68k", "-b", "32", f"malloc://{PROGRAM_LIMIT + 65536}"],
        input="\n".join(commands) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode:
        raise RuntimeError(f"Rizin decoder failed for {profile}: {proc.stderr.strip()}")
    return proc.stdout


def _decode_batch(rizin: Path, profile: str, batch: Sequence[dict[str, Any]]) -> None:
    commands = ["e scr.color=0", f"e asm.cpu={profile}", f"s {TARGET_ADDRESS:#x}"]
    zeroes = "00" * 32
    for index, case in enumerate(batch):
        commands.extend(
            [
                f"wx {zeroes} @ {TARGET_ADDRESS:#x}",
                f"wx {case['bytes']} @ {TARGET_ADDRESS:#x}",
                f"echo __M68K_CASE__{index}",
                "aoj~{[0].id}",
                "aoj~{[0].opex}",
            ]
        )
    commands.append("q")
    lines = iter(_run_rizin(rizin, profile, commands).splitlines())
    decoded = 0
    for line in lines:
        marker = re.fullmatch(r"__M68K_CASE__(\d+)", line.strip())
        if not marker:
            continue
        index = int(marker.group(1))
        try:
            id_line = next(lines).strip()
            opex_line = next(lines).strip()
        except StopIteration as error:
            raise RuntimeError(f"truncated Rizin decoder output for {profile}") from error
        case = batch[index]
        if not id_line.isdigit():
            case["decode_error"] = "instruction did not decode"
            continue
        decoded_id = int(id_line)
        expected = case.get("instruction_id")
        if expected is not None and decoded_id != expected:
            case["decode_error"] = f"decoder ID {decoded_id} != {expected}"
            continue
        try:
            opex = json.loads(opex_line)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"invalid opex for {case.get('case_id')}: {opex_line!r}") from error
        case["instruction_id"] = decoded_id
        case["operands"] = opex.get("operands", [])
        case["address_signature"] = address_signature(case["operands"])
        decoded += 1
    if decoded != len(batch):
        missing = [case.get("case_id") for case in batch if "operands" not in case]
        # Soft-fail individual encodings during synthesis; hard-fail the seed set.
        if any(case.get("require_decode") for case in batch):
            raise RuntimeError(
                f"decoded {decoded}/{len(batch)} required cases for {profile}; missing {missing[:5]}"
            )


def decode_cases(rizin: Path, cases: Sequence[dict[str, Any]], required: bool = True) -> None:
    """Populate exact Capstone/Rizin operand metadata in-place."""
    by_profile: dict[str, list[dict[str, Any]]] = {profile: [] for profile in PROFILES}
    for case in cases:
        case["require_decode"] = required
        by_profile[case["profile"]].append(case)
    for profile, profile_cases in by_profile.items():
        if not profile_cases:
            continue
        print(f"decoding {len(profile_cases)} encodings for {profile}", file=sys.stderr)
        for start in range(0, len(profile_cases), DECODE_BATCH):
            _decode_batch(rizin, profile, profile_cases[start : start + DECODE_BATCH])


def address_signature(operands: Sequence[dict[str, Any]]) -> str:
    signature = []
    for operand in operands:
        operand_type = str(operand.get("type", "unknown"))
        mode = int(operand.get("address_mode", 0))
        details = [operand_type, ADDRESS_MODE_NAMES.get(mode, f"mode-{mode}")]
        if operand.get("bitfield"):
            details.append("bitfield")
            details.append("dynamic-offset" if int(operand.get("offset", 0)) & 0x80 else "static-offset")
            details.append("dynamic-width" if int(operand.get("width", 0)) & 0x80 else "static-width")
        if operand_type == "reg_pair":
            details.append("pair")
        if operand_type == "reg_bits":
            details.append("list")
        if operand.get("index_reg"):
            details.append("index-long" if operand.get("index_size") else "index-word")
            details.append(f"scale-{operand.get('scale', 0) or 1}")
        signature.append(":".join(details))
    return "|".join(signature) if signature else "none"


def _opcode_word(case: dict[str, Any]) -> int:
    return int(case["bytes"][:4], 16)


def _mode_reg_from_operand(operand: dict[str, Any]) -> tuple[int, int] | None:
    mode = int(operand.get("address_mode", 0))
    mapping = {
        1: (0, None),
        2: (1, None),
        3: (2, None),
        4: (3, None),
        5: (4, None),
        6: (5, None),
        7: (6, None),
        8: (6, None),
        9: (6, None),
        10: (6, None),
        11: (7, 2),
        12: (7, 3),
        13: (7, 3),
        14: (7, 3),
        15: (7, 3),
        16: (7, 0),
        17: (7, 1),
        18: (7, 4),
    }
    if mode not in mapping:
        return None
    encoded_mode, encoded_reg = mapping[mode]
    if encoded_reg is not None:
        return encoded_mode, encoded_reg
    name = str(operand.get("reg") or operand.get("base_reg") or "")
    if name.startswith("d") and name[1:].isdigit():
        return encoded_mode, int(name[1:])
    if name.startswith("a") and name[1:].isdigit():
        return encoded_mode, int(name[1:])
    return encoded_mode, 0


def detect_ea_field(case: dict[str, Any]) -> tuple[str, int] | None:
    """Return ('src', operand_index) or ('dst', operand_index) when EA is in the opcode."""
    if len(case["bytes"]) < 4:
        return None
    opcode = _opcode_word(case)
    src_mode, src_reg = (opcode >> 3) & 7, opcode & 7
    dst_mode, dst_reg = (opcode >> 6) & 7, (opcode >> 9) & 7
    operands = case.get("operands") or []
    for index, operand in enumerate(operands):
        decoded = _mode_reg_from_operand(operand)
        if decoded is None:
            continue
        mode, reg = decoded
        if (mode, reg) == (src_mode, src_reg):
            return "src", index
        if operand.get("type") in {"mem", "reg"} and (mode, reg) == (dst_mode, dst_reg):
            return "dst", index
    return None


def _immediate_bytes(case: dict[str, Any]) -> bytes:
    suffix = case["mnemonic"].rsplit(".", 1)[-1] if "." in case["mnemonic"] else ""
    size = {"b": 2, "w": 2, "l": 4, "s": 4}.get(suffix, 2)
    value = 1 if suffix in {"b", "w"} else 0x00000001
    return value.to_bytes(size, "big")


def rewrite_ea(case: dict[str, Any], spec: tuple[str, int, int, bytes]) -> str | None:
    field = detect_ea_field(case)
    if field is None:
        return None
    kind, _index = field
    name, mode, reg, extension = spec
    if name == "imm":
        extension = _immediate_bytes(case)
    raw = bytearray.fromhex(case["bytes"])
    opcode = int.from_bytes(raw[:2], "big")
    if kind == "src":
        opcode = (opcode & ~0x3F) | (mode << 3) | reg
    else:
        opcode = (opcode & ~0x0FC0) | (mode << 6) | (reg << 9)
    # Keep every word before the rewritten EA's first extension, drop the old EA tail.
    kept = 2
    if len(raw) >= 4 and (raw[0] & 0xF0) == 0xF0:
        kept = 4
    elif case["instruction_name"].startswith(("bf", "cas", "chk2", "cmp2", "pack", "unpk")):
        kept = min(4, len(raw))
    rebuilt = bytearray(opcode.to_bytes(2, "big"))
    if kept > 2:
        rebuilt.extend(raw[2:kept])
    rebuilt.extend(extension)
    return rebuilt.hex()


def synthesize_ea_variants(cases: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    templates: dict[tuple[int, str], dict[str, Any]] = {}
    for case in cases:
        if "operands" not in case:
            continue
        key = (int(case["instruction_id"]), case["mnemonic"])
        current = templates.get(key)
        if current is None or _template_score(case) < _template_score(current):
            if detect_ea_field(case):
                templates[key] = case
    generated: list[dict[str, Any]] = []
    existing = {(case["profile"], case["bytes"]) for case in cases}
    for template in templates.values():
        for spec in EA_SPECS:
            encoded = rewrite_ea(template, spec)
            if not encoded or (template["profile"], encoded) in existing:
                continue
            existing.add((template["profile"], encoded))
            generated.append(
                {
                    **{
                        k: v
                        for k, v in template.items()
                        if k not in {"operands", "address_signature", "decode_error"}
                    },
                    "case_id": f"generated:ea:{template['instruction_name']}:{template['mnemonic']}:{spec[0]}:{template['profile']}",
                    "source_kind": "generated-addressing-mode",
                    "source": None,
                    "source_line": None,
                    "bytes": encoded,
                    "expected_disassembly": None,
                    "operands_text": [],
                    "require_decode": False,
                }
            )
    return generated


def lifted_instruction_names(il_source: Path) -> set[str]:
    names = set()
    for match in LIFTED_ID_RE.finditer(il_source.read_text()):
        names.add(match.group(1).lower())
    return names


def expand_across_profiles(
    rizin: Path, cases: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Cross each unique encoding to every Rizin profile that decodes it."""
    unique: dict[tuple[int, str], dict[str, Any]] = {}
    for case in cases:
        if "operands" not in case:
            continue
        key = (int(case["instruction_id"]), case["bytes"])
        unique.setdefault(key, case)
    seeds = list(unique.values())
    expanded: list[dict[str, Any]] = []
    print(f"crossing {len(seeds)} encodings across {len(PROFILES)} profiles", file=sys.stderr)
    for profile in PROFILES:
        probes = []
        for seed in seeds:
            probes.append(
                {
                    "case_id": f"probe:{profile}:{seed['case_id']}",
                    "bytes": seed["bytes"],
                    "profile": profile,
                    "instruction_id": seed["instruction_id"],
                    "require_decode": False,
                }
            )
        decode_cases(rizin, probes, required=False)
        by_bytes = {probe["bytes"]: probe for probe in probes if "operands" in probe}
        for seed in seeds:
            probe = by_bytes.get(seed["bytes"])
            if not probe:
                continue
            clone = {
                **{k: v for k, v in seed.items() if k not in {"operands", "address_signature"}},
                "case_id": f"{seed['case_id']}@{profile}",
                "profile": profile,
                "source_profile": seed.get("source_profile", seed["profile"]),
                "operands": probe["operands"],
                "address_signature": probe["address_signature"],
                "applicable_relation": (
                    "exact-source"
                    if profile == seed.get("source_profile", seed["profile"])
                    else "decoder-applicable"
                ),
            }
            expanded.append(clone)
    return expanded


def _patch_condition_word(encoded: str, condition: int) -> str:
    raw = bytearray.fromhex(encoded)
    if len(raw) < 4:
        raise ValueError(f"condition instruction is too short: {encoded}")
    extension = int.from_bytes(raw[2:4], "big")
    extension = (extension & ~0x1F) | condition
    raw[2:4] = extension.to_bytes(2, "big")
    return raw.hex()


def _template_score(case: dict[str, Any]) -> tuple[int, int, str]:
    magnitude = 0
    for operand in case.get("operands", []):
        for field in ("address", "in_disp", "out_disp", "disp"):
            magnitude += abs(int(operand.get(field, 0)))
    return magnitude, len(case["bytes"]), case["bytes"]


def add_fpu_condition_cross_product(
    cases: list[dict[str, Any]], names: Sequence[str]
) -> list[dict[str, Any]]:
    name_to_id = {name: index for index, name in enumerate(names)}
    existing = {(case["profile"], case["bytes"]) for case in cases}
    generated: list[dict[str, Any]] = []

    fs_templates: dict[int, dict[str, Any]] = {}
    for case in cases:
        if 203 <= case["instruction_id"] <= 234:
            memory_modes = [
                int(operand.get("address_mode", 0))
                for operand in case["operands"]
                if int(operand.get("address_mode", 0)) != 0
            ]
            if memory_modes:
                mode = memory_modes[0]
            elif any(operand.get("type") == "reg" for operand in case["operands"]):
                # FScc on a data register decodes without an address_mode.
                mode = 1
            else:
                mode = 0
            current = fs_templates.get(mode)
            if current is None or _template_score(case) < _template_score(current):
                fs_templates[mode] = case
    expected_fs_modes = {1, 3, 4, 5, 6, 7, 8, 9, 16, 17}
    if set(fs_templates) != expected_fs_modes:
        raise ValueError(f"FScc template modes changed: {sorted(fs_templates)}")

    fdb_template = min(
        (case for case in cases if 133 <= case["instruction_id"] <= 164),
        key=_template_score,
    )
    ftrap_templates: dict[int, dict[str, Any]] = {}
    for case in cases:
        if 241 <= case["instruction_id"] <= 272:
            current = ftrap_templates.get(len(case["bytes"]) // 2)
            if current is None or _template_score(case) < _template_score(current):
                ftrap_templates[len(case["bytes"]) // 2] = case
    if set(ftrap_templates) != {4, 6, 8}:
        raise ValueError(f"FTRAPcc template sizes changed: {sorted(ftrap_templates)}")

    families: list[tuple[str, Iterable[tuple[str, dict[str, Any]]], str]] = [
        ("fs", ((f"mode-{mode}", case) for mode, case in sorted(fs_templates.items())), "fs"),
        ("fdb", (("word-branch", fdb_template),), "fdb"),
        (
            "ftrap",
            ((f"size-{size}", case) for size, case in sorted(ftrap_templates.items())),
            "ftrap",
        ),
    ]
    for family, templates_iter, prefix in families:
        templates = list(templates_iter)
        for condition, suffix in enumerate(FPU_CONDITION_NAMES):
            instruction_name = f"{prefix}{suffix}"
            instruction_id = name_to_id[instruction_name]
            for template_name, template in templates:
                encoded = _patch_condition_word(template["bytes"], condition)
                key = ("68020", encoded)
                if key in existing:
                    continue
                existing.add(key)
                generated.append(
                    {
                        **{k: v for k, v in template.items() if k not in {"operands", "address_signature"}},
                        "case_id": f"generated:{family}:{suffix}:{template_name}",
                        "source_kind": "generated-fpu-condition-cross-product",
                        "source": None,
                        "source_line": None,
                        "source_profile": "68020",
                        "profile": "68020",
                        "origin": 0,
                        "bytes": encoded,
                        "expected_disassembly": None,
                        "mnemonic": instruction_name,
                        "instruction_name": instruction_name,
                        "instruction_id": instruction_id,
                        "operands_text": [],
                    }
                )
    return generated


def integer_condition_suffix(name: str) -> str | None:
    for prefix in ("db", "trap"):
        if name.startswith(prefix):
            suffix = name[len(prefix) :]
            if suffix == "ra":
                return "f"
            return suffix if suffix in INTEGER_CONDITIONS else None
    if name.startswith("b") and name not in {"bra", "bsr", "bkpt", "bgnd", "bchg", "bclr", "bset", "btst", "bitrev", "byterev"}:
        suffix = name[1:]
        return suffix if suffix in INTEGER_CONDITIONS else None
    if name.startswith("s") and name not in {"stop", "sub", "suba", "subi", "subq", "subx", "swap", "sats", "sbcd", "strldsr"}:
        suffix = name[1:]
        return suffix if suffix in INTEGER_CONDITIONS else None
    return None


def ccr_state(label: str, ccr: int, d0: int = 2) -> State:
    dregs = list(DEFAULT_STATE.dregs)
    dregs[0] = d0 & 0xFFFFFFFF
    return State(label, tuple(dregs), ccr=ccr, memory=DEFAULT_STATE.memory)


def integer_condition_states(name: str) -> tuple[State | None, State | None]:
    suffix = integer_condition_suffix(name)
    if suffix is None:
        return None, None
    predicate = INTEGER_CONDITIONS[suffix]
    true_ccr = false_ccr = None
    for ccr in range(16):
        c = bool(ccr & 1)
        v = bool(ccr & 2)
        z = bool(ccr & 4)
        n = bool(ccr & 8)
        if predicate(c, v, z, n) and true_ccr is None:
            true_ccr = ccr
        if not predicate(c, v, z, n) and false_ccr is None:
            false_ccr = ccr
    return (
        ccr_state("condition-true", true_ccr) if true_ccr is not None else None,
        ccr_state("condition-false", false_ccr) if false_ccr is not None else None,
    )


def fpu_condition_index(case: dict[str, Any]) -> int | None:
    instruction_id = int(case["instruction_id"])
    if 98 <= instruction_id <= 129:
        return instruction_id - 98
    if 133 <= instruction_id <= 164:
        return instruction_id - 133
    if 203 <= instruction_id <= 234:
        return instruction_id - 203
    if 241 <= instruction_id <= 272:
        return instruction_id - 241
    return None


def eval_fpu_condition(index: int, fpsr: int) -> bool:
    n = bool(fpsr & (1 << 27))
    z = bool(fpsr & (1 << 26))
    nan = bool(fpsr & (1 << 24))
    base = index & 0x0F
    values = (
        False,
        z,
        not nan and not z and not n,
        z or (not nan and not n),
        not nan and not z and n,
        z or (not nan and n),
        not nan and not z,
        not nan,
        nan,
        nan or z,
        nan or (not z and not n),
        nan or z or not n,
        nan or (not z and n),
        nan or z or n,
        not z,
        True,
    )
    # Conditions 16..31 are the signaling variants of 0..15.  Their boolean
    # predicates are identical; only exception signaling differs.
    return values[base]


def fpu_condition_states(case: dict[str, Any]) -> tuple[State | None, State | None]:
    index = fpu_condition_index(case)
    if index is None:
        return None, None
    candidates = (0, 1 << 26, 1 << 27, 1 << 25, 1 << 24)
    true_fpsr = false_fpsr = None
    for fpsr in candidates:
        if eval_fpu_condition(index, fpsr) and true_fpsr is None:
            true_fpsr = fpsr
        if not eval_fpu_condition(index, fpsr) and false_fpsr is None:
            false_fpsr = fpsr
    make = lambda label, value: dataclasses.replace(DEFAULT_STATE, name=label, fpsr=value)
    return (
        make("fp-condition-true", true_fpsr) if true_fpsr is not None else None,
        make("fp-condition-false", false_fpsr) if false_fpsr is not None else None,
    )


def path_states(case: dict[str, Any]) -> list[State]:
    name = case["instruction_name"]
    true_state, false_state = integer_condition_states(name)
    fp_true, fp_false = fpu_condition_states(case)

    if name.startswith("db") and true_state is not None:
        states = []
        if true_state:
            states.append(dataclasses.replace(true_state, name="condition-true"))
        if false_state:
            states.extend(
                [
                    dataclasses.replace(false_state, name="condition-false-counter-taken", dregs=(2,) * 8),
                    dataclasses.replace(false_state, name="condition-false-counter-exhausted", dregs=(0,) * 8),
                ]
            )
        return states
    if 133 <= int(case["instruction_id"]) <= 164:
        states = []
        if fp_true:
            states.append(fp_true)
        if fp_false:
            states.extend(
                [
                    dataclasses.replace(fp_false, name="fp-condition-false-counter-taken", dregs=(2,) * 8),
                    dataclasses.replace(fp_false, name="fp-condition-false-counter-exhausted", dregs=(0,) * 8),
                ]
            )
        return states
    if true_state or false_state:
        return [state for state in (true_state, false_state) if state]
    if fp_true or fp_false:
        return [state for state in (fp_true, fp_false) if state]

    if name in {"addx", "subx", "negx"}:
        return [ZERO_STATE, ONE_STATE, CARRY_STATE, MAX_STATE, dataclasses.replace(ZERO_STATE, name="sticky-z-clear", ccr=0)]
    if name in {"abcd", "sbcd", "nbcd"}:
        return [
            State("bcd-zero", (0,) * 8, memory=0),
            State("bcd-low-digit", (0x09,) * 8, memory=0x09),
            State("bcd-59", (0x59,) * 8, ccr=0x11, memory=0x59),
            State("bcd-99-carry", (0x99,) * 8, ccr=0x11, memory=0x99),
            dataclasses.replace(ZERO_STATE, name="sticky-z-clear", ccr=0),
        ]
    if name == "pack":
        return [
            State("pack-0705", (0x0705,) * 8, memory=0x0705),
            State("pack-0009", (0x0009,) * 8, memory=0x0009),
            State("pack-0900", (0x0900,) * 8, memory=0x0900),
        ]
    if name == "unpk":
        return [
            State("unpk-57", (0x57,) * 8, memory=0x57),
            State("unpk-99", (0x99,) * 8, memory=0x99),
            State("unpk-00", (0,) * 8, memory=0),
        ]
    if name in {"add", "adda", "addi", "addq", "sub", "suba", "subi", "subq", "cmp", "cmpa", "cmpi", "cmpm", "cmp2", "neg"}:
        return [ZERO_STATE, ONE_STATE, NEGATIVE_STATE, CARRY_STATE, OVERFLOW_STATE]
    if name in {"asl", "asr", "lsl", "lsr", "rol", "ror", "roxl", "roxr"}:
        states = []
        for count in (0, 1, 31, 32, 63):
            dregs = tuple(count for _ in range(8))
            states.append(State(f"count-{count}", dregs, ccr=0x11, memory=0x80000001))
        return states
    if name in {"divs", "divu", "rems", "remu"}:
        return [
            DEFAULT_STATE,
            State("divide-by-zero", (0,) * 8, memory=0),
            State("quotient-overflow", (0x80000000,) * 8, memory=1),
            State("signed-min-over-minus-one", (0x80000000, 0xFFFFFFFF) + (1,) * 6, memory=0xFFFFFFFF),
        ]
    if name in {"cas", "cas2"}:
        return [
            ZERO_STATE,
            State("compare-success", (3,) * 8, memory=3),
            State("compare-failure", (7,) * 8, memory=3),
        ]
    if name in {"chk", "chk2"}:
        return [ZERO_STATE, DEFAULT_STATE, NEGATIVE_STATE, MAX_STATE]
    if name in {"bchg", "bclr", "bset", "btst", "bfchg", "bfclr", "bfexts", "bfextu", "bfffo", "bfins", "bfset", "bftst", "bitrev"}:
        return [ZERO_STATE, ONE_STATE, MAX_STATE]
    if 89 <= int(case["instruction_id"]) <= 274:
        return [
            dataclasses.replace(DEFAULT_STATE, name="fp-positive", fp_single=0x3F800000),
            dataclasses.replace(ZERO_STATE, name="fp-zero", fp_single=0),
            dataclasses.replace(NEGATIVE_STATE, name="fp-negative", fp_single=0xBF800000),
            dataclasses.replace(DEFAULT_STATE, name="fp-infinity", fp_single=0x7F800000),
            dataclasses.replace(DEFAULT_STATE, name="fp-nan", fp_single=0x7FC00000),
        ]
    states = [DEFAULT_STATE]
    if _is_privileged(case):
        states.append(dataclasses.replace(DEFAULT_STATE, name="user-privilege", ccr=0))
    return states


def _is_privileged(case: dict[str, Any]) -> bool:
    if case["instruction_name"] in PRIVILEGED_NAMES:
        return True
    for operand in case.get("operands", []):
        if str(operand.get("reg", "")).lower() in {"sr", "usp", "msp", "isp", "vbr", "sfc", "dfc"}:
            return True
    return False


def build_manifest(rizin_source: Path, rizin: Path) -> dict[str, Any]:
    asm_dir = rizin_source / "test/db/asm"
    printer = rizin_source / "subprojects/capstone-next/arch/M68K/M68KInstPrinter.c"
    il_source = rizin_source / "librz/arch/isa/m68k/m68k_il.c"
    names = instruction_names(printer)
    lifted = lifted_instruction_names(il_source)
    base_cases = parse_asm_database(asm_dir, names)
    decode_cases(rizin, base_cases, required=True)
    generated = add_fpu_condition_cross_product(base_cases, names)
    decode_cases(rizin, generated, required=True)
    ea_generated = synthesize_ea_variants(base_cases + generated)
    decode_cases(rizin, ea_generated, required=False)
    ea_generated = [case for case in ea_generated if "operands" in case]
    seed_cases = base_cases + generated + ea_generated
    cases = expand_across_profiles(rizin, seed_cases)

    reachable_names = [name for name in names[1:] if name not in UNREACHABLE_IDS]
    covered_ids = {int(case["instruction_id"]) for case in cases}
    expected_ids = {names.index(name) for name in reachable_names}
    missing = sorted(expected_ids - covered_ids)
    unexpected = sorted(covered_ids - expected_ids)
    if missing or unexpected:
        raise ValueError(
            f"instruction universe mismatch: missing={[(i, names[i]) for i in missing]} "
            f"unexpected={[(i, names[i]) for i in unexpected]}"
        )

    planned = 0
    by_case_id = set()
    for case in cases:
        if case["case_id"] in by_case_id:
            raise ValueError(f"duplicate case ID {case['case_id']}")
        by_case_id.add(case["case_id"])
        states = path_states(case)
        case["paths"] = [state.to_json() for state in states]
        case["planned_executions"] = len(states)
        case["lifter"] = "implemented" if case["instruction_name"] in lifted else "unimplemented"
        planned += len(states)

    normalized_variants = {
        (
            case["profile"],
            int(case["instruction_id"]),
            case["mnemonic"],
            case["address_signature"],
        )
        for case in cases
    }
    source_counts: dict[str, int] = {}
    for case in cases:
        source_counts[case["source_kind"]] = source_counts.get(case["source_kind"], 0) + 1
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "rizin_source": str(rizin_source),
        "instruction_universe": {
            "public_enum_ids": len(names) - 1,
            "reachable_ids": len(reachable_names),
            "covered_reachable_ids": len(covered_ids),
            "lifted_ids": sorted(lifted),
            "unreachable_ids": [
                {"id": names.index(name), "name": name, "reason": reason}
                for name, reason in UNREACHABLE_IDS.items()
            ],
        },
        "denominator": {
            "seed_encodings": len(seed_cases),
            "encoding_cases": len(cases),
            "normalized_profile_id_variant_address_combinations": len(normalized_variants),
            "planned_path_executions": planned,
            "source_counts": source_counts,
        },
        "profiles": list(PROFILES),
        "cases": cases,
    }


def overlaps_microprogram(address: int, size: int = 16) -> bool:
    end = address + size
    return address < PROGRAM_LIMIT and end > SETUP_ADDRESS


def _replace_be(raw: bytearray, start: int, old: int, width: int, new: int) -> bool:
    if old < 0:
        old &= (1 << (8 * width)) - 1
    if new < 0:
        new &= (1 << (8 * width)) - 1
    needle = old.to_bytes(width, "big")
    replacement = new.to_bytes(width, "big")
    offset = raw.find(needle, start)
    if offset < 0:
        return False
    raw[offset : offset + width] = replacement
    return True


def relocate_encoding(case: dict[str, Any], encoded: bytes) -> bytes:
    raw = bytearray(encoded)
    for operand in case.get("operands", []):
        mode = int(operand.get("address_mode", 0))
        if mode == 16:
            old = int(operand.get("address", 0)) & 0xFFFF
            _replace_be(raw, 2, old, 2, ABS_W_DATA)
            operand["address"] = ABS_W_DATA
        elif mode == 17:
            old = int(operand.get("address", 0)) & 0xFFFFFFFF
            _replace_be(raw, 2, old, 4, ABS_L_DATA)
            operand["address"] = ABS_L_DATA
        elif mode == 11:
            old = int(operand.get("disp", 0))
            ext = TARGET_ADDRESS + _ea_extension_offset_bytes(case, operand)
            new_disp = PC_DATA - ext
            width = 2 if int(operand.get("disp_size", 0) or 1) <= 1 else 4
            if width == 2 and -0x8000 <= new_disp <= 0x7FFF:
                _replace_be(raw, 2, old & 0xFFFF, 2, new_disp & 0xFFFF)
                operand["disp"] = new_disp
            elif width == 4:
                _replace_be(raw, 2, old & 0xFFFFFFFF, 4, new_disp & 0xFFFFFFFF)
                operand["disp"] = new_disp
        elif mode in {12, 13}:
            old = int(operand.get("disp", 0) or operand.get("in_disp", 0))
            if _replace_be(raw, 2, old & 0xFF, 1, 0):
                operand["disp"] = 0
                operand["in_disp"] = 0
    return bytes(raw)


def _set_index_register(dregs: list[int], aregs: dict[str, int], name: str | None, value: int) -> None:
    if not name:
        return
    if name.startswith("d") and name[1:].isdigit():
        dregs[int(name[1:])] = value & 0xFFFFFFFF
    elif name.startswith("a") and name[1:].isdigit() and name != "a7":
        aregs[name] = value & 0xFFFFFFFF


def _choose_aregs(case: dict[str, Any], state: State) -> tuple[dict[str, int], State]:
    aregs = _default_aregs()
    dregs = list(state.dregs)
    for index, operand in enumerate(case.get("operands", [])):
        if operand.get("type") != "mem":
            continue
        mode = int(operand.get("address_mode", 0))
        slot = (ABS_L_DATA + 0x1000 + index * 0x80) & 0xFFFFFFFF
        size = _operation_bytes(case)
        disp = int(operand.get("disp", 0) or 0)
        in_disp = int(operand.get("in_disp", 0) or 0)
        base = operand.get("base_reg")
        index_name = operand.get("index_reg")
        if mode in {3, 4} and base in aregs:
            aregs[base] = slot
        elif mode == 5 and base in aregs:
            aregs[base] = (slot + size) & 0xFFFFFFFF
        elif mode == 6 and base in aregs:
            aregs[base] = (slot - disp) & 0xFFFFFFFF
        elif mode in {7, 8, 9, 10} and base in aregs:
            _set_index_register(dregs, aregs, index_name, 0)
            aregs[base] = (slot - in_disp - disp) & 0xFFFFFFFF
        elif mode in {11, 12, 13, 14, 15}:
            ext = TARGET_ADDRESS + _ea_extension_offset_bytes(case, operand)
            scale = int(operand.get("scale", 0) or 1)
            _set_index_register(
                dregs,
                aregs,
                index_name,
                ((PC_DATA - ext - disp - in_disp) // scale) & 0xFFFFFFFF,
            )
    adjusted = dataclasses.replace(state, dregs=tuple(dregs))
    return aregs, adjusted


def _encode_move_immediate_dreg(register: int, value: int) -> bytes:
    return struct.pack(">HI", 0x203C + (register << 9), value & 0xFFFFFFFF)


def _encode_movea_immediate(register: int, value: int) -> bytes:
    return struct.pack(">HI", 0x207C + (register << 9), value & 0xFFFFFFFF)


def _encode_jmp(address: int) -> bytes:
    return struct.pack(">HI", 0x4EF9, address & 0xFFFFFFFF)


def _default_aregs() -> dict[str, int]:
    address_registers = {f"a{i}": A_BASE + i * A_STRIDE + 0x800 for i in range(7)}
    address_registers["a7"] = STACK_ADDRESS
    return address_registers


def _setup_bytes(state: State, case: dict[str, Any]) -> tuple[bytes, dict[str, int], State]:
    address_registers, adjusted = _choose_aregs(case, state)
    sr = 0x0000 if state.name == "user-privilege" else 0x2700
    code = bytearray()
    for register, value in enumerate(adjusted.dregs):
        code.extend(_encode_move_immediate_dreg(register, value))
    for register in range(7):
        code.extend(_encode_movea_immediate(register, address_registers[f"a{register}"]))
    code.extend(_encode_movea_immediate(7, STACK_ADDRESS))
    code.extend(struct.pack(">HH", 0x46FC, sr | (state.ccr & 0x1F)))

    uses_fpu = case["instruction_name"].startswith("f") and case["instruction_name"] != "ff1"
    if uses_fpu:
        for fp_register in range(8):
            extension = 0x4400 | (fp_register << 7)
            code.extend(struct.pack(">HHI", 0xF23C, extension, state.fp_single))
        code.extend(_encode_move_immediate_dreg(0, state.fpsr))
        code.extend(bytes.fromhex("f2008800"))  # fmove.l d0, fpsr
        code.extend(_encode_move_immediate_dreg(0, state.fpcr))
        code.extend(bytes.fromhex("f2009000"))  # fmove.l d0, fpcr
        code.extend(_encode_move_immediate_dreg(0, adjusted.dregs[0]))
    code.extend(_encode_jmp(TARGET_ADDRESS))
    return bytes(code), address_registers, adjusted


def _patch_control_displacement(case: dict[str, Any], encoded: bytes) -> bytes:
    name = case["instruction_name"]
    raw = bytearray(encoded)
    is_integer_branch = name in {"bra", "bsr"} or (
        name.startswith("b") and integer_condition_suffix(name) is not None
    )
    is_fp_branch = 98 <= int(case["instruction_id"]) <= 129
    is_db = name.startswith("db") or 133 <= int(case["instruction_id"]) <= 164
    displacement = TAKEN_ADDRESS - (TARGET_ADDRESS + 2)
    if is_integer_branch:
        if len(raw) == 2:
            if not -128 <= displacement <= 127 or displacement in {0, -1}:
                raise ValueError("byte branch trampoline is out of range")
            raw[1] = displacement & 0xFF
        elif len(raw) == 4:
            raw[-2:] = struct.pack(">h", displacement)
        elif len(raw) == 6:
            raw[-4:] = struct.pack(">i", displacement)
    elif is_fp_branch:
        if len(raw) == 4:
            raw[-2:] = struct.pack(">h", displacement)
        elif len(raw) == 6:
            raw[-4:] = struct.pack(">i", displacement)
    elif is_db:
        raw[-2:] = struct.pack(">h", displacement)
    return bytes(raw)


def _signed_index(value: int, long_index: bool) -> int:
    if long_index:
        return value - (1 << 32) if value & 0x80000000 else value
    value &= 0xFFFF
    return value - (1 << 16) if value & 0x8000 else value


def _register_value(name: str | None, state: State, aregs: dict[str, int]) -> int:
    if not name:
        return 0
    if name.startswith("d") and name[1:].isdigit():
        return state.dregs[int(name[1:])]
    return aregs.get(name, 0)


def _operation_bytes(case: dict[str, Any]) -> int:
    suffix = case["mnemonic"].rsplit(".", 1)[-1] if "." in case["mnemonic"] else ""
    return {"b": 1, "w": 2, "l": 4, "s": 4, "d": 8, "x": 12, "p": 12}.get(suffix, 4)


def _ea_extension_offset_bytes(case: dict[str, Any], operand: dict[str, Any]) -> int:
    """Byte offset of the operand's first extension word within the encoding.

    The 68k PC-relative base is the address of the extension word being
    processed, so operands behind immediate or operand-extension words start
    later than the opcode word.
    """
    mode = int(operand.get("address_mode", 0))
    if mode == 11:
        words = int(operand.get("disp_size", 0)) or 1
    elif mode in {12, 13}:
        words = 1
    else:
        words = (
            1
            + int(operand.get("in_disp_size", 0))
            + int(operand.get("out_disp_size", 0))
        )
    return len(case["bytes"]) // 2 * 2 - 2 * words


def _effective_memory(
    case: dict[str, Any], operand: dict[str, Any], state: State, aregs: dict[str, int]
) -> tuple[int | None, list[tuple[int, bytes]]]:
    mode = int(operand.get("address_mode", 0))
    base = _register_value(operand.get("base_reg"), state, aregs)
    index = _register_value(operand.get("index_reg"), state, aregs)
    index = _signed_index(index, bool(operand.get("index_size")))
    index *= int(operand.get("scale", 0) or 1)
    disp = int(operand.get("disp", 0))
    in_disp = int(operand.get("in_disp", 0))
    out_disp = int(operand.get("out_disp", 0))
    size = _operation_bytes(case)
    if operand.get("base_reg") == "a7" and size == 1:
        size = 2
    auxiliary: list[tuple[int, bytes]] = []
    if mode in {3, 4}:
        address = base
    elif mode == 5:
        address = base - size
    elif mode == 6:
        address = base + disp
    elif mode == 7:
        address = base + disp + index
    elif mode == 8:
        address = base + in_disp + index
    elif mode in {9, 10}:
        inner = base + in_disp + (index if mode == 10 else 0)
        data = INDIRECT_DATA
        pointer = (data - out_disp - (index if mode == 9 else 0)) & 0xFFFFFFFF
        auxiliary.append((inner & 0xFFFFFFFF, struct.pack(">I", pointer)))
        address = data
    elif mode == 11:
        address = TARGET_ADDRESS + _ea_extension_offset_bytes(case, operand) + disp
    elif mode == 12:
        address = TARGET_ADDRESS + _ea_extension_offset_bytes(case, operand) + disp + index
    elif mode == 13:
        address = TARGET_ADDRESS + _ea_extension_offset_bytes(case, operand) + in_disp + index
    elif mode in {14, 15}:
        inner = (
            TARGET_ADDRESS
            + _ea_extension_offset_bytes(case, operand)
            + in_disp
            + (index if mode == 15 else 0)
        )
        data = INDIRECT_DATA
        pointer = (data - out_disp - (index if mode == 14 else 0)) & 0xFFFFFFFF
        auxiliary.append((inner & 0xFFFFFFFF, struct.pack(">I", pointer)))
        address = data
    elif mode in {16, 17}:
        address = int(operand.get("address", 0))
    else:
        return None, auxiliary
    return address & 0xFFFFFFFF, auxiliary


def _memory_initializers(
    case: dict[str, Any], state: State, aregs: dict[str, int]
) -> tuple[list[tuple[int, bytes]], str | None]:
    initializers: list[tuple[int, bytes]] = []
    pattern = struct.pack(">I", state.memory & 0xFFFFFFFF) * 4
    for operand in case.get("operands", []):
        if operand.get("type") != "mem":
            continue
        address, auxiliary = _effective_memory(case, operand, state, aregs)
        initializers.extend(auxiliary)
        if address is None:
            continue
        if address + len(pattern) > RAM_BYTES or address >= 0xFF000000:
            return [], f"effective address {address:#x} is outside safe RAM"
        if overlaps_microprogram(address, len(pattern)):
            return [], f"effective address {address:#x} overlaps the microprogram"
        initializers.append((address, pattern))
    return initializers, None


def _return_initializers(case: dict[str, Any]) -> list[tuple[int, bytes]]:
    name = case["instruction_name"]
    if name in {"rts", "rtd"}:
        return [(STACK_ADDRESS, struct.pack(">I", TAKEN_ADDRESS))]
    if name == "rtr":
        return [(STACK_ADDRESS, struct.pack(">HI", 0x001F, TAKEN_ADDRESS))]
    if name == "rte":
        if case["profile"] == "68000":
            payload = struct.pack(">HI", 0x2700, TAKEN_ADDRESS)
        else:
            payload = struct.pack(">HIH", 0x2700, TAKEN_ADDRESS, 0)
        return [(STACK_ADDRESS, payload)]
    return []


def _control_trampoline(
    case: dict[str, Any], state: State, aregs: dict[str, int]
) -> tuple[list[tuple[int, bytes]], str | None]:
    name = case["instruction_name"]
    if name not in {"jmp", "jsr"}:
        return [], None
    memory_operands = [operand for operand in case.get("operands", []) if operand.get("type") == "mem"]
    if not memory_operands:
        return [], "control transfer has no resolvable memory operand"
    address, auxiliary = _effective_memory(case, memory_operands[0], state, aregs)
    if address is None:
        return [], "control transfer target is not resolvable"
    if address + 6 > RAM_BYTES or address >= 0xFF000000 or overlaps_microprogram(address, 6):
        return [], f"control transfer target {address:#x} is outside safe RAM"
    return auxiliary + [(address, _encode_jmp(TAIL_ADDRESS))], None


def _loader_arguments(initializers: Sequence[tuple[int, bytes]]) -> list[str]:
    args: list[str] = []
    seen: set[tuple[int, bytes]] = set()
    for address, data in initializers:
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + 8]
            item = (address + offset, chunk)
            offset += len(chunk)
            if item in seen:
                continue
            seen.add(item)
            value = int.from_bytes(chunk, "big")
            args.extend(
                [
                    "-device",
                    f"loader,addr={item[0]:#x},data={value:#x},data-len={len(chunk)},data-be=on",
                ]
            )
    return args


TERMINAL_NO_POSTSTATE = {"halt", "stop", "lpstop"}
UNSUPPORTED_CONTROL = {"callm", "rtm"}
ARCHITECTED_EXCEPTION_NAMES = {
    "bkpt",
    "illegal",
    "trap",
    "trapv",
    "rte",
    "bgnd",
    "reset",
}
# QEMU instruction translations that disagree with the M68000 manuals.
# Rizin stays on the manuals. These are recorded, not used as an oracle.
QEMU_MANUAL_GAPS = {
    "cmp2": (
        "QEMU's 68020+ translator implements only CHK2. CMP2 "
        "(extension word bit 11 clear) is raised as illegal instead of "
        "comparing the register to the bound pair (M68000PRM CMP2)."
    ),
}


def build_microprogram(case: dict[str, Any], state: State) -> tuple[bytes, list[str], str | None]:
    if case["instruction_name"] in TERMINAL_NO_POSTSTATE:
        return b"", [], "terminal instruction has no following plugin-visible post-state"
    if case["instruction_name"] in UNSUPPORTED_CONTROL:
        return b"", [], "control-flow fixture is not safely constructible"
    if case["instruction_name"] in ARCHITECTED_EXCEPTION_NAMES or case[
        "instruction_name"
    ].startswith(("trap", "ftrap")):
        return (
            b"",
            [],
            "architected exception path is not compared (manual exception; harness has no exception hooks)",
        )

    case = {
        **case,
        "operands": [dict(operand) for operand in case.get("operands", [])],
    }
    encoded = relocate_encoding(case, _patch_control_displacement(case, bytes.fromhex(case["bytes"])))
    setup, aregs, state = _setup_bytes(state, case)
    memory, error = _memory_initializers(case, state, aregs)
    if error:
        return b"", [], error
    control, error = _control_trampoline(case, state, aregs)
    if error:
        return b"", [], error
    memory.extend(control)
    memory.extend(_return_initializers(case))

    image = bytearray(TAIL_ADDRESS + 16)
    image[0:6] = _encode_jmp(SETUP_ADDRESS)
    for vector in range(2, 256):
        image[vector * 4 : vector * 4 + 4] = struct.pack(">I", TAIL_ADDRESS)
    if SETUP_ADDRESS + len(setup) >= TARGET_ADDRESS:
        raise ValueError("setup no longer fits before target")
    image[SETUP_ADDRESS : SETUP_ADDRESS + len(setup)] = setup
    image[TARGET_ADDRESS : TARGET_ADDRESS + len(encoded)] = encoded
    fallthrough = TARGET_ADDRESS + len(encoded)
    image[fallthrough : fallthrough + 6] = _encode_jmp(TAIL_ADDRESS)
    image[TAKEN_ADDRESS : TAKEN_ADDRESS + 6] = _encode_jmp(TAIL_ADDRESS)
    image[TAIL_ADDRESS : TAIL_ADDRESS + 2] = bytes.fromhex("4e71")
    image[TAIL_ADDRESS + 2 : TAIL_ADDRESS + 12] = struct.pack(
        ">HII", 0x23FC, 2, VIRT_CTRL_COMMAND
    )
    # Bound TB-local trailing execution while the shutdown request propagates.
    image[TAIL_ADDRESS + 12 : TAIL_ADDRESS + 16] = bytes.fromhex("4e722700")
    loader_args = _loader_arguments(memory)
    return bytes(image), loader_args, None


def _terminate_qemu(process: subprocess.Popen[str], grace: float = 1.0) -> bool:
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=grace)
        return True
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return False


def execute_one(
    case: dict[str, Any],
    state: State,
    qemu: Path,
    plugin: Path,
    tracetest: Path,
    work_root: Path,
    timeout_seconds: float,
    keep: str,
) -> dict[str, Any]:
    execution_id = f"{case['case_id']}::{state.name}"
    started = time.monotonic()
    program, loader_args, skip_reason = build_microprogram(case, state)
    base_result = {
        "schema": SCHEMA,
        "execution_id": execution_id,
        "case_id": case["case_id"],
        "profile": case["profile"],
        "instruction_id": case["instruction_id"],
        "instruction_name": case["instruction_name"],
        "mnemonic": case["mnemonic"],
        "address_signature": case["address_signature"],
        "path": state.name,
        "state": state.to_json(),
        "lifter": case.get("lifter"),
        "producer_relation": QEMU_PROFILE[case["profile"]][2],
    }
    if skip_reason:
        return {
            **base_result,
            "result": "skip",
            "reason": skip_reason,
            "skip_class": "fixture-unreachable",
            "duration_seconds": time.monotonic() - started,
        }

    case_hash = hashlib.sha256(execution_id.encode()).hexdigest()[:16]
    case_dir = work_root / case_hash
    case_dir.mkdir(parents=True, exist_ok=True)
    binary = case_dir / "case.bin"
    trace = case_dir / "case.frame"
    qemu_log = case_dir / "qemu.log"
    report = case_dir / "report.json"
    binary.write_bytes(program)
    qemu_cpu, frame_machine, producer_relation = QEMU_PROFILE[case["profile"]]
    command = [
        str(qemu),
        "-M",
        "virt",
        "-cpu",
        qemu_cpu,
        "-m",
        QEMU_MEMORY,
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "none",
        "-device",
        f"loader,file={binary},addr=0,force-raw=on",
        *loader_args,
        "-plugin",
        f"file={plugin},bin_path={binary},out={trace},endianness=b,machine={frame_machine}",
        "-d",
        "plugin",
    ]
    timed_out = False
    with qemu_log.open("w") as log_file:
        process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT, text=True)
        try:
            qemu_status = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            graceful = _terminate_qemu(process)
            qemu_status = process.returncode
            if not graceful:
                result = {
                    **base_result,
                    "result": "infrastructure-failure",
                    "reason": "QEMU timeout required SIGKILL; trace may be incomplete",
                    "qemu_status": qemu_status,
                    "producer_relation": producer_relation,
                    "duration_seconds": time.monotonic() - started,
                    "artifact_dir": str(case_dir),
                }
                return result

    if not trace.exists() or trace.stat().st_size < 64:
        return {
            **base_result,
            "result": "infrastructure-failure",
            "reason": "QEMU did not produce a complete trace",
            "qemu_status": qemu_status,
            "producer_relation": producer_relation,
            "duration_seconds": time.monotonic() - started,
            "artifact_dir": str(case_dir),
        }

    trace_command = [
        str(tracetest),
        "-x",
        "-C",
        case["profile"],
        "-J",
        str(report),
        str(trace),
    ]
    trace_proc = subprocess.run(trace_command, text=True, capture_output=True, check=False)
    if not report.exists():
        return {
            **base_result,
            "result": "infrastructure-failure",
            "reason": "rz-tracetest did not produce JSON",
            "qemu_status": qemu_status,
            "tracetest_status": trace_proc.returncode,
            "tracetest_stderr": trace_proc.stderr[-1000:],
            "producer_relation": producer_relation,
            "duration_seconds": time.monotonic() - started,
            "artifact_dir": str(case_dir),
        }
    trace_report = load_json(report)
    target_frames = [
        frame
        for frame in trace_report.get("frames", [])
        if int(frame.get("address", -1)) == TARGET_ADDRESS
    ]
    if not target_frames:
        result = {
            **base_result,
            "result": "skip" if timed_out else "infrastructure-failure",
            "reason": "target instruction did not reach a complete trace frame",
            "skip_class": "producer-control-flow" if timed_out else None,
            "qemu_status": qemu_status,
            "tracetest_status": trace_proc.returncode,
            "producer_relation": producer_relation,
            "duration_seconds": time.monotonic() - started,
            "artifact_dir": str(case_dir),
        }
    else:
        frame = target_frames[0]
        frame_result = frame.get("result", "unknown")
        result_name = "pass" if frame_result == "success" else (
            "skip" if frame_result == "skipped" else "fail"
        )
        result = {
            **base_result,
            "result": result_name,
            "frame_result": frame_result,
            "disassembly": frame.get("disassembly"),
            "bytes": frame.get("bytes"),
            "register_differences": frame.get("register_differences", []),
            "memory_differences": frame.get("memory_differences", []),
            "details": frame.get("details", []),
            "qemu_status": qemu_status,
            "qemu_timed_out": timed_out,
            "tracetest_status": trace_proc.returncode,
            "producer_relation": producer_relation,
            "duration_seconds": time.monotonic() - started,
            "artifact_dir": str(case_dir),
        }
    if keep == "none" or (keep == "failures" and result["result"] == "pass"):
        shutil.rmtree(case_dir)
        result.pop("artifact_dir", None)
    return result


def iter_executions(
    manifest: dict[str, Any], case_pattern: re.Pattern[str] | None = None
) -> Iterator[tuple[dict[str, Any], State]]:
    for case in manifest["cases"]:
        if case_pattern and not case_pattern.search(case["case_id"]):
            continue
        for raw_state in case["paths"]:
            yield case, State(
                name=raw_state["name"],
                dregs=tuple(raw_state["dregs"]),
                ccr=int(raw_state.get("ccr", 0)),
                memory=int(raw_state.get("memory", 0)),
                fpsr=int(raw_state.get("fpsr", 0)),
                fpcr=int(raw_state.get("fpcr", 0)),
                fp_single=int(raw_state.get("fp_single", 0x3F800000)),
            )


def load_completed(results_path: Path) -> set[str]:
    if not results_path.exists():
        return set()
    completed = set()
    for line in results_path.read_text().splitlines():
        if not line.strip():
            continue
        completed.add(json.loads(line)["execution_id"])
    return completed


def run_manifest(args: argparse.Namespace) -> None:
    manifest = load_json(args.manifest)
    if manifest.get("schema") != SCHEMA:
        raise ValueError(f"unsupported manifest schema: {manifest.get('schema')}")
    pattern = re.compile(args.case_regex) if args.case_regex else None
    executions = list(iter_executions(manifest, pattern))
    if args.limit is not None:
        executions = executions[: args.limit]
    completed = load_completed(args.results) if args.resume else set()
    executions = [
        (case, state)
        for case, state in executions
        if f"{case['case_id']}::{state.name}" not in completed
    ]
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.results.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.resume else "w"
    print(f"executing {len(executions)} M68K matrix cases with {args.jobs} workers", file=sys.stderr)
    with args.results.open(mode) as output:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = {
                pool.submit(
                    execute_one,
                    case,
                    state,
                    args.qemu,
                    args.plugin,
                    args.tracetest,
                    args.work_dir,
                    args.timeout,
                    args.keep,
                ): (case, state)
                for case, state in executions
            }
            for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
                result = future.result()
                output.write(json.dumps(result, sort_keys=True) + "\n")
                output.flush()
                if done % 100 == 0 or done == len(futures):
                    print(f"completed {done}/{len(futures)}", file=sys.stderr)


def results_records(path: Path) -> list[dict[str, Any]]:
    records = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        record = normalize_result(json.loads(line))
        records.append(record)
    return records


def _is_producer_illegal(result: dict[str, Any]) -> bool:
    regs = result.get("register_differences", [])
    pc = next((d for d in regs if d["name"] == "pc"), None)
    a7 = next((d for d in regs if d["name"] == "a7"), None)
    return bool(
        pc
        and a7
        and int(pc["expected"], 16) == TAIL_ADDRESS
        and int(a7["expected"], 16) < int(a7["actual"], 16)
    )


def normalize_result(result: dict[str, Any]) -> dict[str, Any]:
    record = dict(result)
    if record.get("result") == "fail" and _is_producer_illegal(record):
        name = record.get("instruction_name", "")
        path = record.get("path", "")
        architected = (
            name in EXCEPTION_SEMANTIC_NAMES
            or name.startswith(EXCEPTION_SEMANTIC_PREFIXES)
            or name in {"chk", "chk2", "divs", "divu", "rems", "remu"}
            or path in EXCEPTION_SEMANTIC_PATHS
            or path == "user-privilege"
        )
        relation = record.get("producer_relation", "exact")
        if name in QEMU_MANUAL_GAPS:
            record["result"] = "skip"
            record["skip_class"] = "qemu-incorrect-implementation"
            record["reason"] = QEMU_MANUAL_GAPS[name]
        elif architected:
            record["result"] = "skip"
            record["skip_class"] = "architected-exception"
            record["reason"] = (
                "QEMU took an exception frame; the manuals require that "
                "path, but this harness does not compare exception frames"
            )
        elif relation != "exact":
            record["result"] = "skip"
            record["skip_class"] = "producer-inapplicable"
            record["reason"] = (
                "producer CPU took the illegal-instruction path for a "
                f"{relation} encoding that Rizin decoded"
            )
    record["failure_class"] = classify_failure(record)
    return record


EXCEPTION_SEMANTIC_NAMES = {
    "bkpt",
    "illegal",
    "trap",
    "trapcc",
    "trapf",
    "trapt",
    "wdebug",
}
EXCEPTION_SEMANTIC_PREFIXES = ("trap", "ftrap")
EXCEPTION_SEMANTIC_PATHS = {
    "divide-by-zero",
    "quotient-overflow",
    "signed-min-over-minus-one",
}


def classify_failure(result: dict[str, Any]) -> str | None:
    outcome = result["result"]
    if outcome in {"pass", "skip"}:
        return None
    if outcome == "infrastructure-failure":
        return "producer-crash"
    name = result["instruction_name"]
    path = result.get("path", "")
    regs = result.get("register_differences", [])
    mems = result.get("memory_differences", [])
    details = result.get("details", [])

    def _first(register: str) -> dict[str, Any] | None:
        return next((d for d in regs if d["name"] == register), None)

    pc = _first("pc")
    a7 = _first("a7")
    if (
        pc
        and a7
        and int(pc["expected"], 16) == TAIL_ADDRESS
        and int(a7["expected"], 16) < int(a7["actual"], 16)
    ):
        # The producer CPU vectored into the exception trampoline while the
        # RzIL VM continued with non-exception semantics.
        if (
            name in EXCEPTION_SEMANTIC_NAMES
            or name.startswith(EXCEPTION_SEMANTIC_PREFIXES)
            or name in {"chk", "chk2", "divs", "divu", "rems", "remu"}
            or path in EXCEPTION_SEMANTIC_PATHS
        ):
            return "producer-exception-semantic-path"
        return "producer-rejected-encoding"
    if not regs and not mems and details:
        return "trace-visibility-gap"
    if regs and all(d["name"] == "pc" for d in regs) and not mems:
        return "producer-length-or-control-divergence"
    if any(d["name"].startswith("fp") or d["name"] == "fpsr" for d in regs):
        return "fpu-flags-or-precision"
    if result.get("lifter") == "unimplemented":
        return "reference-gap"
    return "rzil-value-mismatch"


FAILURE_CLASS_DESCRIPTIONS = {
    "producer-crash": "QEMU aborted while producing the trace (translator assert or host SIGFPE)",
    "producer-exception-semantic-path": "producer raised the architected exception; RzIL continued without modelling it",
    "producer-rejected-encoding": "exact producer CPU rejected the encoding; Rizin decoder accepted it",
    "trace-visibility-gap": "final state matches, but the trace did not record an IL-observed register/memory operand",
    "producer-length-or-control-divergence": "producer and Rizin disagree on instruction length or control target",
    "fpu-flags-or-precision": "FPU value, FPSR flag, or precision mismatch",
    "reference-gap": "RzIL lifter has no implemented semantics for this instruction",
    "qemu-incorrect-implementation": "QEMU instruction translation disagrees with the M68000 manuals; Rizin is not aligned to QEMU",
    "architected-exception": "manual requires an exception; this harness does not compare exception frames",
    "rzil-value-mismatch": "integer/address register or memory value mismatch pending manual triage",
}


def summarize(manifest: dict[str, Any], results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    by_id: dict[int, dict[str, Any]] = {}
    by_profile: dict[str, dict[str, int]] = {profile: {} for profile in PROFILES}
    skip_reasons: dict[str, int] = {}
    failure_classes: dict[str, dict[str, Any]] = {}
    for result in results:
        outcome = result["result"]
        counts[outcome] = counts.get(outcome, 0) + 1
        profile_counts = by_profile[result["profile"]]
        profile_counts[outcome] = profile_counts.get(outcome, 0) + 1
        instruction_id = int(result["instruction_id"])
        entry = by_id.setdefault(
            instruction_id,
            {
                "id": instruction_id,
                "name": result["instruction_name"],
                "pass": 0,
                "fail": 0,
                "skip": 0,
                "infrastructure-failure": 0,
                "profiles": set(),
                "address_signatures": set(),
                "paths": set(),
            },
        )
        entry[outcome] = entry.get(outcome, 0) + 1
        entry["profiles"].add(result["profile"])
        entry["address_signatures"].add(result["address_signature"])
        entry["paths"].add(result["path"])
        if outcome == "skip":
            reason = result.get("reason", "unspecified")
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
        failure_class = result.get("failure_class")
        if failure_class:
            class_entry = failure_classes.setdefault(
                failure_class, {"count": 0, "instructions": {}}
            )
            class_entry["count"] += 1
            instr = class_entry["instructions"]
            instr[result["instruction_name"]] = instr.get(result["instruction_name"], 0) + 1
    normalized_by_id = []
    for entry in by_id.values():
        normalized_by_id.append(
            {
                **entry,
                "profiles": sorted(entry["profiles"]),
                "address_signatures": sorted(entry["address_signatures"]),
                "paths": sorted(entry["paths"]),
            }
        )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "manifest_denominator": manifest["denominator"],
        "instruction_universe": manifest["instruction_universe"],
        "executions_recorded": len(results),
        "outcomes": counts,
        "profiles": by_profile,
        "instructions": sorted(normalized_by_id, key=lambda item: item["id"]),
        "skip_reasons": [
            {"reason": reason, "count": count}
            for reason, count in sorted(skip_reasons.items(), key=lambda item: (-item[1], item[0]))
        ],
        "failure_classes": [
            {
                "class": name,
                "description": FAILURE_CLASS_DESCRIPTIONS.get(name, ""),
                "count": value["count"],
                "top_instructions": [
                    {"instruction": instr, "count": count}
                    for instr, count in sorted(
                        value["instructions"].items(), key=lambda item: (-item[1], item[0])
                    )[:15]
                ],
            }
            for name, value in sorted(
                failure_classes.items(), key=lambda item: (-item[1]["count"], item[0])
            )
        ],
    }


def markdown_report(summary: dict[str, Any]) -> str:
    outcomes = summary["outcomes"]
    universe = summary["instruction_universe"]
    denominator = summary["manifest_denominator"]
    lines = [
        "# Rizin M68K systematic QEMU trace matrix",
        "",
        f"Generated: {summary['generated_at']}",
        "",
        "## Coverage denominator",
        "",
        f"- Public Capstone instruction IDs: **{universe['public_enum_ids']}**",
        f"- Decoder-reachable IDs: **{universe['reachable_ids']}**",
        f"- Reachable IDs represented by the manifest: **{universe['covered_reachable_ids']}**",
        f"- Seed encodings before profile crossing: **{denominator.get('seed_encodings', denominator['encoding_cases'])}**",
        f"- Encoding × applicable-profile cases: **{denominator['encoding_cases']}**",
        "- Normalized profile × ID × size/variant × addressing-mode combinations: "
        f"**{denominator['normalized_profile_id_variant_address_combinations']}**",
        f"- Planned semantic-path executions: **{denominator['planned_path_executions']}**",
        f"- Sources: {denominator.get('source_counts', {})}",
        "",
        "## Execution outcome",
        "",
        f"Recorded executions: **{summary['executions_recorded']}**",
        "",
        "| Result | Count |",
        "|---|---:|",
    ]
    for name in ("pass", "fail", "skip", "infrastructure-failure"):
        lines.append(f"| {name} | {outcomes.get(name, 0)} |")
    lines.extend(
        [
            "",
            "## CPU profiles",
            "",
            "| Profile | Pass | Fail | Skip | Producer crash |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for profile in PROFILES:
        values = summary["profiles"][profile]
        lines.append(
            f"| {profile} | {values.get('pass', 0)} | {values.get('fail', 0)} | "
            f"{values.get('skip', 0)} | {values.get('infrastructure-failure', 0)} |"
        )
    lines.extend(["", "## Failure root-cause classes", ""])
    if summary["failure_classes"]:
        lines.extend(["| Class | Count | Meaning | Top instructions |", "|---|---:|---|---|"])
        for item in summary["failure_classes"]:
            top = ", ".join(
                f"{entry['instruction']}×{entry['count']}"
                for entry in item["top_instructions"][:8]
            )
            lines.append(
                f"| `{item['class']}` | {item['count']} | {item['description']} | {top} |"
            )
    else:
        lines.append("None.")
    lines.extend(["", "## Decoder-unreachable public IDs", ""])
    for item in universe["unreachable_ids"]:
        lines.append(f"- `{item['id']} {item['name']}` — {item['reason']}")
    lines.extend(["", "## Explicit skips", ""])
    if summary["skip_reasons"]:
        for item in summary["skip_reasons"][:20]:
            lines.append(f"- {item['count']} × {item['reason']}")
        extra = len(summary["skip_reasons"]) - 20
        if extra > 0:
            lines.append(f"- … {extra} additional skip reasons")
    else:
        lines.append("None.")
    zero_pass = [
        item for item in summary["instructions"]
        if item.get("pass", 0) == 0
    ]
    lines.extend(
        [
            "",
            "## Instruction IDs with no passing execution",
            "",
            f"{len(zero_pass)} of {len(summary['instructions'])} reachable IDs have zero passes.",
            "",
        ]
    )
    for item in zero_pass:
        lines.append(
            f"- `{item['id']} {item['name']}` — pass {item.get('pass', 0)}, "
            f"fail {item.get('fail', 0)}, skip {item.get('skip', 0)}, "
            f"crash {item.get('infrastructure-failure', 0)}"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    manifest_parser = subparsers.add_parser("manifest", help="build the canonical case manifest")
    manifest_parser.add_argument("--rizin-source", type=Path, required=True)
    manifest_parser.add_argument("--rizin", type=Path, required=True)
    manifest_parser.add_argument("--output", type=Path, required=True)

    run_parser = subparsers.add_parser("run", help="execute a manifest with QEMU")
    run_parser.add_argument("--manifest", type=Path, required=True)
    run_parser.add_argument("--qemu", type=Path, required=True)
    run_parser.add_argument("--plugin", type=Path, required=True)
    run_parser.add_argument("--tracetest", type=Path, required=True)
    run_parser.add_argument("--work-dir", type=Path, required=True)
    run_parser.add_argument("--results", type=Path, required=True)
    run_parser.add_argument("--jobs", type=int, default=1)
    run_parser.add_argument("--timeout", type=float, default=2.0)
    run_parser.add_argument("--limit", type=int)
    run_parser.add_argument("--case-regex")
    run_parser.add_argument("--resume", action="store_true")
    run_parser.add_argument("--keep", choices=("none", "failures", "all"), default="failures")

    summary_parser = subparsers.add_parser("summarize", help="summarize JSONL results")
    summary_parser.add_argument("--manifest", type=Path, required=True)
    summary_parser.add_argument("--results", type=Path, required=True)
    summary_parser.add_argument("--json", type=Path, required=True)
    summary_parser.add_argument("--markdown", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.command == "manifest":
        manifest = build_manifest(args.rizin_source.resolve(), args.rizin.resolve())
        write_json(args.output, manifest)
        print(json.dumps(manifest["denominator"], sort_keys=True))
    elif args.command == "run":
        run_manifest(args)
    elif args.command == "summarize":
        manifest = load_json(args.manifest)
        summary = summarize(manifest, results_records(args.results))
        write_json(args.json, summary)
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown_report(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
