from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from kcrash.collector.vmcore_reader import Frame


@dataclass
class CrashFingerprint:
    hash_value: str
    top_function: str
    error_class: str
    module: str
    stack_signature: list[str]
    depth: int
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hash": self.hash_value,
            "top_function": self.top_function,
            "error_class": self.error_class,
            "module": self.module,
            "stack_signature": self.stack_signature,
            "depth": self.depth,
        }


ERROR_CLASSES = {
    "BUG": "kernel_bug",
    "Oops": "kernel_oops",
    "Unable to handle kernel NULL pointer": "null_deref",
    "unable to handle page fault": "page_fault",
    "general protection fault": "gpf",
    "kernel panic": "panic",
    "divide error": "divide_error",
    "stack overflow": "stack_overflow",
    "double fault": "double_fault",
    "NMI": "nmi",
    "RIP:": "rip_crash",
}


def classify_error(dmesg: str) -> str:
    for marker, error_class in ERROR_CLASSES.items():
        if marker in dmesg:
            return error_class
    return "unknown"


def generate_fingerprint(
    frames: list[Frame], dmesg: str = ""
) -> CrashFingerprint:
    if not frames:
        return CrashFingerprint(
            hash_value="empty",
            top_function="unknown",
            error_class="unknown",
            module="",
            stack_signature=[],
            depth=0,
        )

    top = frames[0]
    error_class = classify_error(dmesg)

    module = top.module
    if not module:
        for f in frames:
            if f.module:
                module = f.module
                break

    max_depth = min(5, len(frames))
    stack_sig = [
        f"{f.function}+0x{f.offset:x}" for f in frames[:max_depth]
    ]

    hash_input = json.dumps(
        {"func": top.function, "offset": top.offset, "err": error_class, "sig": stack_sig},
        sort_keys=True,
    )
    hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    return CrashFingerprint(
        hash_value=hash_value,
        top_function=top.function,
        error_class=error_class,
        module=module,
        stack_signature=stack_sig,
        depth=len(frames),
        raw={"dmesg_snippet": dmesg[:500]},
    )


def is_similar(
    fp1: CrashFingerprint, fp2: CrashFingerprint, threshold: float = 0.7
) -> bool:
    if fp1.hash_value == fp2.hash_value:
        return True
    if fp1.top_function != fp2.top_function:
        return False
    if fp1.error_class != fp2.error_class:
        return False

    if not fp1.stack_signature or not fp2.stack_signature:
        return False

    set1 = set(fp1.stack_signature)
    set2 = set(fp2.stack_signature)
    intersection = len(set1 & set2)
    union = len(set1 | set2)

    if union == 0:
        return False

    jaccard = intersection / union
    return jaccard >= threshold
