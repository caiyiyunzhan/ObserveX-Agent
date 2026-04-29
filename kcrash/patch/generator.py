from __future__ import annotations

import json
from typing import Any

from openai import OpenAI

from kcrash.agents.base_agent import Argument
from kcrash.reasoning.prompts import EBPF_GENERATION_SYSTEM, EBPF_GENERATION_USER
from kcrash.reasoning.chain_panic import _call_llm
from kcrash.utils.logging import get_logger

logger = get_logger("kcrash.patch.ebpf")


BPF_NULL_DEREF_TEMPLATE = """\
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>

BPF_HASH(call_counts, u64, u64);
BPF_PERF_OUTPUT(events);

struct event_t {{
    u64 pid;
    u64 timestamp;
    u64 addr;
    char comm[TASK_COMM_LEN];
    char func[64];
}};

int trace_{func_name}(struct pt_regs *ctx) {{
    u64 pid = bpf_get_current_pid_tgid();
    u64 zero = 0;
    u64 *count = call_counts.lookup_or_init(&pid, &zero);
    *count += 1;

    struct event_t evt = {{}};
    evt.pid = pid;
    evt.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_kernel(&evt.func, sizeof(evt.func), "{func_name}");

#ifdef __TARGET_ARCH_x86
    evt.addr = PT_REGS_PARM1(ctx);
#else
    evt.addr = 0;
#endif

    events.perf_submit(ctx, &evt, sizeof(evt));

    bpf_trace_printk(
        "kcrash: {func_name} pid=%llu count=%llu\\n",
        pid, *count
    );

    return 0;
}}
"""

BPF_PAGE_FAULT_TEMPLATE = """\
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/sched.h>

BPF_HASH(fault_addrs, u64, u64);
BPF_PERF_OUTPUT(fault_events);

struct fault_event {{
    u64 pid;
    u64 addr;
    u64 timestamp;
    u32 cpu;
    char comm[TASK_COMM_LEN];
}};

int trace_{func_name}(struct pt_regs *ctx) {{
    u64 pid = bpf_get_current_pid_tgid();
    u64 addr = PT_REGS_PARM1(ctx);

    if (addr == 0) {{
        struct fault_event evt = {{}};
        evt.pid = pid;
        evt.addr = addr;
        evt.timestamp = bpf_ktime_get_ns();
        evt.cpu = bpf_get_smp_processor_id();
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

        fault_events.perf_submit(ctx, &evt, sizeof(evt));

        bpf_trace_printk(
            "kcrash: NULL deref in {func_name} pid=%llu cpu=%u\\n",
            pid, evt.cpu
        );
    }}

    u64 zero = 0;
    u64 *count = fault_addrs.lookup_or_init(&addr, &zero);
    *count += 1;

    return 0;
}}
"""

BPF_MEMORY_LEAK_TEMPLATE = """\
#include <uapi/linux/ptrace.h>
#include <linux/slab.h>
#include <linux/sched.h>

BPF_HASH(allocs, u64, u64);
BPF_HASH(frees, u64, u64);
BPF_PERF_OUTPUT(leak_events);

struct alloc_event {{
    u64 pid;
    u64 addr;
    u64 size;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char func[64];
}};

int trace_{func_name}_alloc(struct pt_regs *ctx) {{
    u64 size = PT_REGS_PARM1(ctx);
    u64 pid = bpf_get_current_pid_tgid();

    if (size > 1024 * 1024) {{
        struct alloc_event evt = {{}};
        evt.pid = pid;
        evt.size = size;
        evt.timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        bpf_probe_read_kernel(&evt.func, sizeof(evt.func), "{func_name}");

        leak_events.perf_submit(ctx, &evt, sizeof(evt));

        bpf_trace_printk(
            "kcrash: {func_name} large alloc %llu bytes pid=%llu\\n",
            size, pid
        );
    }}

    return 0;
}}

int trace_kfree_enter(struct pt_regs *ctx) {{
    u64 addr = PT_REGS_PARM1(ctx);
    u64 pid = bpf_get_current_pid_tgid();

    u64 zero = 0;
    u64 *count = frees.lookup_or_init(&addr, &zero);
    *count += 1;

    return 0;
}}
"""

BPF_RACE_CONDITION_TEMPLATE = """\
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_ARRAY(lock_contention, u64, 1);
BPF_PERF_OUTPUT(race_events);

struct race_event {{
    u64 pid;
    u64 timestamp;
    u32 cpu;
    char comm[TASK_COMM_LEN];
    char func[64];
}};

int trace_{func_name}_enter(struct pt_regs *ctx) {{
    u32 key = 0;
    u64 *count = lock_contention.lookup(&key);
    if (count) {{
        lock_contention.update(&key, *count + 1);
    }}

    struct race_event evt = {{}};
    evt.pid = bpf_get_current_pid_tgid();
    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_kernel(&evt.func, sizeof(evt.func), "{func_name}");

    race_events.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}}

int trace_{func_name}_exit(struct pt_regs *ctx) {{
    u32 key = 0;
    u64 *count = lock_contention.lookup(&key);
    if (count && *count > 100) {{
        bpf_trace_printk(
            "kcrash: high contention on {func_name}: %llu calls\\n",
            *count
        );
    }}
    return 0;
}}
"""

BPF_GENERIC_MONITOR_TEMPLATE = """\
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(call_counts, u64, u64);
BPF_HASH(latency_sum, u64, u64);
BPF_HASH(entry_times, u64, u64);
BPF_PERF_OUTPUT(monitor_events);

struct monitor_event {{
    u64 pid;
    u64 latency_ns;
    u64 timestamp;
    u32 cpu;
    char comm[TASK_COMM_LEN];
    char func[64];
}};

int trace_{func_name}_enter(struct pt_regs *ctx) {{
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    entry_times.update(&pid, &ts);

    u64 zero = 0;
    u64 *count = call_counts.lookup_or_init(&pid, &zero);
    *count += 1;

    return 0;
}}

int trace_{func_name}_exit(struct pt_regs *ctx) {{
    u64 pid = bpf_get_current_pid_tgid();
    u64 now = bpf_ktime_get_ns();

    u64 *entry_ts = entry_times.lookup(&pid);
    if (entry_ts) {{
        u64 latency = now - *entry_ts;

        struct monitor_event evt = {{}};
        evt.pid = pid;
        evt.latency_ns = latency;
        evt.timestamp = now;
        evt.cpu = bpf_get_smp_processor_id();
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        bpf_probe_read_kernel(&evt.func, sizeof(evt.func), "{func_name}");

        monitor_events.perf_submit(ctx, &evt, sizeof(evt));

        if (latency > 1000000000ULL) {{
            bpf_trace_printk(
                "kcrash: SLOW {func_name} latency=%lluns pid=%llu\\n",
                latency, pid
            );
        }}

        entry_times.delete(&pid);
    }}

    return 0;
}}
"""


TEMPLATE_MAP = {
    "null_deref": BPF_NULL_DEREF_TEMPLATE,
    "page_fault": BPF_PAGE_FAULT_TEMPLATE,
    "memory_leak": BPF_MEMORY_LEAK_TEMPLATE,
    "race_condition": BPF_RACE_CONDITION_TEMPLATE,
}


class EbpfGenerator:
    def __init__(
        self,
        llm_client: OpenAI | None = None,
        model: str = "gpt-4-turbo",
        max_tokens: int = 4096,
    ) -> None:
        self._client = llm_client
        self._model = model
        self._max_tokens = max_tokens

    def generate(
        self,
        verdict: Argument,
        kernel_version: str = "5.14.0",
        template: str | None = None,
    ) -> str:
        func_name = self._extract_function(verdict)

        if template and template in TEMPLATE_MAP:
            return TEMPLATE_MAP[template].format(func_name=func_name)

        if self._client is None:
            return self._generate_smart_skeleton(verdict, func_name)

        return self._generate_llm(verdict, func_name, kernel_version)

    def _extract_function(self, verdict: Argument) -> str:
        for ev in verdict.evidences:
            if "+" in ev and "0x" in ev:
                parts = ev.split("+")[0].strip()
                for prefix in ["Panic at ", "Panic point: "]:
                    if parts.startswith(prefix):
                        parts = parts[len(prefix):]
                return parts.strip()
        return "unknown_function"

    def _generate_llm(
        self, verdict: Argument, func_name: str, kernel_version: str
    ) -> str:
        claim = verdict.claim
        user_prompt = EBPF_GENERATION_USER.format(
            root_cause=claim,
            affected_function=func_name,
            kernel_version=kernel_version,
        )

        try:
            raw = _call_llm(
                self._client, self._model,
                EBPF_GENERATION_SYSTEM, user_prompt, self._max_tokens,
            )
            code = raw.strip()
            if code.startswith("```"):
                lines = code.splitlines()
                lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                code = "\n".join(lines)
            return code
        except Exception as exc:
            logger.warning("LLM eBPF generation failed: %s, using template", exc)
            return self._generate_smart_skeleton(verdict, func_name)

    def _generate_smart_skeleton(
        self, verdict: Argument, func_name: str
    ) -> str:
        error_class = self._classify_error(verdict.claim)
        template = TEMPLATE_MAP.get(error_class, BPF_GENERIC_MONITOR_TEMPLATE)
        return template.format(func_name=func_name)

    @staticmethod
    def _classify_error(claim: str) -> str:
        claim_lower = claim.lower()
        if "null" in claim_lower or "nul" in claim_lower:
            return "null_deref"
        if "page fault" in claim_lower or "page_fault" in claim_lower:
            return "page_fault"
        if "leak" in claim_lower or "oom" in claim_lower or "memory" in claim_lower:
            return "memory_leak"
        if "race" in claim_lower or "deadlock" in claim_lower or "contention" in claim_lower:
            return "race_condition"
        return "generic"
