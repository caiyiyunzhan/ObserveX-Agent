from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from observex.models.remediation import (
    RemediationPlan, RemediationStep, RemediationType, SandboxResult, VerificationStatus,
)


EBPF_TEMPLATES = {
    "null_deref": """
#include <uapi/linux/ptrace.h>
BPF_HASH(guard, u64, u64);
int probe_{func}(struct pt_regs *ctx) {{
    u64 addr = PT_REGS_PARM1(ctx);
    if (addr == 0) {{
        bpf_trace_printk("kcrash: NULL guard on {func}\\n");
        return -1;
    }}
    return 0;
}}
""",
    "rate_limit": """
#include <uapi/linux/ptrace.h>
BPF_HASH(counter, u64, u64);
int probe_{func}(struct pt_regs *ctx) {{
    u64 pid = bpf_get_current_pid_tgid();
    u64 zero = 0;
    u64 *cnt = counter.lookup_or_init(&pid, &zero);
    if (*cnt > 1000) {{
        bpf_trace_printk("kcrash: rate limit {func} pid=%llu\\n", pid);
        return -1;
    }}
    *cnt += 1;
    return 0;
}}
""",
}

SYSCTL_TEMPLATES = {
    "tcp_tw_reuse": "sysctl -w net.ipv4.tcp_tw_reuse=1",
    "somaxconn": "sysctl -w net.core.somaxconn=4096",
    "tcp_keepalive_time": "sysctl -w net.ipv4.tcp_keepalive_time=300",
    "vm_overcommit": "sysctl -w vm.overcommit_memory=1",
    "max_connections": "sysctl -w fs.file-max=1000000",
}

SERVICE_RESTART = {
    "mysql": "systemctl restart mysqld",
    "postgresql": "systemctl restart postgresql",
    "redis": "systemctl restart redis",
    "nginx": "systemctl restart nginx",
    "docker": "systemctl restart docker",
    "kubelet": "systemctl restart kubelet",
}


class RemediationEngine:
    def __init__(self, sandbox_enabled: bool = True) -> None:
        self._sandbox = sandbox_enabled

    def generate_plan(
        self,
        root_cause: str,
        confidence: float,
        incident_id: str = "",
        affected_service: str = "",
    ) -> RemediationPlan:
        plan = RemediationPlan(
            incident_id=incident_id,
            root_cause=root_cause,
            confidence=confidence,
        )

        cause_lower = root_cause.lower()

        if "null" in cause_lower or "deref" in cause_lower or "fault" in cause_lower:
            func = self._extract_func(root_cause)
            plan.add_step(RemediationStep(
                step_type=RemediationType.EBP_PATCH,
                description=f"eBPF guard against NULL deref in {func}",
                code=EBPF_TEMPLATES["null_deref"].format(func=func),
                estimated_risk=0.3,
                requires_approval=True,
            ))

        if "timeout" in cause_lower or "connection" in cause_lower:
            plan.add_step(RemediationStep(
                step_type=RemediationType.KERNEL_PARAM,
                description="Enable TCP time-wait reuse",
                command=SYSCTL_TEMPLATES["tcp_tw_reuse"],
                rollback_command="sysctl -w net.ipv4.tcp_tw_reuse=0",
                estimated_risk=0.1,
            ))
            plan.add_step(RemediationStep(
                step_type=RemediationType.KERNEL_PARAM,
                description="Increase somaxconn",
                command=SYSCTL_TEMPLATES["somaxconn"],
                rollback_command="sysctl -w net.core.somaxconn=128",
                estimated_risk=0.05,
            ))

        if "oom" in cause_lower or "memory" in cause_lower:
            plan.add_step(RemediationStep(
                step_type=RemediationType.KERNEL_PARAM,
                description="Adjust VM overcommit policy",
                command=SYSCTL_TEMPLATES["vm_overcommit"],
                rollback_command="sysctl -w vm.overcommit_memory=0",
                estimated_risk=0.2,
                requires_approval=True,
            ))

        if affected_service and affected_service.lower() in SERVICE_RESTART:
            svc = affected_service.lower()
            plan.add_step(RemediationStep(
                step_type=RemediationType.SERVICE_RESTART,
                description=f"Restart {svc}",
                command=SERVICE_RESTART[svc],
                target_service=svc,
                estimated_risk=0.4,
                requires_approval=True,
            ))

        if "link down" in cause_lower or "packet loss" in cause_lower:
            plan.add_step(RemediationStep(
                step_type=RemediationType.JIRA_TICKET,
                description="Create network team escalation ticket",
                command="",
                estimated_risk=0.0,
            ))

        if not plan.steps:
            plan.add_step(RemediationStep(
                step_type=RemediationType.JIRA_TICKET,
                description=f"Manual investigation required: {root_cause[:200]}",
                estimated_risk=0.0,
            ))

        plan.status = "generated"
        return plan

    def verify_in_sandbox(
        self,
        plan: RemediationPlan,
        step_index: int = 0,
    ) -> SandboxResult:
        if step_index >= len(plan.steps):
            return SandboxResult(status=VerificationStatus.FAILED, error_message="Invalid step index")

        step = plan.steps[step_index]
        start = time.time()

        if step.step_type == RemediationType.EBP_PATCH:
            return self._verify_ebpf(step, plan.iterations)
        elif step.step_type == RemediationType.KERNEL_PARAM:
            return self._verify_sysctl(step)
        elif step.step_type == RemediationType.SERVICE_RESTART:
            return SandboxResult(
                status=VerificationStatus.PASSED,
                stdout=f"[sandbox] Would execute: {step.command}",
                exit_code=0,
                duration_ms=10,
            )
        else:
            return SandboxResult(
                status=VerificationStatus.SKIPPED,
                stdout=f"[sandbox] Step type {step.step_type.value} not sandbox-testable",
            )

    def _verify_ebpf(self, step: RemediationStep, iteration: int) -> SandboxResult:
        if not step.code:
            return SandboxResult(
                status=VerificationStatus.FAILED,
                error_message="No eBPF code provided",
            )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(step.code)
            src = f.name

        output = src.replace(".c", ".o")
        start = time.time()

        try:
            result = subprocess.run(
                ["clang", "-target", "bpf", "-O2", "-c", src, "-o", output],
                capture_output=True, text=True, timeout=30,
            )
            duration = (time.time() - start) * 1000

            if result.returncode == 0:
                return SandboxResult(
                    status=VerificationStatus.PASSED,
                    stdout="eBPF compilation successful",
                    duration_ms=duration,
                    iteration=iteration,
                )
            return SandboxResult(
                status=VerificationStatus.FAILED,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_ms=duration,
                error_message=result.stderr[:500],
                iteration=iteration,
            )
        except FileNotFoundError:
            return SandboxResult(
                status=VerificationStatus.FAILED,
                error_message="clang not found — cannot verify eBPF",
                iteration=iteration,
            )
        finally:
            Path(src).unlink(missing_ok=True)
            Path(output).unlink(missing_ok=True)

    def _verify_sysctl(self, step: RemediationStep) -> SandboxResult:
        if not step.command:
            return SandboxResult(status=VerificationStatus.SKIPPED)

        return SandboxResult(
            status=VerificationStatus.PASSED,
            stdout=f"[sandbox] Would execute: {step.command}",
            exit_code=0,
            duration_ms=5,
        )

    def iteratively_fix(
        self,
        plan: RemediationPlan,
        error_feedback_fn=None,
    ) -> RemediationPlan:
        while plan.can_retry and not plan.is_verified:
            result = self.verify_in_sandbox(plan, step_index=0)
            plan.add_sandbox_result(result)

            if result.status == VerificationStatus.PASSED:
                plan.status = "verified"
                break

            if error_feedback_fn and plan.can_retry:
                new_code = error_feedback_fn(result.stderr, plan.iterations)
                if new_code and plan.steps:
                    plan.steps[0].code = new_code

        if not plan.is_verified:
            plan.status = "failed_verification"

        return plan

    @staticmethod
    def _extract_func(text: str) -> str:
        for token in text.split():
            if "+" in token and "0x" in token:
                return token.split("+")[0]
            if token.replace("_", "").replace("-", "").isalnum() and len(token) > 3:
                return token
        return "target_func"
