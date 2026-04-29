from __future__ import annotations

from typing import Any

from kcrash.agents.base_agent import Argument
from kcrash.llm.client import LLMClient
from kcrash.utils.logging import get_logger

logger = get_logger("kcrash.patch.kpatch")


KPATCH_TEMPLATE = """\
#include <linux/module.h>
#include <linux/livepatch.h>

static int kcrash_patch_ret0(void)
{{
    return 0;
}}

static struct klp_func funcs[] = {{
    {{
        .old_name = "{function_name}",
        .new_func = kcrash_patch_ret0,
    }},
    {{ }}
}};

static struct klp_object objs[] = {{
    {{
        .name = "{module_name}",
        .funcs = funcs,
    }},
    {{ }}
}};

static struct klp_patch patch = {{
    .mod = THIS_MODULE,
    .objs = objs,
    .replace = true,
}};

static int __init kpatch_init(void)
{{
    int ret;

    ret = klp_enable_patch(&patch);
    if (ret)
        pr_err("kcrash: failed to enable live patch (%d)\\n", ret);
    else
        pr_info("kcrash: live patch applied for {function_name}\\n");

    return ret;
}}

static void __exit kpatch_exit(void)
{{
    pr_info("kcrash: live patch unloaded\\n");
}}

module_init(kpatch_init);
module_exit(kpatch_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kcrash hot-patch for {function_name} in {module_name}");
MODULE_VERSION("1.0");
"""

KPATCH_MAKEFILE = """\
obj-m := kpatch.o
KDIR := /lib/modules/$(shell uname -r)/build

all:
\t$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
\t$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
\tinsmod kpatch.ko

remove:
\trmmod kpatch
"""


class KpatchGenerator:
    def __init__(
        self,
        llm_client: LLMClient | None = None,
        kernel_source_dir: str = "/usr/src/kernels/$(uname -r)",
    ) -> None:
        self._llm = llm_client
        self._kernel_source_dir = kernel_source_dir

    def generate(self, verdict: Argument) -> str:
        function_name = self._extract_function(verdict)
        module_name = self._extract_module(verdict)

        if self._llm:
            return self._generate_llm(verdict, function_name, module_name)

        return self._generate_template(function_name, module_name)

    def _extract_function(self, verdict: Argument) -> str:
        for ev in verdict.evidences:
            if "+" in ev and "0x" in ev:
                parts = ev.split("+")[0].strip()
                for prefix in ["Panic at ", "Panic point: "]:
                    if parts.startswith(prefix):
                        parts = parts[len(prefix):]
                return parts.strip()

        claim = verdict.claim
        for marker in ["at ", "in "]:
            idx = claim.find(marker)
            if idx >= 0:
                rest = claim[idx + len(marker):].split()[0]
                if "+" in rest:
                    rest = rest.split("+")[0]
                return rest

        return "target_function"

    def _extract_module(self, verdict: Argument) -> str:
        for ev in verdict.evidences:
            if ev.startswith("Module:"):
                return ev.split(":", 1)[1].strip()
        return "target_module"

    def _generate_template(
        self, function_name: str, module_name: str
    ) -> str:
        return KPATCH_TEMPLATE.format(
            function_name=function_name,
            module_name=module_name,
        )

    def _generate_llm(
        self, verdict: Argument, function_name: str, module_name: str
    ) -> str:
        system = """\
You are a Linux kernel livepatch expert. Generate a kpatch-style live patch module
that hot-fixes the given crash. Use the klp_func/klp_object/klp_patch structure.
The patch should be a loadable kernel module (.ko) that can be insmod'd directly.
Output only valid C code."""

        user = f"""\
## Root Cause
{verdict.claim}

## Affected Function
{function_name}

## Module
{module_name}

## Evidence
{chr(10).join(verdict.evidences)}

Generate a kpatch live patch module source file."""

        try:
            result = self._llm.chat(system, user, max_tokens=4096)
            code = result.content.strip()
            if code.startswith("```"):
                lines = code.splitlines()
                lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                code = "\n".join(lines)
            return code
        except Exception as exc:
            logger.warning("LLM kpatch generation failed, using template: %s", exc)
            return self._generate_template(function_name, module_name)

    @staticmethod
    def generate_makefile() -> str:
        return KPATCH_MAKEFILE
