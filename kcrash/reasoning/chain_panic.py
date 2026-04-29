from __future__ import annotations

import json
from typing import Any

from kcrash.collector.vmcore_reader import VMCoreReader
from kcrash.reasoning.prompts import PHASE1_SYSTEM, PHASE1_USER
from kcrash.utils.logging import get_logger

logger = get_logger("kcrash.reasoning.panic")


def _call_llm(client: Any, model: str, system: str, user: str, max_tokens: int) -> str:
    from kcrash.llm.client import LLMClient
    from openai import OpenAI

    if isinstance(client, LLMClient):
        result = client.chat(system, user, max_tokens=max_tokens)
        return result.content
    elif isinstance(client, OpenAI):
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=0.1,
        )
        from kcrash.utils.token_counter import get_token_counter
        counter = get_token_counter()
        counter.record(
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
        )
        return response.choices[0].message.content or ""
    else:
        raise TypeError(f"Unsupported client type: {type(client)}")


def phase1_semantic_analysis(
    reader: VMCoreReader,
    llm_client: Any,
    model: str = "gpt-4-turbo",
    max_tokens: int = 4096,
) -> dict[str, Any]:
    stack_frames = reader.get_panic_stack()
    panic_stack_text = "\n".join(
        f"  [{i}] {f.function}+0x{f.offset:x} (ip=0x{f.ip:x}, module={f.module})"
        for i, f in enumerate(stack_frames)
    )

    registers = _extract_registers(stack_frames)
    dmesg = reader.read_kernel_log()

    deref_chain = {}
    if stack_frames:
        top = stack_frames[0]
        deref_chain = reader.dereference_chain(
            start_addr=top.ip, struct_type="struct page", depth=3
        )

    user_prompt = PHASE1_USER.format(
        panic_stack=panic_stack_text,
        registers=json.dumps(registers, indent=2),
        deref_chain=json.dumps(deref_chain, indent=2),
        dmesg=dmesg,
    )

    raw = _call_llm(llm_client, model, PHASE1_SYSTEM, user_prompt, max_tokens)

    try:
        return _parse_json_response(raw)
    except json.JSONDecodeError:
        logger.warning("Failed to parse Phase 1 LLM response as JSON")
        return {
            "panic_point": stack_frames[0].function if stack_frames else "unknown",
            "root_object_type": "unknown",
            "error_class": "parse_failure",
            "evidence": [raw],
            "confidence": 0.1,
            "register_analysis": {},
            "pointer_chain": [],
            "possible_leaks": [],
            "dmesg_warnings": [],
        }


def _extract_registers(frames: list) -> dict:
    if not frames:
        return {}
    return {
        "top_function": frames[0].function,
        "top_ip": hex(frames[0].ip),
        "top_module": frames[0].module,
        "top_offset": hex(frames[0].offset),
        "stack_depth": len(frames),
        "modules_involved": list({f.module for f in frames if f.module}),
    }


def _parse_json_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        if lines and lines[0].startswith("json"):
            lines[0] = lines[0][4:]
        text = "\n".join(lines)
    return json.loads(text)
