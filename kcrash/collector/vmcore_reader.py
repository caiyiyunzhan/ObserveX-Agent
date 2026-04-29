from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Frame:
    function: str
    offset: int
    ip: int
    module: str = ""
    source_line: str = ""


class VMCoreReader:
    def __init__(self, vmcore_path: str, vmlinux_path: str) -> None:
        self.vmcore_path = Path(vmcore_path)
        self.vmlinux_path = Path(vmlinux_path)
        self._mock_data: dict[str, Any] | None = None

        if self.vmcore_path.suffix == ".json":
            with open(self.vmcore_path, "r") as f:
                self._mock_data = json.load(f)

    def get_panic_stack(self) -> list[Frame]:
        if self._mock_data is not None:
            return [
                Frame(
                    function=s["function"],
                    offset=s["offset"],
                    ip=s["ip"],
                    module=s.get("module", ""),
                    source_line=s.get("source_line", ""),
                )
                for s in self._mock_data.get("panic_stack", [])
            ]

        return self._read_stack_from_drgn()

    def _read_stack_from_drgn(self) -> list[Frame]:
        try:
            import drgn
            from drgn import ProgramFlags

            prog = drgn.Program()
            prog.set_core_dump(str(self.vmcore_path))
            prog.load_debug_info([str(self.vmlinux_path)])

            crash = prog.crashed_thread()
            frames: list[Frame] = []
            for frame in crash.stack_trace():
                frames.append(
                    Frame(
                        function=frame.name or f"<{frame.symbol_name}>",
                        offset=frame.offset,
                        ip=frame.pc,
                    )
                )
            return frames
        except Exception as exc:
            raise RuntimeError(
                f"Failed to read vmcore with drgn: {exc}"
            ) from exc

    def dereference_chain(
        self, start_addr: int, struct_type: str, depth: int = 5
    ) -> dict:
        if self._mock_data is not None:
            chains = self._mock_data.get("deref_chains", {})
            hex_key = hex(start_addr)
            return chains.get(hex_key, chains.get(str(start_addr), {}))

        return self._deref_chain_drgn(start_addr, struct_type, depth)

    def _deref_chain_drgn(
        self, start_addr: int, struct_type: str, depth: int
    ) -> dict:
        try:
            import drgn

            prog = drgn.Program()
            prog.set_core_dump(str(self.vmcore_path))
            prog.load_debug_info([str(self.vmlinux_path)])

            obj = prog.object(address=start_addr, type_name=struct_type)
            chain: dict = {"address": hex(start_addr), "type": struct_type}
            current = chain
            node = obj

            for _ in range(depth):
                members = []
                try:
                    for member in node.type_.members:
                        members.append(member.name)
                except Exception:
                    break

                if not members:
                    break

                child: dict = {}
                for name in members[:5]:
                    try:
                        val = getattr(node, name)
                        child[name] = {
                            "address": hex(val.address_),
                            "value": str(val),
                        }
                    except Exception:
                        continue

                current["members"] = child
                current = child
                break

            return chain
        except Exception as exc:
            return {"error": str(exc)}

    def read_kernel_log(self) -> str:
        if self._mock_data is not None:
            return self._mock_data.get("dmesg", "")

        try:
            import drgn

            prog = drgn.Program()
            prog.set_core_dump(str(self.vmcore_path))
            prog.load_debug_info([str(self.vmlinux_path)])

            log_buf = prog["log_buf"]
            log_buf_len = int(prog["log_buf_len"])
            data = log_buf.read(log_buf_len)
            text = data.decode("utf-8", errors="replace")
            lines = text.splitlines()
            return "\n".join(lines[-200:])
        except Exception as exc:
            return f"<failed to read kernel log: {exc}>"
