from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


class EbpfValidator:
    def __init__(self, clang_path: str = "clang") -> None:
        self._clang_path = clang_path

    def validate(self, code: str) -> tuple[bool, str]:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".c", delete=False
        ) as src:
            src.write(code)
            src_path = src.name

        output_path = src_path.replace(".c", ".o")

        try:
            result = subprocess.run(
                [
                    self._clang_path,
                    "-target", "bpf",
                    "-O2",
                    "-c", src_path,
                    "-o", output_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                return True, "Compilation successful"

            return False, result.stderr or "Unknown compilation error"

        except FileNotFoundError:
            return False, (
                f"Compiler not found: {self._clang_path}. "
                "Install clang with BPF target support."
            )
        except subprocess.TimeoutExpired:
            return False, "Compilation timed out after 30s"
        finally:
            Path(src_path).unlink(missing_ok=True)
            Path(output_path).unlink(missing_ok=True)

    def validate_syntax_only(self, code: str) -> tuple[bool, str]:
        missing: list[str] = []

        if "BPF_" not in code:
            missing.append("No BPF helper usage detected")

        if "pt_regs" not in code:
            missing.append("No pt_regs struct access detected")

        brace_open = code.count("{")
        brace_close = code.count("}")
        if brace_open != brace_close:
            missing.append(
                f"Unbalanced braces: {brace_open} open vs {brace_close} close"
            )

        if missing:
            return False, "; ".join(missing)

        return True, "Basic syntax check passed"
