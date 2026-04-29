"""Generate mock vmcore data for end-to-end testing without real vmcore."""

from __future__ import annotations

import json
from pathlib import Path


MOCK_DATA = {
    "panic_stack": [
        {
            "function": "mlx5_poll_cq",
            "offset": 0x124,
            "ip": 0xffffffffc0a2d124,
            "module": "mlx5_core",
            "source_line": "drivers/net/ethernet/mellanox/mlx5/core/cq.c:342",
        },
        {
            "function": "mlx5_napi_poll",
            "offset": 0x8c,
            "ip": 0xffffffffc0a2e08c,
            "module": "mlx5_core",
            "source_line": "drivers/net/ethernet/mellanox/mlx5/core/en_rx.c:1205",
        },
        {
            "function": "net_rx_action",
            "offset": 0x1a4,
            "ip": 0xffffffff81a2a1a4,
            "module": "",
            "source_line": "net/core/dev.c:6712",
        },
        {
            "function": "__do_softirq",
            "offset": 0xd8,
            "ip": 0xffffffff81c010d8,
            "module": "",
            "source_line": "kernel/softirq.c:559",
        },
        {
            "function": "do_softirq",
            "offset": 0x42,
            "ip": 0xffffffff81c01442,
            "module": "",
            "source_line": "kernel/softirq.c:456",
        },
    ],
    "deref_chains": {
        "0xffffffffc0a2d124": {
            "address": "0xffffffffc0a2d124",
            "type": "struct page",
            "members": {
                "flags": {
                    "address": "0xffffea0012345600",
                    "value": "0x100000000000680",
                },
                "_refcount": {
                    "address": "0xffffea0012345608",
                    "value": "0",
                },
                "mapping": {
                    "address": "0xffffea0012345610",
                    "value": "0x0",
                },
            },
        }
    },
    "dmesg": (
        "[   0.000000] Linux version 5.14.0-284.el9.x86_64\n"
        "[   0.000000] Command line: BOOT_IMAGE=(hd0,gpt2)/vmlinuz-5.14.0-284.el9\n"
        "[   1.234567] mlx5_core 0000:3b:00.0: firmware version: 16.35.2000\n"
        "[ 123.456789] BUG: unable to handle page fault for address: 0000000000000010\n"
        "[ 123.456790] #PF: supervisor read access in kernel mode\n"
        "[ 123.456791] #PF: error_code(0x0000) - not-present page\n"
        "[ 123.456792] PGD 0 P4D 0\n"
        "[ 123.456793] Oops: 0000 [#1] SMP PTI\n"
        "[ 123.456794] CPU: 12 PID: 0 Comm: swapper/12 Not tainted 5.14.0-284.el9.x86_64\n"
        "[ 123.456795] Hardware name: Dell Inc. PowerEdge R750/XXXX, BIOS 1.0.0 01/01/2022\n"
        "[ 123.456796] RIP: 0010:mlx5_poll_cq+0x124\n"
    ),
    "metadata": {
        "recent_changes": [
            {
                "type": "rpm",
                "name": "kernel",
                "old": "5.14.0-283.el9",
                "new": "5.14.0-284.el9",
            },
            {
                "type": "rpm",
                "name": "mlx5_core",
                "old": "5.14-1.el9",
                "new": "5.14-2.el9",
            },
            {
                "type": "config",
                "name": "sysctl/net.core.netdev_budget",
                "old": "300",
                "new": "600",
            },
        ],
        "sibling_crashes": [
            {
                "hostname": "worker-02",
                "function": "mlx5_poll_cq",
                "offset": 0x120,
                "error_type": "page_fault",
                "timestamp": "2024-01-15T03:22:10Z",
            },
            {
                "hostname": "worker-05",
                "function": "mlx5_napi_poll",
                "offset": 0x90,
                "error_type": "null_deref",
                "timestamp": "2024-02-01T11:45:33Z",
            },
        ],
        "mcelog_errors": [],
        "smartctl_errors": [],
        "edac_errors": [],
    },
}


def generate_mock_data(output_path: str = "mock_vmcore.json") -> None:
    path = Path(output_path)
    with open(path, "w") as f:
        json.dump(MOCK_DATA, f, indent=2, default=str)
    print(f"Mock vmcore data written to: {path}")
    print(f"Run with: kcrash analyze --vmcore {path} --vmlinux dummy --enable-patch")


if __name__ == "__main__":
    generate_mock_data()
