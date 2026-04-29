# ObserveX Agent / kcrash-agent

**Multi-Agent Intelligent Observability & Kernel Crash Analysis Platform**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-188%20passing-brightgreen.svg)](tests/)

A dual-subsystem platform combining **kernel crash analysis** (`kcrash/`) with **full-stack observability intelligence** (`observex/`). Built for large-scale server clusters (50,000+ machines), it delivers automated root-cause diagnosis with multi-agent debate, temporal causal graphs, and auto-remediation through eBPF/kpatch hot-fix generation.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Architecture Overview](#architecture-overview)
- [Subsystem: kcrash (Kernel Crash Analysis)](#subsystem-kcrash-kernel-crash-analysis)
- [Subsystem: ObserveX (Full-Stack Observability)](#subsystem-observex-full-stack-observability)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [REST API](#rest-api)
- [Configuration](#configuration)
- [Output Schema](#output-schema)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Contributing](#contributing)

---

## Problem Statement

Large-scale data centers experience kernel panics, oopses, and memory corruption events daily, causing servers to become unresponsive. Traditional diagnosis relies on senior SREs manually copying vmcore dumps, running `crash` tool analysis step-by-step — a single diagnosis can take half a day to a full day. Many crashes are sporadic under specific hardware batches or stress conditions, making reproduction extremely difficult and exhausting the operations team.

Additionally, modern observability stacks generate millions of events across logs, metrics, traces, and infrastructure telemetry. Correlating these signals to identify root causes requires cross-domain expertise that no single engineer can maintain across all areas.

**ObserveX Agent** addresses both challenges through multi-agent collaboration with long-chain reasoning:

```
Multi-source streams (kmsg, journald, container, eBPF, SNMP)
        │
        ▼
Event Clustering + Cross-Source Correlation
        │
        ▼
Temporal Causal Graph Construction
        │
        ▼
4-Agent Structured Debate (Kernel / Application / Infrastructure / Change)
        │
        ▼
Root Cause Verdict + Auto-Remediation Plan (eBPF/kpatch hot-fix)
```

**Delivery target**: Under 10 minutes for a complete root-cause report with confidence score, causal chain, code-level evidence, and executable hot-fix code.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ObserveX Agent                               │
├────────────────────────────────┬────────────────────────────────────┤
│     kcrash/ Subsystem          │      observex/ Subsystem           │
│  (Kernel Crash Analysis)       │  (Full-Stack Observability)        │
│                                │                                    │
│  vmcore ─► Collector           │  kmsg/journald/container/eBPF/SNMP │
│     │      (drgn parser)       │         │                          │
│     ▼                          │         ▼                          │
│  Reasoning (2-stage chain)     │  EventStreamProcessor              │
│     │                          │         │                          │
│     ▼                          │         ▼                          │
│  3-Agent Debate                │  EventClusterer +                  │
│  (Symbol/Change/Hardware)      │  CrossSourceCorrelator             │
│     │                          │         │                          │
│     ▼                          │         ▼                          │
│  eBPF/kpatch Generator         │  CausalGraphBuilder                │
│                                │         │                          │
│                                │         ▼                          │
│                                │  4-Agent Debate Engine             │
│                                │  (Kernel/App/Infra/Change)         │
│                                │         │                          │
│                                │         ▼                          │
│                                │  RemediationEngine                 │
│                                │  (sandbox-verified auto-fix)       │
│                                │         │                          │
│                                │         ▼                          │
│                                │  KnowledgeBase (pattern learning)  │
└────────────────────────────────┴────────────────────────────────────┘
```

### Design Principles

- **Multi-Agent Debate**: Specialized agents analyze from different expert perspectives (symbol-level, change history, hardware telemetry, application behavior). Structured debate with rebuttals ensures cross-validation before verdicts.
- **Temporal Causal Graphs**: Events are linked into directed causal graphs with topological ordering, enabling precise root-cause chain tracing rather than simple correlation.
- **Sandbox-Verified Remediation**: All generated eBPF/kpatch hot-fixes are compiled and validated in a sandbox environment before deployment.
- **Knowledge Base Learning**: Every resolved incident feeds back into the pattern knowledge base, improving future diagnosis through Jaccard similarity matching.

---

## Subsystem: kcrash (Kernel Crash Analysis)

The `kcrash/` subsystem focuses on automated vmcore crash analysis using drgn-based parsing, 2-stage long-chain reasoning, and a 3-agent debate system.

### Data Collection Layer (`kcrash/collector/`)

| Module | Description |
|--------|-------------|
| `vmcore_reader.py` | drgn wrapper: extracts panic stacks, variables, dereference chains, dmesg logs |
| `change_fetcher.py` | CMDB change queries + historical crash fingerprint matching |
| `hw_errors.py` | mcelog / smartctl / EDAC hardware error collection |

### Reasoning Layer (`kcrash/reasoning/`)

Two-stage long-chain reasoning pipeline:

1. **Stage 1 — Pointer Backtrace** (`chain_panic.py`): Walks the panic stack frame-by-frame, dereferences kernel pointers, extracts structured evidence (registers, memory state, code paths).
2. **Stage 2 — Context Enrichment** (`chain_history.py`): Correlates with recent CMDB changes, matches historical crash patterns, identifies regressions.

### Multi-Agent Debate (`kcrash/agents/`)

Three specialized agents debate the root cause from different perspectives:

| Agent | Perspective | Key Analysis |
|-------|-------------|-------------|
| `SymbolAgent` | Symbol/Code | Stack frames, register states, pointer dereferences, code-level evidence |
| `ChangeAgent` | Change History | Recent deployments, config changes, driver updates, version regressions |
| `HardwareAgent` | Hardware | MCE errors, ECC corrections, SMART data, thermal events |

**Debate Flow**: Each agent presents an initial argument with confidence score → Rebuttal phase where agents challenge each other's conclusions → Moderator aggregates verdicts with consensus detection.

### Hot-Patch Generation (`kcrash/patch/`)

| Module | Description |
|--------|-------------|
| `generator.py` | eBPF kprobe/kretprobe code generation (5 templates: null_deref, buffer_overflow, race_condition, use_after_free, memory_leak) |
| `kpatch.py` | kpatch/livepatch kernel module generation |
| `validator.py` | clang BPF compilation verification + syntax validation |

### Core Infrastructure (`kcrash/core/`)

| Module | Description |
|--------|-------------|
| `pipeline.py` | 7-stage analysis pipeline orchestration (serial/parallel) |
| `fingerprint.py` | SHA256 crash fingerprint generation + Jaccard similarity matching |
| `severity.py` | Severity scoring (LOW/MEDIUM/HIGH/CRITICAL) with SLA impact assessment |
| `cache.py` | Analysis result cache with TTL + LRU eviction |
| `dedup.py` | Crash deduplication with rate limiting + cluster-wide alerting |
| `metrics.py` | Prometheus-style metrics (Counter, Gauge, Histogram, Summary) |
| `database.py` | SQLite persistence with WAL mode, crash history, trend analysis |
| `notifications.py` | Multi-channel notifications (webhook / log / console) |
| `batch.py` | ThreadPoolExecutor-based batch processing |

---

## Subsystem: ObserveX (Full-Stack Observability)

The `observex/` subsystem provides real-time multi-source event ingestion, causal graph construction, 4-agent debate, auto-remediation, and knowledge base learning.

### Data Models (`observex/models/`)

| Model | Description |
|-------|-------------|
| `RawEvent` | Unified event model with source type, severity, metadata, SHA256 fingerprint |
| `ClusteredEvent` | Aggregated events with template, host set, occurrence count |
| `ChangeEvent` | CMDB/deployment change events for regression correlation |
| `CausalNode` | Graph node (EVENT / CHANGE / METRIC_ANOMALY / INFRA_STATE / ROOT_CAUSE / SYMPTOM) |
| `CausalEdge` | Graph edge (CAUSES / TRIGGERS / PRECEDES / CORRELATES / MITIGATED_BY) |
| `CausalGraph` | Full DAG with topological ordering and causal chain tracing |
| `DebateSession` | Structured debate transcript with agent arguments and evidence citations |
| `RemediationPlan` | Iterative remediation plan with sandbox verification |

### Stream Ingestion (`observex/stream/ingestion.py`)

Multi-source parsers with a threaded batch processor:

```python
from observex.stream.ingestion import EventStreamProcessor

processor = EventStreamProcessor(batch_size=100, flush_interval=5.0)
events = processor.process_batch(raw_lines, source="kmsg")
```

Supported sources:
- **kmsg**: Kernel ring buffer messages
- **journald**: JSON-formatted systemd journal entries
- **container**: Docker/containerd log streams
- **eBPF**: Real-time eBPF event payloads
- **structured**: Generic structured log formats (JSON, key-value)

### Event Clustering & Correlation (`observex/processing/`)

**EventClusterer**: Groups events by template similarity.
- Regex-based log template normalization
- SHA256 template fingerprinting
- Time-window based cluster merging

**CrossSourceCorrelator**: Detects correlations across different event sources.
- Time-window co-occurrence analysis (default 5000ms window)
- Host-based linking
- Source-type affinity scoring

### Causal Graph Builder (`observex/processing/causal_builder.py`)

Constructs temporal causal graphs from clustered events and change records:

- **Temporal inference**: Events close in time on the same host are linked with confidence-scaled edges
- **Change impact**: Change events linked to subsequent anomalous events
- **Topological ordering**: Enables root-cause-first traversal of the graph

### 4-Agent Debate Engine (`observex/debate/engine.py`)

Four specialized agents debate the root cause:

| Agent | Domain | Analysis Focus |
|-------|--------|---------------|
| `KernelAgent` | Kernel | Panic patterns, lockups, OOM, scheduling anomalies, memory corruption |
| `ApplicationAgent` | Application | Timeouts, GC pauses, connection pool exhaustion, resource leaks |
| `InfrastructureAgent` | Infrastructure | Network failures, disk errors, power/thermal events, hardware faults |
| `ChangeAgent` | Change Management | Deployments, config changes, version regressions, CMDB correlations |

**Debate Phases**:
1. **Initial Arguments**: Each agent analyzes the causal graph and presents a hypothesis with evidence citations
2. **Rebuttals**: Agents challenge opposing conclusions with counter-evidence
3. **Verdict**: Moderator aggregates confidence scores and detects consensus (threshold: configurable)

### Auto-Remediation (`observex/remediation/engine.py`)

Generates executable remediation plans with sandbox verification:

- **eBPF Guard Patches**: Runtime guards injected via eBPF probes
- **sysctl Tuning**: Kernel parameter adjustments
- **Service Restarts**: Automated service recovery commands
- **Rollback Plans**: Deployment rollback procedures

All eBPF code is compiled and verified via `clang` in a sandbox before delivery.

### Knowledge Base (`observex/knowledge/base.py`)

Persistent pattern learning system:

- **FailurePattern**: Signature-based patterns with Jaccard similarity matching
- **KnowledgeEntry**: Searchable incident resolution records
- **Pattern Evolution**: Resolved incidents auto-generate patterns that improve future matching
- **Storage**: JSON-based persistence in `.observex_kb/` directory

---

## Installation

### Prerequisites

- Python 3.11+
- clang (for eBPF hot-fix validation)
- drgn (for vmcore analysis, optional)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/caiyiyunzhan/ObserveX-Agent.git
cd ObserveX-Agent

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install with all dependencies
pip install -e ".[all]"

# Or install specific extras
pip install -e ".[api]"      # FastAPI + uvicorn
pip install -e ".[dev]"      # Testing tools
pip install -e ".[ebpf]"     # BCC for eBPF
```

### Dependencies

| Category | Packages |
|----------|----------|
| Core | `openai`, `pydantic`, `pandas`, `click`, `pyyaml`, `rich` |
| API | `fastapi`, `uvicorn` (optional) |
| eBPF | `bcc` (optional) |
| Testing | `pytest`, `anyio`, `httpx` (optional) |

---

## Quick Start

### 1. Generate Mock Data

```bash
python scripts/mock_vmcore_info.py
```

This creates `mock_vmcore.json` with simulated crash data for testing without a real vmcore dump.

### 2. Configure API Key

```bash
export OPENAI_API_KEY=sk-...
```

### 3. Run CLI Analysis

```bash
# Analyze a vmcore dump
kcrash analyze \
  --vmcore mock_vmcore.json \
  --vmlinux dummy \
  --enable-patch \
  --patch-type ebpf \
  --hostname worker-01 \
  --hours 72 \
  --debate-rounds 2 \
  --min-confidence 0.6 \
  --output result.json \
  --verbose
```

### 4. Start the REST API Server

```bash
kcrash-api
# Or
python -m kcrash.api
```

The API will be available at `http://localhost:8000`.

### 5. Run ObserveX Pipeline

```python
from observex.pipeline import ObserveXPipeline
from observex.models.events import RawEvent, EventSource, EventSeverity

pipeline = ObserveXPipeline(
    debate_rounds=2,
    min_confidence=0.6,
    enable_remediation=True,
)

events = [
    RawEvent(
        source=EventSource.KERNEL,
        severity=EventSeverity.CRITICAL,
        message="BUG: unable to handle kernel NULL pointer dereference at 0000000000000000",
        host="worker-01",
        timestamp=1714400000.0,
    ),
]

result = pipeline.process_events(events)
print(f"Incident: {result['incident_id']}")
print(f"Verdict: {result['debate']['verdict']}")
print(f"Confidence: {result['debate']['confidence']:.2f}")
```

---

## CLI Reference

### `kcrash analyze`

Run a single crash analysis.

```bash
kcrash analyze [OPTIONS]

Options:
  --vmcore PATH           Path to vmcore dump or mock JSON file [required]
  --vmlinux PATH          Path to vmlinux debug symbols [required]
  --hostname TEXT         Hostname of the crashed machine
  --hours INTEGER         Hours of change history to consider (default: 72)
  --debate-rounds INTEGER Number of debate rounds (default: 2)
  --min-confidence FLOAT  Minimum confidence threshold (default: 0.6)
  --enable-patch          Enable hot-fix generation
  --patch-type TEXT        Patch type: ebpf, kpatch, both (default: ebpf)
  --output PATH           Output file path (JSON format)
  --verbose               Enable verbose output
```

### `kcrash ingest`

Watch a directory for new crash dumps and process them automatically.

```bash
kcrash ingest [OPTIONS]

Options:
  --watch-dir PATH    Directory to monitor for new crash files [required]
  --enable-patch      Enable hot-fix generation
  --output-dir PATH   Output directory for results
```

### `kcrash stats`

Display cache statistics and system metrics.

### `kcrash clear-cache`

Clear the analysis result cache.

---

## REST API

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check, returns service status |
| `POST` | `/analyze` | Submit a single crash analysis request |
| `POST` | `/analyze/batch` | Submit multiple crash analysis requests |
| `GET` | `/crashes/{hash}` | Retrieve cached analysis result by fingerprint hash |
| `GET` | `/stats` | Cache and system statistics |
| `DELETE` | `/cache` | Clear all cached results |

### Authentication

API requests require an `Authorization` header with a valid API key:

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "vmcore_path": "/var/crash/vmcore",
    "vmlinux_path": "/usr/lib/debug/vmlinux",
    "hostname": "worker-01",
    "enable_patch": true
  }'
```

Rate limiting is enforced via token bucket algorithm.

---

## Configuration

Configuration is loaded from `config.yaml` with environment variable injection support:

```yaml
llm:
  provider: "openai"
  model: "gpt-4-turbo"
  api_key: ${OPENAI_API_KEY}
  max_tokens_per_call: 16384
  max_retries: 3
  timeout: 120

debate:
  rounds: 2
  min_consensus_ratio: 0.67
  min_confidence: 0.6

patch:
  enable_generation: true
  kernel_source_dir: "/usr/src/kernels/$(uname -r)"
  validation:
    enable_sandbox: true
    compiler: "clang"

pipeline:
  cluster_window: 60
  correlation_window_ms: 5000

knowledge_base:
  path: ".observex_kb"
  match_threshold: 0.5

database:
  path: "crashes.db"
  wal_mode: true

notifications:
  channels:
    - type: webhook
      url: ${WEBHOOK_URL}
    - type: console
    - type: log
      level: INFO
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for LLM calls | (required) |
| `KCRASH_LOG_LEVEL` | Logging level | `INFO` |
| `KCRASH_CACHE_DIR` | Cache directory path | `.kcrash_cache` |
| `KCRASH_DB_PATH` | SQLite database path | `crashes.db` |
| `OBSERVEX_KB_DIR` | Knowledge base directory | `.observex_kb` |

---

## Output Schema

### Crash Analysis Result

```json
{
  "status": "completed",
  "fingerprint": {
    "hash": "a1b2c3d4e5f6",
    "top_function": "mlx5_poll_cq",
    "error_class": "null_deref",
    "module": "mlx5_core"
  },
  "severity": {
    "level": "HIGH",
    "score": 75.0,
    "sla_impact": "Performance degradation or partial outage",
    "recommended_action": "Notify SRE team, investigate within 30 minutes"
  },
  "root_cause": "NULL pointer dereference in mlx5_poll_cq after driver update to 5.14-2",
  "confidence": 0.82,
  "verdict_agent": "SymbolAgent",
  "is_consensus": true,
  "debate": {
    "arguments": 6,
    "rounds": 2,
    "agents": ["SymbolAgent", "ChangeAgent", "HardwareAgent"]
  },
  "patch": {
    "type": "ebpf",
    "code": "#include <uapi/linux/ptrace.h>...",
    "valid": true,
    "template": "null_deref_guard"
  },
  "causal_chain": [
    "driver_update: mlx5_core 5.12 -> 5.14",
    "null_deref: mlx5_poll_cq+0x42",
    "panic: Fatal exception"
  ],
  "token_usage": {
    "total_prompt_tokens": 8500,
    "total_completion_tokens": 3200,
    "total_tokens": 11700
  },
  "total_duration_ms": 45000
}
```

### ObserveX Pipeline Result

```json
{
  "incident_id": "inc-a1b2c3d4",
  "status": "completed",
  "event_count": 150,
  "active_clusters": 5,
  "correlations": 3,
  "matched_patterns": 1,
  "debate": {
    "verdict": "Kernel memory corruption due to slab allocator bug",
    "confidence": 0.85,
    "consensus": true,
    "tokens": 12500,
    "argument_count": 8
  },
  "remediation": {
    "plan_id": "plan-x1y2z3",
    "steps": [
      {
        "type": "ebpf_patch",
        "description": "Deploy null-deref guard on kmalloc",
        "code": "#include <uapi/linux/ptrace.h>...",
        "verified": true
      }
    ]
  },
  "duration_ms": 8200
}
```

---

## Testing

The project includes **188 tests** across 4 test modules:

| Module | Tests | Coverage |
|--------|-------|----------|
| `tests/test_integration.py` | 68 | kcrash subsystem (collector, reasoning, agents, debate, patch, core) |
| `tests/test_observex.py` | 49 | observex subsystem (pipeline, clustering, causal, debate, remediation, knowledge) |
| `tests/test_enterprise.py` | 66 | Enterprise modules (metrics, dedup, severity, database, notifications, batch, auth) |
| `tests/test_api.py` | 5 | REST API endpoints |

### Run Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific module
python -m pytest tests/test_integration.py -v

# Run with coverage
python -m pytest tests/ --cov=kcrash --cov=observex --cov-report=html

# Run tests matching a pattern
python -m pytest tests/ -k "test_debate" -v
```

---

## Project Structure

```
kcrash-agent/
├── kcrash/                          # Kernel crash analysis subsystem
│   ├── collector/                   # Data collection (vmcore, changes, hardware)
│   │   ├── vmcore_reader.py         # drgn-based vmcore parser
│   │   ├── change_fetcher.py        # CMDB change queries
│   │   └── hw_errors.py             # Hardware error collection
│   ├── reasoning/                   # Long-chain reasoning (2-stage)
│   │   ├── chain_panic.py           # Stage 1: pointer backtrace
│   │   ├── chain_history.py         # Stage 2: change correlation
│   │   └── prompts.py               # LLM prompt templates
│   ├── agents/                      # 3-agent debate
│   │   ├── base_agent.py            # Abstract base class
│   │   ├── symbol_agent.py          # Symbol/code analysis
│   │   ├── change_agent.py          # Change history analysis
│   │   └── hardware_agent.py        # Hardware analysis
│   ├── debate/                      # Debate orchestration
│   │   ├── moderator.py             # Multi-round debate + verdict
│   │   └── memory.py                # Debate transcript archiving
│   ├── patch/                       # Hot-fix generation
│   │   ├── generator.py             # eBPF code generation (5 templates)
│   │   ├── kpatch.py                # kpatch module generation
│   │   └── validator.py             # clang compilation verification
│   ├── core/                        # Core infrastructure
│   │   ├── pipeline.py              # 7-stage analysis pipeline
│   │   ├── fingerprint.py           # SHA256 crash fingerprinting
│   │   ├── severity.py              # Severity scoring engine
│   │   ├── cache.py                 # TTL + LRU cache
│   │   ├── database.py              # SQLite with WAL mode
│   │   ├── dedup.py                 # Crash deduplication
│   │   ├── metrics.py               # Prometheus-style metrics
│   │   ├── notifications.py         # Multi-channel notifications
│   │   ├── batch.py                 # Batch processing
│   │   ├── ingestion.py             # Event ingestion
│   │   └── report.py                # Report generation
│   ├── llm/                         # LLM client
│   │   └── client.py                # OpenAI wrapper (retry, rate limit, tokens)
│   ├── api/                         # REST API
│   │   ├── server.py                # FastAPI application
│   │   └── __main__.py              # uvicorn entry point
│   ├── utils/                       # Utilities
│   │   ├── config.py                # YAML config + env injection
│   │   ├── logging.py               # Structured JSON logging
│   │   └── token_counter.py         # Token usage tracking
│   ├── exceptions.py                # Custom exceptions
│   └── main.py                      # CLI entry point
│
├── observex/                        # Full-stack observability subsystem
│   ├── models/                      # Data models
│   │   ├── events.py                # RawEvent, ClusteredEvent, ChangeEvent
│   │   ├── causal.py                # CausalNode, CausalEdge, CausalGraph
│   │   ├── debate.py                # DebateSession, DebateArgument
│   │   └── remediation.py           # RemediationPlan, RemediationStep
│   ├── stream/                      # Stream ingestion
│   │   └── ingestion.py             # Multi-source parsers + batch processor
│   ├── processing/                  # Event processing
│   │   ├── clustering.py            # Event clustering + cross-source correlation
│   │   └── causal_builder.py        # Temporal causal graph construction
│   ├── agents/                      # 4 specialized agents
│   │   ├── kernel_agent.py          # Kernel event analysis
│   │   ├── application_agent.py     # Application event analysis
│   │   ├── infra_agent.py           # Infrastructure event analysis
│   │   └── change_agent.py          # Change impact analysis
│   ├── debate/                      # 4-agent debate engine
│   │   └── engine.py                # Debate orchestration + consensus detection
│   ├── remediation/                 # Auto-remediation
│   │   └── engine.py                # Plan generation + sandbox verification
│   ├── knowledge/                   # Knowledge base
│   │   └── base.py                  # Pattern matching + incident learning
│   └── pipeline.py                  # End-to-end pipeline orchestrator
│
├── scripts/
│   └── mock_vmcore_info.py          # Mock data generator
│
├── tests/
│   ├── test_integration.py          # 68 kcrash integration tests
│   ├── test_observex.py             # 49 ObserveX tests
│   ├── test_enterprise.py           # 66 enterprise module tests
│   └── test_api.py                  # 5 API tests
│
├── pyproject.toml                   # Project metadata + dependencies
├── config.yaml                      # Configuration template
├── .gitignore                       # Git ignore rules
└── README.md                        # This file
```

---

## Key Design Patterns

### Circuit Breaker (LLM Client)

The LLM client implements a circuit breaker pattern to handle API failures gracefully:

- **CLOSED**: Normal operation, requests pass through
- **OPEN**: After consecutive failures, requests are rejected immediately
- **HALF_OPEN**: After cooldown period, a single probe request is sent

Combined with exponential backoff retry (up to 3 retries) and token bucket rate limiting.

### Crash Fingerprinting

Each crash is fingerprinted using SHA256 of its stack signature (top N functions + error class). Similar crashes are matched using Jaccard similarity on function sets, enabling deduplication and trend analysis across the cluster.

### Severity Scoring

A weighted scoring system evaluates crash severity across multiple dimensions:

| Factor | Weight | Description |
|--------|--------|-------------|
| Error class | 30 | panic > oops > bug > warning |
| Stack depth | 15 | Deeper stacks indicate more complex failures |
| Module criticality | 20 | Core kernel modules score higher |
| Hardware involvement | 15 | MCE/ECC errors indicate hardware faults |
| Reproducibility | 10 | First-occurrence crashes score higher |
| Data corruption risk | 10 | Memory corruption indicators |

Scores map to severity levels: LOW (< 30), MEDIUM (30-60), HIGH (60-80), CRITICAL (> 80).

---

## Performance Characteristics

| Metric | Target |
|--------|--------|
| Single crash analysis | < 60 seconds |
| Batch throughput | 100+ crashes/minute |
| Event ingestion | 500K-1M lines/second |
| Cluster size | 50,000+ servers |
| API latency (p99) | < 200ms (cached results) |
| Knowledge base pattern match | < 50ms |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`python -m pytest tests/ -v`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Standards

- Python 3.11+ with type hints throughout
- No Chinese comments — all code and comments in English
- Enterprise-grade error handling and logging
- 100% test coverage for new modules
- Follow existing code patterns and conventions

---

## License

This project is licensed under the MIT License — see the LICENSE file for details.

---

## Acknowledgments

- [drgn](https://github.com/osandov/drgn) — Programmable debugger for the Linux kernel
- [OpenAI](https://openai.com/) — LLM API for intelligent analysis
- [FastAPI](https://fastapi.tiangolo.com/) — Modern web framework for the REST API
