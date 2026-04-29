# kcrash-agent Architecture

## System Design

kcrash-agent is a multi-agent collaboration system for automated kernel crash analysis
in large-scale server clusters (5000+ nodes). It combines LLM-based long-chain reasoning
with adversarial debate to produce high-confidence root cause diagnoses within 10 minutes
of crash occurrence.

## Analysis Pipeline (7 Stages)

```
Stage 1: Collection
  ├── VMCoreReader (drgn) -> panic stack, registers, deref chains, dmesg
  └── CrashFingerprint -> SHA256 hash of stack signature

Stage 2: Cache Check
  └── Lookup fingerprint in AnalysisCache (TTL-based, LRU eviction)

Stage 3: Severity Assessment
  ├── Error class scoring (panic=40, oops=30, page_fault=20)
  ├── Critical subsystem bonus (mlx5, nvme, btrfs, xfs = +20)
  ├── Hardware error bonus (MCE critical = +15 each)
  └── Cluster-wide detection (sibling crashes = +5 each, max +25)
  -> SeverityAssessment (LOW/MEDIUM/HIGH/CRITICAL)

Stage 4: Phase 1 - Semantic Analysis
  └── LLM analyzes panic stack + registers + deref chains
      -> {panic_point, error_class, pointer_chain, confidence}

Stage 5: Phase 2 - History Correlation
  ├── ChangeFetcher -> recent kernel/driver/config changes
  ├── SiblingCrashSearch -> same crash on other hosts
  └── LLM multi-hop reasoning on change-crash correlation
      -> {root_cause_candidates ranked by probability}

Stage 6: Multi-Agent Debate
  ├── SymbolAgent: analyzes stack frames, registers, pointer chains
  ├── ChangeAgent: weighs recent changes and regression patterns
  ├── HardwareAgent: evaluates MCE/ECC/SMART error evidence
  ├── Round 1: each agent proposes initial argument
  ├── Round 2: each agent rebuts opponents' arguments
  └── Moderator: resolves verdict by highest confidence + consensus check
      -> {verdict, final_confidence, is_consensus, transcript}

Stage 7: Patch Generation (if confidence >= threshold)
  ├── EbpfGenerator: kprobe code with 5 templates (null_deref, page_fault,
  │   memory_leak, race_condition, generic_monitor)
  ├── KpatchGenerator: livepatch kernel module (.ko)
  └── Validator: clang BPF compile test + syntax check
```

## Module Details

### LLM Client (`llm/client.py`)
- Exponential backoff retry (3 attempts, 2^n delay)
- Token-per-minute rate limiting
- Per-call token usage logging
- JSON response auto-parsing with markdown fence stripping

### Crash Fingerprinting (`core/fingerprint.py`)
- SHA256 hash of (top_function, offset, error_class, stack_signature)
- Jaccard similarity for cluster detection
- Error classification: 11 patterns (BUG, Oops, NULL, page_fault, GPF, etc.)

### Severity Assessment (`core/severity.py`)
- Score-based system (0-100)
- Factors: error class, subsystem criticality, stack depth, HW errors, cluster size
- Maps to SLA impact and recommended action

### Debate Memory (`debate/memory.py`)
- Records every argument from every agent in every round
- Supports opponent lookup, round filtering
- Produces human-readable transcript for audit

### eBPF Templates (`patch/generator.py`)
5 production templates, each with kprobe + perf_output + BPF maps:
1. `null_deref`: NULL pointer detection with PID tracking
2. `page_fault`: page fault address monitoring
3. `memory_leak`: large allocation tracking (>1MB)
4. `race_condition`: lock contention detection
5. `generic_monitor`: function enter/exit latency tracking

### Kpatch Generator (`patch/kpatch.py`)
- Generates `klp_func/klp_object/klp_patch` structured modules
- Includes Makefile for cross-compilation
- Can use LLM for complex patches or template for simple ones

### API Server (`api/server.py`)
- FastAPI with lifespan management
- Endpoints: /health, /analyze, /analyze/batch, /crashes/{hash}, /stats, /cache
- Pydantic request/response models with validation

## Data Flow

```
┌─────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────────┐
│  vmcore     │────>│ Collector│────>│ Reasoning│────>│   Agents     │
│  (drgn)     │     │ Fingerprint│    │ Phase1/2 │     │ Symbol/      │
│  (mock JSON)│     │ Severity  │     │ LLM calls│     │ Change/HW    │
└─────────────┘     └──────────┘     └──────────┘     └──────┬───────┘
                                                             │
                    ┌──────────┐     ┌──────────┐     ┌──────v───────┐
                    │  Report  │<────│  Patch   │<────│   Debate     │
                    │  JSON    │     │ BPF/kpatch│    │  Moderator   │
                    │  Cache   │     │ Validator │    │  Memory      │
                    └──────────┘     └──────────┘     └──────────────┘
```
