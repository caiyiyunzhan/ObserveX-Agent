# kcrash-agent

**内核 Crash 自动归因与热补丁生成 Agent**

面向大规模服务器集群（5000+ 物理机）的内核崩溃智能分析系统。在 crash 发生后 10 分钟内自动给出根因诊断，并对可卸载模块生成 BPF/kpatch 热修复代码。

## 核心痛点

大型数据中心每天都有内核 panic、kernel oops、内存 corruption 导致的服务器无响应。传统方式依赖资深 SRE 手动拷贝 vmcore、使用 crash 工具逐步分析，单次诊断耗时半天到一天。很多 crash 在特定硬件批次或压力条件下偶发，复现极难，团队疲于奔命。

## 解决方案

kcrash-agent 采用 **多 Agent 协作辩论 + 长链推理** 架构：

```
vmcore dump ──> 数据采集 ──> 长链推理（2阶段） ──> 多Agent辩论 ──> 根因报告 + 热补丁
                    │              │                   │
              drgn解析        LLM语义分析        Symbol/Change/
              变更关联        历史模式匹配        Hardware三视角
              硬件错误                         交叉验证辩论
```

**10 分钟内交付**：结构化根因报告（置信度 + 调用链 + 代码行）+ eBPF/kpatch 热补丁代码 + 完整辩论记录

## 架构总览

```
kcrash-agent/
├── kcrash/
│   ├── collector/              # 数据采集层
│   │   ├── vmcore_reader.py    # drgn 封装：panic栈/变量/解引用链/dmesg
│   │   ├── change_fetcher.py   # CMDB变更查询 + 历史crash指纹匹配
│   │   └── hw_errors.py        # mcelog/smartctl/EDAC 硬件错误采集
│   │
│   ├── reasoning/              # 长链推理层
│   │   ├── chain_panic.py      # 阶段一：指针回溯 + 结构化证据生成
│   │   ├── chain_history.py    # 阶段二：变更关联 + 历史模式匹配
│   │   └── prompts.py          # 所有 system/user prompt 模板
│   │
│   ├── agents/                 # 多 Agent 辩论层
│   │   ├── base_agent.py       # 抽象基类（argument + rebut 接口）
│   │   ├── symbol_agent.py     # 符号分析视角：栈帧/寄存器/解引用
│   │   ├── change_agent.py     # 变更分析视角：回归/版本/配置变更
│   │   └── hardware_agent.py   # 硬件分析视角：MCE/ECC/SMART
│   │
│   ├── debate/                 # 辩论引擎
│   │   ├── moderator.py        # 多轮辩论调度 + 置信度裁决 + 共识检测
│   │   └── memory.py           # 完整辩论记录存档（审计追溯）
│   │
│   ├── patch/                  # 热补丁生成层
│   │   ├── generator.py        # eBPF kprobe/kretprobe 代码生成（5种模板）
│   │   ├── kpatch.py           # kpatch/livepatch 内核模块生成
│   │   └── validator.py        # clang BPF 编译验证 + 语法检查
│   │
│   ├── core/                   # 核心基础设施
│   │   ├── pipeline.py         # 分析流水线编排（7阶段串行/并行）
│   │   ├── fingerprint.py      # Crash 指纹生成 + 相似度匹配（Jaccard）
│   │   ├── severity.py         # 严重度评估（LOW/MEDIUM/HIGH/CRITICAL）
│   │   ├── cache.py            # 分析结果缓存（TTL + LRU淘汰）
│   │   ├── ingestion.py        # Crash 事件接入（单文件/批量/目录监听）
│   │   └── report.py           # 结构化报告生成（JSON/文本摘要）
│   │
│   ├── llm/                    # LLM 客户端层
│   │   └── client.py           # OpenAI 封装（重试/限流/Token统计/超时）
│   │
│   ├── api/                    # REST API 层
│   │   ├── server.py           # FastAPI 服务（单次/批量/查询/统计）
│   │   └── __main__.py         # uvicorn 启动入口
│   │
│   ├── utils/                  # 工具层
│   │   ├── config.py           # YAML 配置 + 环境变量注入
│   │   ├── logging.py          # 结构化 JSON 日志
│   │   └── token_counter.py    # 全局 Token 用量统计
│   │
│   └── main.py                 # CLI 入口（analyze/ingest/stats/clear-cache）
│
├── scripts/
│   └── mock_vmcore_info.py     # 模拟数据生成器（无真实vmcore也能跑）
│
├── tests/
│   ├── test_integration.py     # 68 个集成测试
│   └── test_api.py             # 5 个 API 测试
│
└── docs/
    └── architecture.md         # 详细架构文档
```

## 快速开始

```bash
# 1. 安装
pip install -e ".[all]"

# 2. 生成模拟数据
python scripts/mock_vmcore_info.py

# 3. 设置 API Key
export OPENAI_API_KEY=sk-...

# 4. CLI 分析
kcrash analyze --vmcore mock_vmcore.json --vmlinux dummy --enable-patch

# 5. 启动 API 服务
kcrash-api
# 或
python -m kcrash.api
```

## CLI 命令

```bash
# 单次分析
kcrash analyze \
  --vmcore /path/to/vmcore \
  --vmlinux /usr/lib/debug/vmlinux \
  --enable-patch \
  --patch-type ebpf \
  --hostname worker-01 \
  --hours 72 \
  --debate-rounds 2 \
  --min-confidence 0.6 \
  --output result.json \
  --verbose

# 目录监听模式
kcrash ingest \
  --watch-dir /var/crash \
  --enable-patch \
  --output-dir ./results

# 缓存统计
kcrash stats

# 清理缓存
kcrash clear-cache
```

## API 接口

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/health` | 健康检查 |
| POST | `/analyze` | 单次分析 |
| POST | `/analyze/batch` | 批量分析 |
| GET | `/crashes/{hash}` | 查询缓存结果 |
| GET | `/stats` | 缓存和系统统计 |
| DELETE | `/cache` | 清理缓存 |

## 配置

`config.yaml`：

```yaml
llm:
  provider: "openai"
  model: "gpt-4-turbo"
  api_key: ${OPENAI_API_KEY}
  max_tokens_per_call: 16384

debate:
  rounds: 2
  min_consensus_ratio: 0.67

patch:
  enable_generation: true
  kernel_source_dir: "/usr/src/kernels/$(uname -r)"
```

## 输出示例

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
  "patch": {
    "type": "ebpf",
    "code": "#include <uapi/linux/ptrace.h>...",
    "valid": true
  },
  "token_usage": {
    "total_prompt_tokens": 8500,
    "total_completion_tokens": 3200,
    "total_tokens": 11700
  },
  "total_duration_ms": 45000
}
```

## 测试

```bash
python -m pytest tests/ -v
# 73 passed
```
