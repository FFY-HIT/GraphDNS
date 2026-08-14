# 实验 04：修复质量与增量验证等价性

本实验回答四个问题：

1. GraphDNS 生成的修复候选经完整重建后能否修复原根因组；
2. 根因分组能够减少多少重复候选验证；
3. 对同一动作序列，增量验证与完整重建得到的漏洞报告集合是否一致；
4. 增量图更新与局部遍历相比完整构图与全量遍历节省多少时间。

## 区域筛选

默认从 Census 中确定性随机抽取 `20,000` 个完整区域作为筛选池，并按抽样顺序选择前 `100` 个满足以下条件的区域：

- 区域目录及 `metadata.json` 完整；
- zone 文件数不超过 `200`；
- 预处理后的资源记录数不超过 `5,000`；
- 至少包含 1 个 `LD/DI/MG/CZD/RL/RB/ML/STALE` 报告；
- 至少形成 1 个根因组并生成 1 个可执行 dry-run 的候选；
- 完整生成的候选数不超过 `100`。

三个规模上限分别由 `--max-zone-files`、`--max-records` 和
`--max-generated-candidates` 调整。实验不会截断候选集合；候选过多的区域会整体排除，避免候选准确率受到抽样偏差影响。

`screening_results.csv` 保存每个抽样区域的筛选状态及排除原因。该实验评估的是规模受控、含可修复漏洞区域上的修复质量，不用于估计 Census 中漏洞的总体流行率。

## 指标

### 根因合并率

对区域 \(i\)：

```text
merge_rate_i = 1 - root_cause_groups_i / repairable_reports_i
```

总体结果同时报告 micro 合并率和各区域合并率的 macro 平均值。

### 候选准确率

每个候选均应用到配置副本并执行完整重建。仅当以下条件同时成立时，候选才记为准确：

1. 候选对应的原根因组消失；
2. 不新增 `LD/MG/CZD/RL/RB/ML` 严重漏洞。

`<TODO_IP>` 与 `<TODO_IPV6>` 使用 TEST-NET 地址进行结构性 dry-run；不含占位符的候选另行统计原生准确率。

### 增量/全量等价性

对每个已执行候选比较：

```text
IncrementalVerify(G, actions).all_reports_after
FullValidate(FullRebuild(R after actions))
```

报告身份由以下字段组成，见证路径不参与身份判定：

```text
kind, zoneCut, nameserver, start, query, target,
server, zone, reason
```

### 时间

时间比较只包含图操作与 DFS，不包含漏洞检测、报告刷新、进程启动、文件写入和输出序列化：

- `incremental_graph_update_seconds`：应用动作、更新基础边/语义边并局部重算 `r`；
- `incremental_local_traversal_seconds`：从受影响前向记录执行局部 DFS；
- `incremental_graph_traversal_seconds`：上述两项之和；
- `full_graph_build_seconds`：构建基础图、语义边、不变量并全图计算 `r`；
- `full_traversal_seconds`：完整图上的纯 DFS（对应 `traverse_core`）；
- `full_graph_traversal_seconds`：上述两项之和。

`semantic_graph` 仍保留原有 `traverse_dfs` 时间，并额外输出
`traverse_core = traverse_dfs - detect_inline`。实验使用 `traverse_core`，从而排除遍历过程中漏洞观察回调的耗时。漏洞检测和报告刷新仍会实际执行，用于判断候选准确性及增量/全量等价性，但其耗时不计入性能对比。

## 完整运行

Ubuntu/WSL：

```bash
cd /path/to/graphdns

python3 experiments/experiment_04_incremental_repair_equivalence/run_experiment.py \
  --config experiments/experiment_04_incremental_repair_equivalence/config.example.json \
  --regions 100 \
  --screening-pool 20000 \
  --min-repairable-reports 1 \
  --max-zone-files 200 \
  --max-records 5000 \
  --max-generated-candidates 100 \
  --workers 8 \
  --candidate-workers 1 \
  --build
```

若筛选池中不足 100 个区域满足条件，优先增大 `--screening-pool`：

```bash
python3 experiments/experiment_04_incremental_repair_equivalence/run_experiment.py \
  --config experiments/experiment_04_incremental_repair_equivalence/config.example.json \
  --regions 100 \
  --screening-pool 50000 \
  --max-zone-files 200 \
  --max-records 5000 \
  --max-generated-candidates 100 \
  --workers 8
```

`--workers` 控制并行区域数，`--candidate-workers` 控制单个区域内部的候选并行数。并发 GraphDNS 进程数约为两者乘积，常规运行建议使用 `8 x 1`。

## 冒烟测试

```bash
python3 experiments/experiment_04_incremental_repair_equivalence/run_experiment.py \
  --config experiments/experiment_04_incremental_repair_equivalence/config.example.json \
  --regions 5 \
  --screening-pool 500 \
  --max-zone-files 200 \
  --max-records 5000 \
  --max-generated-candidates 100 \
  --workers 2 \
  --smoke \
  --build
```

## 中断续跑

```bash
python3 experiments/experiment_04_incremental_repair_equivalence/run_experiment.py \
  --config experiments/experiment_04_incremental_repair_equivalence/config.example.json \
  --run-dir /path/to/graphdns/experiments/runs/exp04_<timestamp> \
  --resume \
  --workers 8
```

筛选条件、二进制或源代码协议发生变化时，应创建新的运行目录，避免混合不同实验口径。

## 输出

```text
exp04_<timestamp>/
  manifest.json
  screening_results.csv
  selected_regions.csv
  inputs/
  baselines/
  checkpoints/
  candidate_checkpoints/
  region_results.csv
  candidate_results.csv
  root_cause_groups.csv
  equivalence_mismatches.jsonl
  summary.json
  report.md
```

- `region_results.csv`：各区域的规模、合并率、候选准确率、等价率和时间；
- `candidate_results.csv`：每个候选的动作、准确性、报告差异和时间；
- `root_cause_groups.csv`：各根因组及其合并报告数；
- `equivalence_mismatches.jsonl`：仅保存增量与全量结果不一致的案例；
- `summary.json`：总体 micro/macro 指标及按漏洞类型统计；
- `report.md`：本次运行的可读汇总。

生成候选失败原因、计时分位数和长尾区域诊断：

```bash
python3 experiments/experiment_04_incremental_repair_equivalence/analyze_run.py \
  experiments/runs/exp04_<timestamp>
```

结果写入该运行目录下的 `detailed_analysis.json`。

## 绘制修复实验图

先运行上述分析命令，再绘制按漏洞类型的候选有效性、根因分组与风险等级图：

```bash
python3 experiments/experiment_04_incremental_repair_equivalence/plot_repair_results.py \
  --run-dir experiments/runs/exp04_<timestamp> \
  --output-dir experiments/runs/exp04_<timestamp>/figures
```

脚本输出 SVG、PDF、600-dpi PNG、600-dpi TIFF、源数据 CSV 和图注说明。
风险等级图仅作为补充材料：风险表示潜在运维影响，不表示候选通过验证的概率。

## 单元测试

```bash
python3 -m unittest discover \
  -s experiments/experiment_04_incremental_repair_equivalence/tests \
  -v
```
