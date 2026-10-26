# CPA 使用手册

[返回 README](../../README.zh-CN.md)

完整的公开选项说明请参考 [README.zh-CN.md](../../README.zh-CN.md) 中的
`选项总览` 一节。

## 前置条件

- 已构建出 `build/bin/cpa`
- 运行环境具备所需的 BPF/perf 能力
- 大多数 `cpa monitor` 场景需要 root 权限

## `cpa monitor`

`cpa monitor` 负责采样并写出 profile 数据目录。

基础持续剖析：

```bash
sudo mkdir -p /var/log/cpa
sudo ./build/bin/cpa monitor \
  --store_dir /var/log/cpa \
  --freq 49
```

常用参数：

- `--backend bpf|perf`：选择采样后端
- `--pid <pid>`：限制到某个进程
- `--comm <name>`：只采线程名等于 name 的线程
- `--record_interval <sec>`：控制存储和查询粒度
- `--persistent_day <days>`：仅保留最近若干天的目录
- `--record_env_name <k1,k2>`：记录指定环境变量键，供 `cpa show` 后续过滤
- `--parse_env_values <v1,v2>`：只对匹配环境值的进程做用户态栈解析
- `--bench`：在运行状态里按 stat 周期打印最终 DWARF 路径 benchmark，包括实际回溯次数、速率、平均/最小/最大耗时和固定耗时桶。`FP_BETTER` 样本不计入。首次符号/CFI 冷加载可能体现在前几个周期。

一次性采样：

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --oneshot \
  --output_prof /tmp/cpa.prof
```

off-CPU 采集：

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --offcpu 1
```

probe 触发采集：

```bash
sudo ./build/bin/cpa monitor \
  --pid 12345 \
  --probe kprobe:try_to_free_pages
```

切到 perf 后端：

```bash
sudo ./build/bin/cpa monitor \
  --backend perf \
  --store_dir /var/log/cpa
```

perf 后端采集 off-CPU（适合容器内运行）。只加 `--offcpu` 只采 off-CPU，和 BPF 后端一致；再加 `--oncpu` 则 on-CPU 和 off-CPU 一起采：

```bash
sudo ./build/bin/cpa monitor \
  --backend perf \
  --pid 12345 \
  --oncpu --offcpu \
  --store_dir /var/log/cpa
```

- 每 `--offcpu_period` 次上下文切换（默认 100）采一次 off-CPU 调用栈，用户栈复制 `--offcpu_stack_size` 字节（默认 16384）。
- 同时记录每次切出/切入，按"等待时长 × offcpu_period"给 off-CPU 栈加权。
- 计数单位改为微秒（`conf` 写入 `count_unit: us`）。同时采 on-CPU 时，on-CPU 每个样本记 `1000000 / freq` 微秒，一张火焰图就是所有线程的总墙钟时间。
- off-CPU 栈在 metadata 之后带 `<# OFFCPU SAMPLE: (R|S) #>` 标记：`R` 是被抢占，`S` 是主动让出 CPU。
- 采集范围默认限定在 perf_event cgroup（`--perf_cgroup auto`）：有 `--pid` 时取该进程所在的 cgroup，否则取 cpa 自身所在的 cgroup。也可以传 cgroup 目录。

perf 后端按硬件或软件事件采样，用来找缓存未命中、分支预测失败集中在哪些函数：

```bash
sudo ./build/bin/cpa monitor \
  --backend perf \
  --pid 12345 \
  --perf_event branch-misses \
  --store_dir /var/log/cpa
```

- `--perf_event` 支持 `perf list` 里的名字：`cycles`、`instructions`、`cache-references`、`cache-misses`、`branches`、`branch-misses`、`ref-cycles` 等硬件事件；`<L1-dcache|L1-icache|LLC|dTLB|iTLB|branch|node>-<loads|stores|prefetches>[-misses]` 形式的 cache 事件；`page-faults`、`major-faults`、`cpu-migrations` 等软件事件；以及 `r<hex>` 原始 PMU 事件。
- 默认按 `--freq` 采样，内核自动调整每个样本间隔多少次事件；`--perf_period N` 改为每 N 次事件采一个样本。事件发生越频繁，N 应该越大。
- 每个样本按它代表的事件次数加权，火焰图的宽度就是估算的事件次数。`conf` 写入 `count_unit: <事件名>`，`cpa show` 不再把计数换算成 CPU 占比。
- 只给出未命中、预测失败发生在哪里，不给出命中率。命中率可以再用 `--perf_event LLC-loads`、`branches` 采一份做分母，或者直接用 `perf stat`。
- 不能和 `--probe`、`--offcpu` 一起使用。容器里要能访问硬件 PMU，否则打开事件会失败。

计数器总量（类似 perf stat）：

```bash
sudo ./build/bin/cpa monitor --pid 12345 --backend perf --perf_stat default --store_dir /var/log/cpa
```

- 每个 CPU 开只计数、不采样的事件，范围和采样相同（`--pid` 所在的 cgroup，或 `--perf_cgroup`）。每 `record_interval` 读一次增量，写入存储目录下的 `perf_stat` 文件：首行 `# record_ms <事件>...`，之后每行 `<record_ms> <计数>...`，`record_ms` 和 `stack.bin` 用同一个时钟。
- `default` 是 `cycles,instructions,branches,branch-misses,LLC-loads,LLC-load-misses`，最多 16 个事件；不支持的事件打印提示后跳过。
- 事件多于硬件计数器时按 `time_enabled / time_running` 折算。
- `--oneshot` 时不写文件，结束时打印总量、每秒速率和派生比率。
- BPF 后端也可以用；`--pid` 是宿主机 PID 时找不到对应 cgroup，会退回整机计数。

## `cpa show`

`cpa show` 用于读取 `cpa monitor` 生成的 profile 目录。

查看可用时间范围：

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --show_range 1
```

导出 flamegraph：

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --output_prof cpa.prof
```

未显式指定时间范围时，导出会从第一个匹配当前筛选条件的 record 开始。

按落盘 record 时间线里的绝对时间范围导出：

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --starttime 00:10:00 \
  --endtime 00:15:00 \
  --output_prof cpa.prof
```

常用过滤参数：

- `--target_pid <pid>`
- `--target_comm <name>`
- `--target_env <value>`
- `--target_cgroup_id <id>`
- `--target_cpu <set>`
- `--target_state <all|on|off>`：对 perf 后端 `--offcpu` 采集的 store 只导出 on-CPU 或 off-CPU 栈

其他常用参数：

- `--show_thread_name 1`：在 flamegraph 中展示线程名
- `--no_pid 1`：不在栈帧中显示 pid 后缀
- `--no_env 1`：不在栈帧中显示 env 标签
- `--show_raw 1`：输出原始 metadata
- `--output_num <n>`：从选中时间点向后导出 `n` 个 record，建议使用正整数
- `--split_path <dir>`：将选中时间范围拆分导出为原始文件
- `--show_perf_stat 1|2`：输出选中时间范围的 perf_stat 总量、每秒速率、IPC 和各项未命中率；2 再逐行输出每个时间间隔

打开内嵌 Rust TUI：

```bash
./build/bin/cpa show \
  --read /var/log/cpa/cpa_YYMMDD \
  --use_cui
```

TUI 支持时间窗口浏览、火焰图缩放和交互式过滤。详细说明见
[src/cpa_show/doc/cpa_show.md](../../src/cpa_show/doc/cpa_show.md)。

## 输出与存储说明

- 默认持续存储目录根是 `/var/log/cpa`
- 默认 one-shot 输出文件名是 `cpa.prof`
- `cpa show` 读取的是 `cpa monitor` 生成的目录，而不是任意 flamegraph 文本
- `--use_cache 1` 允许 `cpa show` 复用解压后的中间文件

## 典型使用流程

1. 对目标 workload 启动 `cpa monitor`
2. 等待写出一个或多个 profile 目录
3. 用 `cpa show --show_range 1` 看可用时间区间
4. 导出 flamegraph，或用 TUI 做交互分析
