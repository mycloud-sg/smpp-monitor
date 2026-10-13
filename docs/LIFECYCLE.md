# SMPP Monitor Lifecycle

本文说明系统运行期间，各个进程、PCAP、诊断和 incident 从创建到清理的完整生命周期。

## 1. 组件职责

```text
smpp_capture_manager.sh
  ├── smpp_capture_worker.sh
  │     └── dumpcap
  └── smpp_detector_worker.sh
        └── smpp_detector.py
              └── smpp_incident.sh
```

| 组件 | 职责 |
|---|---|
| `smpp_capture_manager.sh` | 启动、停止、重启和查看进程状态 |
| `smpp_capture_worker.sh` | 管理共享 dumpcap、加载 Supplier 配置、清理过期 PCAP |
| `dumpcap` | 捕获所有已配置 Supplier 的 TCP 流量并按分钟切分文件 |
| `smpp_detector_worker.sh` | 寻找已经写完且尚未处理的 PCAP |
| `smpp_detector.py` | 调用 tshark、关联 TCP/SMPP 事件、生成中文诊断 |
| `smpp_incident.sh` | 固化诊断、PCAP、配置和 TCP 连接状态 |

## 2. 启动生命周期

执行：

```bash
bash smpp_capture_manager.sh start
```

启动顺序：

```text
manager
  │
  ├── 启动 capture supervisor
  │     ├── 写入 pids/capture.pid
  │     ├── 读取 smpp_suppliers.conf
  │     ├── 生成共享 BPF 过滤条件
  │     └── 启动 dumpcap，写入 pids/capture.dumpcap.pid
  │
  └── 启动 detector worker
        └── 写入 pids/detector.pid
```

manager 使用 PID 文件防止重复启动。进程已经存在时，再次执行 `start` 只会报告当前 PID。

## 3. Supplier 配置生命周期

配置示例：

```ini
[smpp_example]
ip=192.0.2.10
port=2775
timeout=30
```

字段用途：

| 字段 | 抓包阶段 | 检测阶段 |
|---|---|---|
| section 名称 | Supplier 标识 | 诊断中的事故对象 |
| `ip` | 生成 dumpcap 过滤条件 | 将报文归属到 Supplier |
| `port` | 生成 dumpcap 过滤条件 | 将报文归属到 Supplier |
| `timeout` | 不使用 | 判断 `submit_sm_resp` 是否超时 |

capture supervisor 默认每 5 秒对配置文件计算一次校验值。配置发生变化时：

```text
检测到配置变化
    │
    ▼
停止旧 dumpcap
    │
    ▼
根据新配置生成过滤条件
    │
    ▼
启动新 dumpcap
```

切换期间允许出现短暂抓包空窗。也可以执行以下命令主动触发相同流程：

```bash
bash smpp_capture_manager.sh reload
```

如果新配置无法生成有效过滤条件，dumpcap 不会启动，capture supervisor 会保留运行并定期重试。错误写入 `capture.log`。

## 4. PCAP 生命周期

所有 Supplier 共用一个 dumpcap。过滤条件类似：

```text
(host 192.0.2.10 and port 2775)
or
(host 192.0.2.20 and port 30000)
```

默认参数：

```text
ROTATE_SECONDS=60
SNAPLEN=1024
CAPTURE_RETENTION_MINUTES=30
```

文件生命周期：

```text
dumpcap 创建当前 PCAP
        │
        │ 持续写入 60 秒
        ▼
关闭当前 PCAP，并创建下一个 PCAP
        │
        ├── detector 分析已关闭文件
        │
        └── 超过 30 分钟后由 capture supervisor 删除
```

文件位于：

```text
captures/ring/
```

文件名包含 dumpcap 启动时间、轮转序号和文件创建时间。配置重载后会产生新的文件名前缀，但保留策略只看文件修改时间，不区分启动批次。

capture supervisor 每 5 分钟检查一次过期文件。它始终跳过目录中最新的 PCAP，避免删除 dumpcap 仍在写入的文件。

## 5. 检测生命周期

detector worker 默认每 15 秒扫描一次 `captures/ring/`：

```text
扫描 PCAP
  │
  ├── 最新文件：跳过，可能仍在写入
  ├── 存在对应 .done：跳过，已经分析
  └── 其他文件：调用 smpp_detector.py
```

这不是文件系统事件触发，而是轻量轮询。每次轮询只扫描目录；同一个 PCAP 不会重复执行 tshark。

每轮扫描只获取一次按修改时间排序的文件快照，并始终跳过快照中的最后一个文件。这可以
避免 dumpcap 恰好在扫描过程中轮转时，新文件被误当作已关闭文件交给 tshark。

分析结果通过退出码返回：

| 退出码 | 含义 | worker 行为 |
|---:|---|---|
| `0` | 没有发现异常 | 创建 `.done` |
| `2` | 发现异常并生成诊断 | 创建 `.done` |
| 其他 | 分析失败 | 不创建 `.done`，下次重试 |

处理状态位于：

```text
state/processed/<pcap-file>.done
state/last-processed.txt
```

`last-processed.txt` 记录最近一次处理时间、PCAP 和结果，用于区分“没有异常”和“detector
没有工作”。

PCAP 被 capture supervisor 清理后，detector worker 会在周期清理时删除失效的 `.done`。

## 6. tshark 与 detector 生命周期

每个已关闭 PCAP 只执行一次精简 tshark：

```text
PCAP
  │
  ▼
tshark 解码 TCP/SMPP 字段
  │
  ▼
detector 按 TCP stream 和 SMPP sequence number 关联事件
  │
  ▼
应用超时、失败和网络异常规则
```

tshark 负责协议解码；detector 负责业务判断和中文描述。

由于 Supplier 经常使用非标准 SMPP 端口，detector 会根据 `smpp_suppliers.conf` 为每个
端口显式设置 tshark `decode-as`，不依赖 tshark 的自动协议识别。

当前检测范围：

- TCP 强制断开；
- TCP 正常关闭，可通过 `ALERT_ON_FIN=0` 禁用；
- TCP 重发达到阈值；
- 连接一侧暂停接收数据；
- SMPP bind 失败或解除；
- `submit_sm_resp` 超过 Supplier 的 timeout；
- `submit_sm_resp` 返回非成功状态。

当前版本只在单个 PCAP 内关联 SMPP 请求和响应。跨 PCAP 的请求响应状态暂不保留。

## 7. 诊断生命周期

发现异常后，detector 按 Supplier 汇总同一 PCAP 内的事件：

```text
TCP 事件 + SMPP 事件
        │
        ▼
判断主要问题层级
        │
        ├── TCP：同时存在网络异常时优先归为 TCP
        └── SMPP：未发现 TCP 异常时归为 SMPP
        │
        ▼
生成固定格式中文诊断卡片
```

输出位置：

```text
diagnosis.log                         所有诊断卡片
diagnosis-latest.txt                  每个 Supplier 最近一次诊断
diagnosis/<incident-id>.txt           单次中文诊断
diagnosis/<incident-id>.details.json  原始技术事件
```

同一 Supplier、问题层级和事件组合默认有 300 秒冷却时间。冷却期内的同类问题不会重复生成 incident。

## 8. Incident 生命周期

诊断产生后，`smpp_incident.sh` 创建：

```text
incidents/<incident-id>/
├── diagnosis.txt
├── details.json
├── info.txt
├── supplier.conf
├── ss.txt
└── pcap/
    └── 触发文件及之前最多 4 个 PCAP
```

随后生成同名压缩包：

```text
incidents/<incident-id>.tar.gz
```

诊断卡片中的 PCAP 路径指向 incident 内的副本，而不是会被轮转清理的源文件。

incident 默认保留 7 天。detector worker 每小时检查并清理过期目录和压缩包。

## 9. 停止生命周期

执行：

```bash
bash smpp_capture_manager.sh stop
```

停止顺序：

```text
停止 detector worker
        │
        ▼
停止 capture supervisor
        │
        ▼
capture supervisor 停止 dumpcap
        │
        ▼
删除对应 PID 文件
```

停止不会删除 PCAP、诊断和 incident。再次启动后，未生成 `.done` 的已关闭 PCAP 会继续被分析。

## 10. 异常恢复

| 异常 | 恢复行为 |
|---|---|
| dumpcap 意外退出 | capture supervisor 自动尝试重新启动 |
| Supplier 配置修改 | 停止旧 dumpcap，按新配置启动 |
| tshark 分析失败 | 不写 `.done`，后续轮询重试 |
| manager 重复启动 | 根据 PID 文件阻止重复进程 |
| PCAP 超过保留时间 | capture supervisor 自动删除 |
| incident 超过保留天数 | detector worker 自动删除 |
