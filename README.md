# SMPP Monitor

常驻式 SMPP/TCP 故障取证工具。一个共享 `dumpcap` 按分钟轮转 PCAP，并按保留时间清理；每个完成的文件只由
`tshark` 解析一次；detector 将技术事件翻译为固定格式的中文诊断卡片。

## 依赖

- Linux
- Python 3
- Wireshark CLI：`dumpcap`、`tshark`
- `ss`、`tar`
- 运行账户具备抓包权限

脚本默认以自身所在目录作为项目目录，也可通过 `SMPP_MONITOR_HOME` 覆盖。

## 配置

```ini
[smpp_example]
ip=192.0.2.10
port=2775
timeout=30
```

修改并保存 `smpp_suppliers.conf` 后，capture supervisor 会在数秒内检测到变化，停止旧
`dumpcap`，再使用新配置启动。切换期间允许出现短暂抓包空窗。也可以手工执行：

```bash
bash smpp_capture_manager.sh reload
```

当前配置覆盖 8 个 SMPP 通道。检测器会跨分钟轮转文件跟踪 `submit_sm`，在配置的
`timeout` 到期后仍未见 `submit_sm_resp` 时生成诊断；同一 TCP 包中的多个 PDU 也会逐个跟踪。
超时事件表示本机抓包未见响应，不能单凭事件确定丢包发生在哪一侧。

## 使用

```bash
bash smpp_capture_manager.sh start
bash smpp_capture_manager.sh status
bash smpp_capture_manager.sh reload
bash smpp_capture_manager.sh restart
bash smpp_capture_manager.sh stop
```

重要输出：

```text
diagnosis.log          所有事故的中文诊断卡片
diagnosis-latest.txt   每个 Supplier 最近一次诊断
diagnosis/             单次诊断文本及机器详情 JSON
incidents/             PCAP、诊断、配置、TCP 状态、网卡计数器和压缩包
captures/ring/         共享轮转 PCAP
capture.log            抓包进程日志
detector.log           检测调度日志
```

最常用的事故查看命令：

```bash
cat diagnosis-latest.txt
tail -100 diagnosis.log
ls -lht incidents | head
```

## 可调参数

写进 `smpp_monitor.env`（参考 `smpp_monitor.env.example`，manager 每次启动都会读取），或启动前通过环境变量设置（优先）：

```text
INTERFACE=any                         抓包网卡
ROTATE_SECONDS=60                    PCAP 切分周期
SNAPLEN=0                            每个包保存的最大字节数，0 表示完整保存
CAPTURE_RETENTION_MINUTES=30         PCAP 按时间保留的分钟数
INTERVAL=15                          detector 检查新文件的周期
TCP_RETRANSMISSION_THRESHOLD=5       重发达到该次数才写入事故上下文（单独出现不会生成事故）
INCIDENT_COOLDOWN_SECONDS=300        同类事故冷却时间
INCIDENT_RETENTION_HOURS=24          incident 保留小时数
ALERT_ON_FIN=0                       是否将正常关闭连接记为事故
EXPORT_DIR=                          非空时把 incident 复制到该目录供 Web 后台下载
NETPROBE=1                           事故触发时后台采集 mtr / ss 现场证据，0 关闭
NETPROBE_MTR_COUNT=120               mtr（ICMP）探测轮数
NETPROBE_MTR_INTERVAL=1              mtr 每轮间隔秒数（默认共 2 分钟，与 ss 采样同长）
NETPROBE_SS_SECONDS=120              ss -tin 采样总时长
NETPROBE_SS_INTERVAL=2               ss -tin 采样间隔秒数
EXPORT_GROUP=www                     导出文件的属组（权限 0640）
```

## 什么情况会生成事故

只有已经影响业务的异常才生成事故：

| 事件 | 含义 |
|---|---|
| `SMPP_RESP_TIMEOUT` | submit_sm 超过 Supplier timeout 未响应 |
| `SMPP_SUBMIT_FAILED` | Supplier 明确返回提交失败 |
| `SMPP_BIND_LOST` | 已建立的 bind 被 unbind |
| `TCP_RESET` | 连接被 RST 复位（已发出 FIN 后的 RST 属于正常关闭收尾，不计） |
| `SMPP_BIND_FAILED` | bind 被拒绝；同一 Supplier、同一错误码只报第一次，之后有 bind 成功才重新计数（状态在 `state/bind-failed/`） |
| `TCP_CLOSED` | 仅在 `ALERT_ON_FIN=1` 时 |

TCP 重发、对端暂停接收（zero window）只作为事故的上下文写进 `details.json`，单独出现不生成事故；
原始包仍在 PCAP 环形缓存中，需要时可以回查。

## 诊断职责

- `dumpcap`：只负责低成本保存原始网络包。
- `smpp_capture_worker.sh`：管理 dumpcap、配置重载和过期 PCAP 清理。
- `tshark`：把 TCP/SMPP 报文解码成字段。
- `smpp_detector.py`：关联请求响应、应用阈值、判断问题层级并生成中文诊断。
- `smpp_incident.sh`：收集诊断、技术详情、连接状态和对应 PCAP。

诊断文本面向值班人员；原始字段保存在 incident 内的 `details.json`，用于后续深挖。

## 文档

- [生命周期说明](docs/LIFECYCLE.md)
- [部署与使用说明](docs/USAGE.md)

## 现场网络证据（netprobe）

`smpp_incident.sh` 生成事故包后，会以后台进程启动 `smpp_netprobe.sh`（不阻塞 detector），
结果写入 `incidents/<id>/net/`，完成后重新打包 `<id>.tar.gz`（配置了 `EXPORT_DIR` 时同时重新导出）：

```text
summary.txt          自动结论（同时写进事故包的 diagnosis.txt，Web 页可见）
mtr-icmp.txt         mtr ICMP 模式，逐跳延迟与丢包（丢包从哪一跳开始）
ss-series.txt        每 NETPROBE_SS_INTERVAL 秒一次 ss -tin（rtt / rto / cwnd / retrans / Send-Q）
nstat-start/end.txt  系统 TCP 计数器起止快照
route.txt            到供应商的路由
ip-link-stats-end.txt 结束时网卡计数器
```

分工：mtr 只回答“丢包从哪一跳开始”；TCP 层的情况看真实 SMPP 连接（ss 序列 + PCAP 里双方各自的重传）。
`smpp_netprobe_summary.py` 把三者整理成几行结论：

- 路径：终点丢包且从第 N 跳起一直延续到终点 → 问题在第 N-1 到第 N 跳之间；只有中间跳丢包 → 路由器限速，忽略；
  终点不回 ICMP → mtr 看不到端到端，以连接和重传数据为准
- 连接：采样期间已建立连接的重传增量、rtt 范围、停在 SYN-SENT 的建连次数
- 重传：只有本机重传 → 去程嫌疑；只有供应商重传 → 回程嫌疑（mtr 看不到回程）

不使用 `mtr -T`：mtr 的 TCP 模式会对供应商业务端口真实建连（每次事故上百次），内核 SYN 重发让延迟显示成
1s/3s/7s，探测连接还会进入共享 PCAP 被 detector 计为 `TCP_RESET`。

同一 `ip:port` 同时只跑一个 netprobe（`locks/netprobe-<ip>-<port>.lock`，内容是持有者的事故编号），
被跳过时写 `net/skipped.txt` 并指向正在采集的事故。默认约 2 分钟完成，期间事故包内暂时还没有 `net/`。

