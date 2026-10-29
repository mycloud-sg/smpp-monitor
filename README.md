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

启动前通过环境变量设置：

```text
INTERFACE=any                         抓包网卡
ROTATE_SECONDS=60                    PCAP 切分周期
SNAPLEN=1024                         每个包保存的最大字节数
CAPTURE_RETENTION_MINUTES=30         PCAP 按时间保留的分钟数
INTERVAL=15                          detector 检查新文件的周期
TCP_RETRANSMISSION_THRESHOLD=5       单个 PCAP 内同一连接、同一方向的重发告警阈值
INCIDENT_COOLDOWN_SECONDS=300        同类事故冷却时间
INCIDENT_RETENTION_DAYS=3            incident 保留天数
ALERT_ON_FIN=0                       是否将正常关闭连接记为事故
```

如需把正常的 SMPP 连接关闭也记为事故，可设置 `ALERT_ON_FIN=1`。默认只保留强制断开、
传输异常和 SMPP 错误告警。

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
