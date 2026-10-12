# SMPP Monitor

常驻式 SMPP/TCP 故障取证工具。一个共享 `dumpcap` 保存环形 PCAP；每个完成的文件只由
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

修改并保存 `smpp_suppliers.conf` 后，capture supervisor 会在数秒内检测到变化并平滑
重启 `dumpcap`。也可以手工执行：

```bash
bash smpp_capture_manager.sh reload
```

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
incidents/             PCAP、诊断、配置、连接状态和压缩包
captures/ring/         共享环形 PCAP
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
ROTATE_FILES=40                      dumpcap 单代环形文件数
SNAPLEN=512                          每个包保存的最大字节数
INTERVAL=15                          detector 检查新文件的周期
CAPTURE_KEEP_FILES=60                配置重载后全局最多保留文件数
TCP_RETRANSMISSION_THRESHOLD=10      单个 PCAP 的重发告警阈值
INCIDENT_COOLDOWN_SECONDS=300        同类事故冷却时间
INCIDENT_RETENTION_DAYS=7            incident 保留天数
ALERT_ON_FIN=1                       是否将正常关闭连接记为事故
```

如正常的 SMPP 连接关闭较多，可设置 `ALERT_ON_FIN=0`，只保留强制断开、传输异常和
SMPP 错误告警。

## 诊断职责

- `dumpcap`：只负责低成本保存原始网络包。
- `tshark`：把 TCP/SMPP 报文解码成字段。
- `smpp_detector.py`：关联请求响应、应用阈值、判断问题层级并生成中文诊断。
- `smpp_incident.sh`：收集诊断、技术详情、连接状态和对应 PCAP。

诊断文本面向值班人员；原始字段保存在 incident 内的 `details.json`，用于后续深挖。
