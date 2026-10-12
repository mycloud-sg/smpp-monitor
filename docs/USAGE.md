# SMPP Monitor 使用文档

## 1. 运行环境

要求：

- Linux；
- Python 3；
- `dumpcap` 和 `tshark`；
- `ss`、`tar`、`awk`、`find`；
- 运行账户具有抓包权限。

确认依赖：

```bash
command -v python3
command -v dumpcap
command -v tshark
command -v ss
command -v tar
```

项目默认使用脚本所在目录，不要求固定放在 `/root/smpp_monitor`。也可以显式设置：

```bash
export SMPP_MONITOR_HOME=/root/smpp_monitor
```

## 2. 首次配置

编辑 `smpp_suppliers.conf`：

```ini
[smpp_cm_wa]
ip=85.119.48.101
port=30000
timeout=30

[smpp_example]
ip=192.0.2.10
port=2775
timeout=30
```

要求：

- section 名称必须唯一；
- `ip` 是 Supplier 的目标地址；
- `port` 必须为数字；
- `timeout` 必须为大于 0 的秒数。

确认脚本权限：

```bash
chmod +x \
  smpp_capture_manager.sh \
  smpp_capture_worker.sh \
  smpp_detector_worker.sh \
  smpp_detector.py \
  smpp_incident.sh
```

## 3. 启动和停止

启动：

```bash
bash smpp_capture_manager.sh start
```

状态检查：

```bash
bash smpp_capture_manager.sh status
```

正常状态类似：

```text
capture supervisor running pid=1001
dumpcap running pid=1003
detector running pid=1008
```

停止：

```bash
bash smpp_capture_manager.sh stop
```

重启全部组件：

```bash
bash smpp_capture_manager.sh restart
```

## 4. 修改 Supplier 配置

修改并保存：

```bash
vim smpp_suppliers.conf
```

capture supervisor 默认在 5 秒内检测到变化，停止旧 dumpcap，再按照新配置启动。

希望立即重载时执行：

```bash
bash smpp_capture_manager.sh reload
```

随后检查：

```bash
bash smpp_capture_manager.sh status
tail -30 capture.log
```

日志中会打印实际使用的过滤条件：

```text
capture filter: (host 85.119.48.101 and port 30000) or ...
```

## 5. 常用运行参数

所有参数均通过环境变量覆盖默认值。环境变量必须在执行 `start` 前设置，并由启动进程继承。

| 参数 | 默认值 | 作用 |
|---|---:|---|
| `INTERFACE` | `any` | dumpcap 抓包网卡 |
| `ROTATE_SECONDS` | `60` | 每个 PCAP 的时间长度 |
| `SNAPLEN` | `1024` | 每个网络包最多保存的字节数 |
| `CAPTURE_RETENTION_MINUTES` | `30` | 源 PCAP 保留时间 |
| `CONFIG_CHECK_INTERVAL` | `5` | Supplier 配置检查周期，单位秒 |
| `INTERVAL` | `15` | detector 扫描新 PCAP 的周期，单位秒 |
| `TCP_RETRANSMISSION_THRESHOLD` | `10` | 单个 PCAP 内触发诊断的 TCP 重发数量 |
| `INCIDENT_COOLDOWN_SECONDS` | `300` | 同类 incident 冷却时间 |
| `INCIDENT_RETENTION_DAYS` | `7` | incident 保留天数 |
| `ALERT_ON_FIN` | `1` | 是否将正常关闭连接作为事故 |

示例：保留 60 分钟 PCAP，并关闭正常 FIN 告警：

```bash
export CAPTURE_RETENTION_MINUTES=60
export ALERT_ON_FIN=0
bash smpp_capture_manager.sh start
```

如果通过 systemd、Supervisor 或其他服务管理器启动，需要在对应服务配置中设置环境变量。

## 6. 查看诊断

查看每个 Supplier 最近一次事故：

```bash
cat diagnosis-latest.txt
```

查看最近写入的诊断卡片：

```bash
tail -100 diagnosis.log
```

诊断卡片示例：

```text
============================================================
事故编号：20261012-102142-smpp_cm_wa
事故对象：smpp_cm_wa
目标地址：85.119.48.101:30000

时间范围：
  2026-10-12 10:20:58
  至 2026-10-12 10:22:16

问题层级：TCP

问题说明：
  与供应商的连接被供应商一侧强制断开。
  SMPP 异常与网络异常发生在同一时间段，优先排查网络连接。

初步定位：
  优先排查供应商侧。

对应 PCAP：
  /root/smpp_monitor/incidents/20261012-102142-smpp_cm_wa/pcap/example.pcapng
============================================================
```

日常先看中文 `.txt`；需要深入分析时再看同名 `details.json` 或 PCAP。

## 7. 获取 Incident

按时间查看最近事故：

```bash
ls -lht incidents | head -20
```

一个事故同时包含目录和压缩包：

```text
incidents/20261012-102142-smpp_cm_wa/
incidents/20261012-102142-smpp_cm_wa.tar.gz
```

目录内容：

| 文件 | 用途 |
|---|---|
| `diagnosis.txt` | 中文诊断结论 |
| `details.json` | detector 原始技术事件 |
| `info.txt` | 时间、Supplier 和服务器信息 |
| `supplier.conf` | 事故时对应的 Supplier 配置 |
| `ss.txt` | 事故生成时的 TCP 连接状态 |
| `pcap/` | 触发文件及之前最多 4 个 PCAP |

向供应商提交证据时，通常发送 `.tar.gz` 即可。

## 8. 查看运行日志

抓包与配置重载：

```bash
tail -f capture.log
```

检测调度和 tshark 错误：

```bash
tail -f detector.log
```

确认 PCAP 正在轮转：

```bash
ls -lht captures/ring | head
```

确认 detector 正在处理：

```bash
find state/processed -maxdepth 1 -name '*.done' -mmin -5
```

## 9. 手工分析一个 PCAP

分析共享 PCAP 中的所有 Supplier：

```bash
python3 smpp_detector.py captures/ring/<capture>.pcapng
```

只生成指定 Supplier 的诊断：

```bash
python3 smpp_detector.py smpp_cm_wa captures/ring/<capture>.pcapng
```

退出码：

| 退出码 | 含义 |
|---:|---|
| `0` | 未发现异常 |
| `1` | 配置、文件或 tshark 执行失败 |
| `2` | 发现异常 |

手工执行也会生成正式诊断和 incident，并受到 incident 冷却时间限制。

## 10. 常见问题

### capture supervisor 正常，但 dumpcap stopped

检查：

```bash
tail -50 capture.log
command -v dumpcap
dumpcap -D
```

常见原因：

- dumpcap 未安装；
- 当前账户没有抓包权限；
- `INTERFACE` 不存在；
- Supplier 配置缺少有效 IP 或端口。

### detector stopped

检查：

```bash
command -v tshark
tail -50 detector.log
```

detector worker 启动时找不到 tshark 会直接退出。

### PCAP 存在，但没有诊断

依次确认：

1. 当前文件是否仍是最新、尚未关闭的 PCAP；
2. 是否已存在对应 `.done`；
3. `detector.log` 是否有 tshark 错误；
4. tshark 是否能将目标端口识别为 SMPP；
5. 事件是否处于 300 秒冷却期。

### 正常断连告警太多

启动前设置：

```bash
export ALERT_ON_FIN=0
```

然后重启 detector：

```bash
bash smpp_capture_manager.sh restart
```

### 修改环境变量后没有生效

环境变量在进程启动时读取。设置后需要重新启动对应进程：

```bash
bash smpp_capture_manager.sh restart
```

单纯执行 `reload` 只重新加载 Supplier IP 和端口，不会改变已经启动的 supervisor 自身环境。

## 11. 升级注意事项

从旧版“每个 Supplier 一个 tcpdump”升级时：

```bash
bash smpp_capture_manager.sh stop
git pull
bash smpp_capture_manager.sh start
```

启动新版前，确认旧的 Supplier worker 和 tcpdump 已经停止，避免新旧抓包进程同时运行。

历史 `captures/`、`incidents/` 和 `state/` 是运行数据，不应加入 Git。升级前如需长期保存，请备份到项目目录之外。

