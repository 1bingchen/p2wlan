# 排障指南

先记录客户端、daemon、Control、Relay 的准确版本和时间，再按层排查。

| 现象 | 先检查 | 不要据此下结论 |
| --- | --- | --- |
| 无法登录 | Control URL、HTTPS 证书、账号响应、时间 | 不能仅凭 Relay 正常判断 Control 正常 |
| 登录成功但无设备 | 房间成员、设备授权、Control 信令和本地 daemon | UI 在线不等于 TUN 已建立 |
| 启动提示运行目录权限失败 | 客户端启动阶段、配置和日志目录属主、旧实例是否已退出、路径是否为默认用户目录及普通文件 | 不能据此判断 NAT 打洞失败，也不需要清空账号或网络配置 |
| 本地 `/health` 正常但 `/status` 返回 401 | 诊断密钥文件的读取权限、对应实例的运行目录、是否有不同配置共用日志目录；刷新后确认是否恢复 | 不是 Control 登录到期，也不能据此判断数据面已断开 |
| Direct 不通 | NAT profile、候选来源、UDP 防火墙、路径 reason code | STUN 成功不等于对端可入站 |
| 只有 Relay | Relay TLS、audience/region、ticket、/readyz、撤权 feed | Relay 路径不说明 Direct 一定有缺陷 |
| 虚拟 IP 可见但业务不通 | 本机路由、房间租约、数据面收发计数、目标应用监听和防火墙 | 加密 ACK 或在线人数不等于业务往返 |
| 重启后状态错误 | daemon process/revision、网络 generation、peer session、房间授权 | 旧快照不能当作实时状态 |

建议命令：

    p2wlan --version
    p2wlan status --json
    p2wlan doctor
    p2wlan route verify
    p2wlan logs -f

支持包上传必须由用户显式确认。上传前移除不必要的业务日志和环境文件，保留能解释问题的 reason code、版本、时间和脱敏状态。

桌面启动记录保留阶段和失败代码；日志目录无法写入时，本次启动仍在内存中保留最多 64 条、每条最多 1024 字符的诊断记录。macOS/Linux 的默认运行目录可在权限拒绝时请求一次提权恢复。应用目录之外的父目录须已存在且归当前用户所有；自定义路径或不安全链接需要先由管理员检查，客户端不会扩大访问权限来继续启动。
