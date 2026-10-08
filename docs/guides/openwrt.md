# OpenWrt 路由器节点

OpenWrt 包包含 CLI、daemon、procd 服务和 sysupgrade 配置保留规则。它让路由器本机加入 P2WLAN；不会自动发布 LAN 子网、修改 WAN 防火墙或启用 LAN 转发。需要图形界面的用户仍使用桌面客户端，当前没有 LuCI 插件。

## 兼容范围

| OpenWrt | 包格式 | 包架构 |
| --- | --- | --- |
| 24.10 | `.ipk` / opkg | `x86_64`、`aarch64_generic`、`aarch64_cortex-a53`、`aarch64_cortex-a72`、`aarch64_cortex-a76` |
| 25.12 | `.apk` / apk | 同上 |

二进制使用静态 musl 和基础 CPU 指令集。ARM64 的多个包使用相同指令集，分别标注固件认可的包架构，不能用 `all` 或强制忽略架构来安装。32 位 ARM、32 位 x86、MIPS、厂商私有固件和 snapshot 不在当前包范围内。普通 Linux 的 glibc tarball 不能用于 OpenWrt。

原生依赖为 `kmod-tun`、`ip-full`、`jsonfilter`。`kmod-tun` 必须来自与正在运行的内核匹配的固件软件源；缺少匹配模块时应修复固件/软件源，不能强制忽略内核依赖。安装前检查闪存空间，下载和解包还会使用 `/tmp` 内存；不要在存储不足的设备上安装。

## 安装和连接

在路由器上以 root 运行，使用一个明确且包含 OpenWrt 资产的版本：

```sh
VERSION=v0.1.170
wget -O /tmp/p2wlan-install.sh "https://raw.githubusercontent.com/yhan-sun/p2wlan/$VERSION/scripts/install-openwrt.sh"
sh /tmp/p2wlan-install.sh --version "$VERSION"

p2wlan config set control https://control.example.com
p2wlan login -u user@example.com
p2wlan up
p2wlan status
p2wlan room list
```

安装器读取固件版本和 `DISTRIB_ARCH`，从同一 tag 下载原生包与 `RELEASE-MANIFEST.json`，验证包的 SHA-256 后交给 apk/opkg 安装依赖。25.12 使用 `--allow-untrusted` 安装项目提供的本地 APK；项目包未使用 OpenWrt 官方签名密钥，下载完整性由固定 tag 的公开 manifest 校验。HTTPS 下载需要设备时间正确且具备 CA 证书。只查看选择结果可加 `--dry-run`。

首次安装不会生成共享设备身份，也不会在未配置或未登录时反复启动。登录后可按[房间指南](rooms.md)加入房间。配置、设备密钥和登录凭据保存在 `/etc/p2wlan/p2wlan-config.json`，目录权限 `0700`、文件权限 `0600`。不要把这份配置复制给另一台设备。

## 服务和升级

```sh
p2wlan down
p2wlan up
/etc/init.d/p2wlan enable
/etc/init.d/p2wlan disable
p2wlan logs
logread -e p2wlan
```

默认配置的 `up/down` 由 procd 管理。停止会同时移除 procd 的自动重启状态；重复 `up` 复用同一进程。启动失败时检查日志，CLI 不会另起一个绕过 procd 的 daemon。服务崩溃后最多进行五次快速重启，持续失败会停止重试。`enable/disable` 控制开机启动；`/etc/config/p2wlan` 的 `main.enabled` 可禁用服务启动。

日志、诊断令牌和运行状态位于 `/var/run/p2wlan`，重启后清空；daemon 的文件日志有轮转上限。`--config` 指向其他配置时仍使用独立 CLI 实例，不归默认 procd 服务管理。系统服务固定使用默认配置和状态目录，环境变量不能把它的诊断状态重定向到另一个实例。

升级时先 `p2wlan down`，将上面的 `VERSION` 改为目标版本并重新运行原生安装器，再 `p2wlan up`。`p2wlan update` 会拒绝在 musl/OpenWrt 上安装普通 Linux 的 glibc 包。JSON 配置不随包覆盖，UCI 配置属于包管理器的 conffile；`/lib/upgrade/keep.d/p2wlan` 保留 `/etc/p2wlan/`。跨固件升级仍需自行备份配置，并确认新固件属于兼容范围。

TUN 设备由 daemon 创建并分配地址；不要同时让 netifd 为同一设备分配地址或删除路由。需要通过虚拟网访问路由器上的业务端口时，应为自己的防火墙配置添加最小范围的接口和端口规则。此包不自动开放管理端口，也不提供全 LAN 子网路由。

## 从源码构建

在 Linux x86_64 主机上安装 Rust、对应 musl target，以及 workflow 中列出的 SDK/QEMU 依赖，然后在干净且已提交的 checkout 中运行：

```sh
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
python3 scripts/openwrt/build.py --series 25.12 --arch arm64 --tag v0.1.170 --work-dir /tmp/p2wlan-openwrt --output dist-release
```

`--series` 可为 `24.10` 或 `25.12`，`--arch` 可为 `arm64` 或 `x64`，tag 必须与当前源码版本一致。构建器校验 `scripts/openwrt/targets.json` 固定的官方 SDK、内核及 rootfs 摘要，使用 SDK 的 C 编译器构建静态 musl 程序，再生成原生安装包。在匹配内核的 QEMU 固件中完成原生依赖安装、真实 TUN、进程所有权和停止验证后才输出成功结果。

QEMU 验证不能替代具体型号路由器的闪存、内存、无线网络和固件定制验收。
