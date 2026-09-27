# 网络参考

## 路径

默认 Direct-first 优先验证 LAN、IPv6 或 IPv4 UDP 直连；Relay 同时准备但只在有界直连窗口到期或已建立 Direct 明确失活后兜底。Direct 的确认必须来自当前网络 generation、peer session、候选 epoch 和加密业务路径；控制面可达或探测 ACK 不能单独证明业务互通。

## 服务端端口

| 组件 | 默认内部端口 | 公网边界 |
| --- | ---: | --- |
| Control | 18080 | 通过可信 HTTPS 反代公开 |
| Relay TLS | 18081 | 按需公开 |
| Relay metrics/readyz | 18082 | loopback only |
| UDP observer | 由配置指定 | 可选，不是 Relay 数据端口 |

Control 反向代理必须支持 WebSocket Upgrade。Relay TLS 不能用 Control 的普通 HTTP 代理规则代替；证书、audience、region、ticket keyring 和撤权 feed 必须同时匹配。

## MTU 与 DPLPMTUD

Relay 路径使用保守的业务报文预算。DPLPMTUD 从安全下限开始，成功后逐步提升，失败或取消时回退；Direct 与 Relay 的预算、网络 generation 和连接 epoch 不能混用。高于 1380 的 Relay 路径应提示 PMTU blackhole 风险。

诊断至少显示当前路径、selected MTU、探测状态、失败 reason code 和建议值。MTU smoke、真实 TUN、NAT、网络切换和业务流量是不同验证层，不能互相冒充。

## NAT 限制

STUN 观察到公网映射不代表对端可以入站。目的地址相关的 mapping 与入站 filtering 分开记录：没有独立入站证据时，filtering 为 `Unknown`。只有收到该 socket 此前未联系过的另一个 IP 的合法 CHANGE-REQUEST 响应，才可确认 endpoint-independent filtering；超时或同 IP 换端口响应不足以判定严格过滤。家庭宽带、校园网、企业网、移动热点、CGNAT 和双受限 NAT 的结果不同；Direct 失败时应回退 Relay 或明确提示环境限制。

## 探测成本与候选覆盖

前台 UDP 探测复用进程内全局预算，同时限制网络、peer、peer/目标 IP 和跨 peer 的目标 IP 聚合。目标 IP 聚合上限为每秒 448、每 60 秒 4500；原有进程上限每秒 512、每 60 秒 6000 不变。已确认路径的保活和加密业务不消耗这份前台扫描预算。该限制是单进程的，多房间独立 daemon 之间不宣称已经具备跨进程预算协调。

端口预测使用宽整数后取模，剔除端口 0 和重复候选；当前批次的首选端口不会被历史学习步长替换。NAT 标签保留有符号分配步长，反向分配器的负步长不能使整条 profile 的 generation、观测序号或注册生命周期丢失。历史同方向假设仅占用原有候选预算中的有限份额。学习覆盖率表示近期样本一致性，不是实际打洞成功概率。

Hard↔Hard 候选早于对端版本化 NAT profile 到达时，会在原候选任务内请求一次 roster 刷新并有界等待真实元数据；不会从信令声明伪造 generation，也不会延长 rendezvous 截止。只有本端注册已获服务端确认、对端当前注册同时声明 `hh2_pair_nomination` 和 `hh2_plan_v2` 时才协商 `hh2`；缺少任一能力时使用兼容流程。已识别的 `hh2` 报文若无效，不回退为旧协议。

`hh2` 通过专用 socket 的有序测量记录每次实际 STUN 发送及响应，包括已发出但未观测到映射的尾部。分配作用域、端口范围、有符号步长、网络 generation、样本年龄和预测时距共同决定预测是否可用；并发 STUN gather 仅提供置信度受限的策略提示。预测使用生产端口域，不根据模拟器范围推断。发布候选前重新检查测量和 socket 身份，过期证据不继续发布。预测和固定锚的每个新 socket/目标组合在实际首次发包前还必须满足原预测截止；仅成功系统调用才能登记首发，收到 Probe 或 ACK 不能替代。已经发出的原组合重传和确认沿原阶段截止执行。

双方协商一个包含候选顺序、策略、注册身份、phase 和截止时间的计划。按证据选择固定锚、多端口预测或生日探测；固定锚只在双方测量均支持时使用 2、4 或 8 个 socket，首波覆盖全部选定 socket，后续波次保持原 socket 与目标配对。单 socket 预测窗口最多 32 个候选；超过上限时保留前 8 个，再均匀覆盖余下窗口并保留最远端。生日候选使用与端口域互素的步长避免短周期重复。候选数量、唯一 socket/目标组合和重复发送分别计数。

双方均为完整、等宽的固定步长窗口时，initiator 保持收到的候选顺序，responder 保留首选端口并反转尾部。`hh2` 使用协商计划中的共同 phase；兼容流程沿用 fresh generation 的 phase。此顺序不适用于稀疏窗口或随机映射，也不保证发送期间发生其他端口分配时仍可连通。READY 确认计划，SYNC/SYNC_ACK 将最终首发时间绑定到该计划；首发可在原有截止前提前，不能延长测量预测时距。收到对端确认与本端 HTTP 请求完成是不同证据，HTTP 响应延迟不会撤销已经接收的有效确认。最终确认的上传失败可在预扣的原 HTTP 配额内重试，最多 3 次，复用同一报文且不超过原首发截止。

Hard↔Hard 的全部生日探测 worker 与重复波次共享 5 ms 发送节奏，继续接受原有每 peer/目标 IP 每秒 224 次及全局、持久和恢复 epoch 预算检查。`hh2` 在原总预算内为认证后的重复探测和提名预留额度，探索扫描不能耗尽这部分额度；其他流量仍可能竞争全局预算。短期限流只在原 3 秒 sweep 窗口内重试，等待后重新验证会话和网络身份；持久限流不通过等待绕过。兼容副本单独计入物理 datagram 成本。

测量 socket 在发布和 rendezvous 期间保持隔离。固定锚的本地测量租约保留到首波全部 socket 发出，成功、取消和失败均释放租约；它不能阻止 NAT 后其他设备分配端口。认证 Probe 命中只生成待确认的精确候选对。重复探测、提名 ACK 和最终加密验证均绑定本地 socket、远端 endpoint、session token 和当前生命周期。Direct 提交及其业务路径快照发布完成后才清理同 token 的落选 socket、pending probe 和 reader；迟到旧协议报文不能激活已退休的 `hh2` socket。

策略学习只接受当前网络、模型与会话的有效结果。成功反馈来自最终 Direct 提交；失败反馈只由已收到最终对端确认的 initiator 记录，并要求计划完整执行、没有预算或发送错误且未收到认证响应。取消、不完整执行和信令结果不确定不作为策略失败。学习只调整有限策略顺序，不扩大预算，也不把样本一致性当作实际成功率。高熵随机映射叠加严格过滤时仍可能无法 Direct，Relay 保留为回退路径。

Hard↔Hard 日志区分模型生成数量、归一化入口数量、进入信令数量和实际探测统计。`pre_normalization_reduced_count` 表示调用方在归一化之前已裁掉的候选数量；例如模型生成 96 个而当前策略只接受 32 个，不能报告为已经实际覆盖 96 个。

已解密的 Direct 验证请求和 ACK 遇到本端发送锁竞争时，最多等待 100 ms，并在每次重试时核对原 transport session instance；等待不持有发送锁或会话表锁。锁竞争超时与真实会话替换分别报告，真实替换仍拒绝旧帧，后续 peer lifecycle、网络 generation 和验证 owner 检查继续生效。
