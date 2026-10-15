# Minecraft 交互采证工具

`scripts/dual-end/` 提供冻结交互计划、监督适配器进程和离线归约证据的独立工具。它们不安装或启动游戏服务端，不配置 P2WLAN、TUN、世界重置或在线账号。使用前须自行准备固定版本服务端、隔离场景与真实原始观测。

## 固定支持范围

| 适配器 | 协议 | 测试运行时 | 入口 |
| --- | --- | --- | --- |
| Java | 1.20.4 / 765，offline，数字地址 | Node 22.16.0 | `scripts/dual-end/minecraft-adapters/java-adapter.js` |
| Bedrock | 1.18.30 / 503 / RakNet 10，offline，数字 IPv4 地址 | Node 26.0.0 | `scripts/dual-end/minecraft-adapters/bedrock/bedrock-adapter.js` |

动作仅限隔离目标的 `block_place`，使用已观测的目标、参考方块和库存。未知版本、缺少前置观测或输入身份不一致会拒绝执行。不会自动发现版本、下载资源包、重连或把同一动作重试成另一条应用请求。

Bedrock 进一步要求 creative、客户端权威的静止移动、legacy inventory、无自定义方块属性和 NBT、固定声明的方块 palette。它仅从原始 layer-0 `update_block` 读取目标与参考状态，不从未解析的 chunk 推断初始方块。非 loopback 地址须在配置中显式设置 `allow_remote_endpoint: true`。发送、加密延迟及可靠重传都绑定原动作、deadline 和完整 held-item 快照；过期、取消、库存变化或需要分片的 gameplay 会关闭会话。收到早于成功 native 完成的更新可能被保守拒绝。

这里的自动协议测试使用合成 loopback codec fixture，不能证明真实 Minecraft 世界、现代 Bedrock、真实设备、TUN、Direct、公网 NAT 或游戏性能已验收。服务端版本、世界、palette checksum 与构建摘要中的远端身份仍是声明，不能仅凭匹配字段认证远端执行。

## 依赖与本地协议测试

两个目录有独立锁文件，分别使用表中运行时。运行下列命令时，确保当前 `node` 是对应的精确版本；禁止以另一套版本的结果替代。

```sh
# Node 22.16.0
npm ci --ignore-scripts --prefix scripts/dual-end/minecraft-adapters
npm audit --audit-level=moderate --prefix scripts/dual-end/minecraft-adapters
npm test --prefix scripts/dual-end/minecraft-adapters

# Node 26.0.0
npm ci --ignore-scripts --prefix scripts/dual-end/minecraft-adapters/bedrock
npm audit --audit-level=moderate --prefix scripts/dual-end/minecraft-adapters/bedrock
npm test --prefix scripts/dual-end/minecraft-adapters/bedrock
```

`--ignore-scripts` 不执行依赖安装脚本；当前 Bedrock 使用纯 JavaScript backend，不启用 worker 或 native backend。依赖审计和 codec 测试不构成完整安全审计或其他平台兼容性证明。

## 计划、监督与归约

原始契约位于 `contracts/minecraft_interaction.json`。计划须在连接前列出完整的预定请求、原始 source nonce、目标和前后状态摘要、固定配置、scenario、适配器源码、lock、实际运行时及游戏/世界身份。适配器核对原始 manifest 文件字节及 stdin envelope，不接受只改解析对象或沿用其他运行时生成的身份。

POSIX supervisor `minecraft_interaction_runner.py` 需要 Python 3.11 或更高版本、显式绝对可执行路径和 JSON argv 数组；没有内置适配器或 shell 插值。以下是 Bedrock 调用形状，输入文件须事先按原始契约冻结，输出路径须位于 checkout 外且尚不存在：

```sh
python3 scripts/dual-end/minecraft_interaction_runner.py \
  --manifest /absolute/path/to/manifest.json \
  --adapter-argv '["/absolute/path/to/node", "/absolute/path/to/checkout/scripts/dual-end/minecraft-adapters/bedrock/bedrock-adapter.js", "--config", "/absolute/path/to/config.json"]' \
  --timeout-ms 10000 \
  --output /absolute/path/outside/repository/runner-result.json
```

Java 使用同一 supervisor，将 argv 中的入口换为 Java 入口和对应运行时。适配器配置与 scenario 的准确字段以对应 `java-input.js`、`bedrock/bedrock-input.js` 校验器为准；测试用 `fixture-input.js` 生成的身份仅属于 fixture。

supervisor 每轮只启动一次适配器，保留原进程组的 anchor，执行有界回收并分别记录直接子进程与 anchor 是否实际 reaped。回收范围只覆盖同权限、未逃离原 POSIX 进程组的可信进程；Windows、逃离进程组或改变权限的后代不在此清理保证内。退出码 0 表示监督和证据流完整，不表示每个动作成功；退出码 1 记录执行失败或取消，2 表示无效输入。回收不完整不会标成完整结果。

离线归约由 `minecraft_interaction.py` 与 `minecraft_interaction_summary.py` 负责，固定分母包含失败、超时、未开始和缺失证据的全部预定请求。启动或 ready 不计成功；确认必须来自原请求发送后的规定原始服务端事件。`adapter_fixture` 的 `application_interaction_ms` 保持 `null`，fixture 延迟与真实应用性能分别记录，未知遥测不补成零。
