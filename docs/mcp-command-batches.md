# 在已授权主机上运行自定义命令

在网页「MCP 接入」卡片确认主机授权后，配对客户端可为其中一台主机拟定命令批次。审批器会显示具体主机和完整命令，在本机通过 Touch ID 确认后，客户端即可跟踪执行。审批器需要 Apple Silicon Mac、macOS 13 或更高版本、Secure Enclave 和已登记的 Touch ID。

## 构建本机审批器

修改 `tools/macos-approval/Sources/ApprovalCore/Review.swift` 中的 `trustedOrigin`，设为自托管实例的 HTTPS 原点，例如 `https://your-ternssh.example`。只填写协议、主机和可选端口。

从仓库根目录运行以下命令构建并签名应用。

```sh
cd tools/macos-approval
swift build -c release --arch arm64
bin_dir=$(swift build -c release --arch arm64 --show-bin-path)
app_dir="$PWD/.build/TernSSHApproval.app"
mkdir -p "$app_dir/Contents/MacOS"
install -m 755 "$bin_dir/TernSSHApproval" "$app_dir/Contents/MacOS/TernSSHApproval"
install -m 644 Info.plist "$app_dir/Contents/Info.plist"
codesign --force --sign - --options runtime --identifier dev.ternssh.CommandApproval "$app_dir"
codesign --verify --strict "$app_dir"
```

## 配对与登记

1. 在自建实例的卡片中创建专用令牌，按 [README 中的方式](../README.zh.md#接入-mcp-客户端)注册 `/mcp`。网页端若尚未记录目标服务器的 SSH 主机密钥，请先在网页终端连接并核验。
2. 将构建好的 `TernSSHApproval.app` 放入 `/Applications`。打开应用并选择 **Enroll**，输入同一个令牌，完成 Touch ID。应用会显示公钥和 SHA-256 指纹，配对令牌与硬件密钥的封装存入这份构建专用的登录钥匙串项目。
3. 核对审批器显示的指纹，在 Worker 设置中将该 64 位小写十六进制值配置为 `TERNSSH_APPROVER_SHA256`。一个实例同时信任一把审批公钥，配置该指纹后才允许签名批次。
4. 在网页卡片中找到同一配对，点击「登记审批公钥」，粘贴应用提供的公钥并核对指纹。更换审批器构建或签名密钥时，请结束旧配对后重新登记。
5. 在 MCP 客户端中添加本地审批工具。以 Codex 为例，在仓库根目录运行以下命令。

```sh
codex mcp add ternssh-approval -- node "$PWD/scripts/mcp-batch-confirm.mjs"
```

审批器从构建时绑定的实例取回待签批次。签名覆盖站点、配对、主机身份、授权代次、命令原文和顺序、超时、执行策略、到期时间与一次性挑战。审批私钥保留在本机 Secure Enclave，SSH 凭据由 ternssh 服务端使用。

## 从提案到结果

| 步骤 | 工具 | 客户端保存或使用的数据 |
| --- | --- | --- |
| 找到主机 | `list_authorized_servers` | 用当前名单中的 `serverId`。 |
| 创建提案 | `prepare_command_batch` | 先保存新生成的小写 UUIDv4 `batchId`，再提交 `serverId`、`batchId`、有序字符串数组 `commands` 和可选 `timeoutMs`。保存响应的 `digest` 与 `expiresAt`。 |
| 复查待签原文 | `get_command_batch` | 同一配对传入 `serverId` 和 `batchId` 可取回冻结内容。 |
| 本机确认 | 本地 `confirm_command_batch` | 传入 `serverId` 和 `batchId`。在审批器的 **Commands** 页看主机、顺序和完整原文，**UTF-8 bytes** 页可核对不可见字符的编码。选择 **Approve Exact Batch** 并完成 Touch ID，审批器即自行提交一次签名。 |
| 跟踪执行 | `get_command_batch_status` | 传入 `serverId`、`batchId`、`digest`。按 `items[index].jobId` 读取已启动命令的输出。保留三项标识与每个任务的游标，即可断线重连。 |
| 停止批次 | `cancel_command_batch` | 传入同样的三个标识，随后查询各项的实际终态、退出码或信号。 |

每条命令在独立的非交互 SSH 会话中按原文执行，支持参数、引号、管道和重定向。需要共享当前目录或 shell 变量的操作应写在同一条命令中。上一项退出码为零才启动下一项，失败、超时、取消或结果未知都会停止后续项。客户端可以在当前项运行期间分页读取 stdout 和 stderr，或直接定位最后一页。

一次准备或读取的重试不会再次执行。提交签名后的回执丢失时，用原来的三个标识查询批次状态。若仍无法确认是否已分发，按结果未知处理。新编号表示另一次有意发起的操作。新增命令、改写命令、调换顺序或修改超时，均需要新批次和新的本机确认。

## 限额、过期与撤销

- 一批可含 1 至 16 条命令。单条最多 4096 个 UTF-8 字节，合计最多 8192 字节，命令数组编码成 JSON 后最多 12 KiB。普通空格、引号、制表符及 LF、CRLF 换行均保留。空命令、NUL、终端转义和双向文本控制符等会被拒绝。
- `timeoutMs` 对每条命令分别生效，范围为 1000 至 600000 毫秒，默认 120000 毫秒。提案有效期为 15 分钟，每个配对最多保留 32 份有效原文和 8192 个批次编号。过期编号继续占用去重名额。已批准批次的执行授权也有截止时间，上限为两小时。
- 每个任务可完整读取最多 4 MiB 的 stdout 和 stderr 合计输出，任务终结后一小时过期。可读容量、缺失区间、末尾读取及续读方法见[任务输出指南](mcp-job-output.md)。
- 关闭网页、关闭聊天或移除卡片会保留主机授权。整份替换名单、结束授权或撤销配对后，旧授权下的任务编号和游标失效。结束临时使用时，在网页结束本次授权、撤销临时令牌，再在本机应用选择 **Remove Enrollment** 清理凭据。部署维护者可清除 Worker 的审批指纹，关闭签名批次。
