# MCP 任务输出与续读

每个任务都有独立的 SSH 会话，可以在网页终端同时使用或已关闭时读取。对于已批准的自定义命令，用 `get_command_batch_status` 返回的 `items[index].jobId` 读取对应命令。已授权主机的固定诊断也可以创建可续读的任务。见[自定义命令批次指南](mcp-command-batches.md)。

创建固定诊断任务时，调用 `run_diagnostic`，传入 `serverId`、`diagnostic`、UUIDv4 格式的 `requestId` 和 `asJob: true`。`diagnostic` 可选 `utc`、`system_name` 或 `check_exit`。`timeoutMs` 取值为 1000 至 600000 毫秒，默认 120000 毫秒。客户端应在提交前保存请求编号。返回的 `jobId` 与它相同。相同参数和编号可以核对既有任务。跨同步模式、换主机或换诊断均不能用已占用的编号发起第二次执行。

| 工具 | 使用方式 |
| --- | --- |
| `get_job_status` | 传入 `serverId` 和 `jobId` 获取状态、退出码或信号、输出总量。 |
| `read_job_output` | 首次从 `cursor: 0` 读取，保存响应的 `nextCursor`。重新连接后用同一配对、主机、任务和游标续读。 |
| `read_job_tail` | 省略 `stream` 时按接收顺序读合并输出的末尾。只看最近的错误时传 `stream: "stderr"`，只看标准输出时传 `stream: "stdout"`。 |
| `cancel_job` | 请求停止任务。随后查询任务状态，远端已确认的退出码或信号才会出现在结果中。 |

两个读取工具均接受可选的 `limit`，单位为原始字节，默认 8192，最大 32768。合并读取每页最多返回 128 帧。`frames` 按接收顺序排列，每帧给出全局字节偏移 `offset`、流名称 `stream`、文本预览 `text` 和原始字节 `base64`。UTF-8 文本预览将跨块字符放在该字符最后一个字节所在的帧中。校验时逐帧解码 Base64，按流追加并增量计算 SHA-256。收完后将两条流的长度分别与 `stdoutBytes`、`stderrBytes` 比对，有预期摘要时再比对摘要。

SSH 的两条流可能交错到达。即使 stderr 已输出错误，后到的 stdout 也可能占满合并输出的最后一页。此时用 `read_job_tail` 指定 `stream: "stderr"`，`limit` 就只计算 stderr 的字节数。结果中的 `streamTail` 给出所选流、所请求的流内半开区间 `[startOffset, endOffset)` 和其中缺失的流内区间 `missingRanges`。`streamTail.segments` 按流内偏移排列，每段包含流内起点 `offset`、文本预览 `text` 和原始字节 `base64`。某条流尚无输出时，该流的起止偏移均为 0，段列表为空。

读取指定流的末尾后，用响应顶层的 `nextCursor` 调用 `read_job_output`，即可接收此次读取后两条流的新增字节。`nextCursor` 是全局偏移，`streamTail.endOffset` 则只统计所选流。要回读全部输出，仍从全局 `cursor: 0` 开始。

客户端应在完整解析并保存一页后提交 `nextCursor`。重读同一页时按 `offset` 丢弃已保存的字节。读取仍在运行的任务时，同一起点也可能返回稍后新增的数据。如果客户端截短了工具响应，请减小 `limit`，从本页起始游标重读。

`hasMore` 表示响应生成时还有已存数据。`running: true` 且 `hasMore: false` 表示已追到当前末尾，稍后用同一 `nextCursor` 再读。`running: false` 后仍应读到 `hasMore: false`，再核对 `outputState`。读取与取消均要求原配对和原授权代次仍然有效。替换授权、结束授权或撤销配对后，旧任务不能再用于读取。

每个任务保留 4 MiB 输出，stdout 和 stderr 合计。超过容量后保留最初的 4161536 字节和最近的 32768 字节。顶层 `missingRanges` 给出已知缺失的全局半开区间，含起点、不含终点。指定流的尾读遵循同一保留策略，如所请求的流内区间有字节被淘汰，`streamTail.missingRanges` 会给出相应范围。传输异常时，`unknownSuffixFrom` 标记可能缺失的远端尾部。`status: "unknown"` 表示远端结果无法确定。此时用已记录的任务编号查询，换新编号会被视为另一项任务。

每个任务的输出在**该任务进入终态一小时后**过期。各条命令单独计时，长批次宜在运行中逐项读取。已授权的访问会收到 `expired` 和失效的字节范围。批次状态及其任务列表另在整批进入终态一小时后过期。作业保留去重记录，过期的请求编号不能重新执行。
