# 直接通过 MCP 运行工作目录命令

在网页「MCP 接入」卡片选择主机，勾选「允许在隔离工作目录运行命令」并确认。已有授权默认关闭此项权限。配对客户端调用 `list_authorized_servers` 时，可在已开启的主机记录中看到 `workspaceShell: true`。服务器会在执行、读输出、查状态及取消时核对当前权限。关闭网页后授权继续有效。

调用 `run_workspace_command` 时传入 `serverId`、新生成的小写 UUIDv4 `requestId` 和 `command` 原文。命令最长 4096 个 UTF-8 字节。可选的 `timeoutMs` 为 1000 至 600000 毫秒，默认 120000 毫秒。任务编号就是 `requestId`。提交前保存该编号，连接中断时以同一配对重连。相同编号的重试不会再次启动命令。

命令在目标 Linux 主机的隔离环境里运行。每个任务获得独立的临时 `/work`，目录内容在该任务结束时释放。可以在同一条 shell 命令中使用参数、管道、重定向和临时文件。该环境使用 BusyBox 工具，权限限于其隔离文件系统，网络连接、宿主凭据以及宿主服务管理接口均不可用。SSH 凭据由 ternssh 后台使用。

客户端可立即调用 `read_job_output`，从 0 开始按 `nextCursor` 续读。`read_job_tail` 默认读取两条流合并后的最近输出。排查末尾错误时传 `stream: "stderr"`，从 `streamTail.segments` 读取最近的错误信息。响应顶层的 `nextCursor` 可用于续读两条流。`get_job_status` 返回状态和退出信息，`cancel_job` 请求停止执行。正常结束且两条流合计不超过 4 MiB 的任务可以逐字节完整取回。超限时保留开头和最后 32 KiB，并报告缺失区间。输出在任务进入终态一小时后过期。详见[任务输出与保留期限](mcp-job-output.md)。

同一主机在现有配对下最多同时占用两个工作目录任务名额，每小时最多接收 64 个新任务。结果未知的请求会保留名额直至租期结束。需要停止授权时，取消该主机的工作目录权限并确认，或使用「结束本次授权」。旧版本授权关联的任务和游标随即失效。

目标主机须为 x86-64 或 ARM64 Linux，已启用非特权用户命名空间和 cgroup v2。SSH 账户须能用 `systemd-run --scope` 创建受限的临时作用域，普通账户使用已委派相应控制器的用户管理器。需要 Python 3.7 或更新版本、GNU `timeout`、可禁用嵌套用户命名空间并限制 tmpfs 大小的 Bubblewrap、静态链接的 BusyBox 和 `libseccomp.so.2`。客户端仅需现有的 MCP 连接。

启动器会检查发行版预装的 Bubblewrap 和 BusyBox，包括系统工具目录、Flatpak 随附的 Bubblewrap 和名为 `busybox.static` 的静态版本。MCP 客户端不能指定可执行文件路径。若工作目录启动前发现依赖缺失，可以用 `read_job_tail` 传入 `stream: "stderr"` 查看 `ternssh: prerequisites v1` 记录。它分别列出各项依赖的检查结果，尚未验证的命名空间或资源控制能力会单独标出。此时远端返回的退出状态来自启动器，提交的命令尚未运行。

每个 `/work` 最多 8 MiB。任务的整个进程组最多使用 192 MiB 内存、24 个任务和半个 CPU 核，不使用交换空间。单进程限制为 64 MiB 地址空间、8 MiB 文件和 30 秒 CPU 时间；允许等待或间歇输出直至所设的墙钟超时。`uptime` 可以读取只读的系统运行时间。
