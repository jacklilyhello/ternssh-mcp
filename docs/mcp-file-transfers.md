# 本机文件传输

本机需要 Node.js 22、项目内的 `scripts/mcp-transfer.mjs`，以及从网页签发的专用配对令牌。在客户端的安全环境中将令牌保存为 `TERNSSH_MCP_TOKEN`，并将 `TERNSSH_MCP_ORIGIN` 设为签发令牌的 HTTPS 原点，例如 `https://your-ternssh.example`。原点包含协议、主机和可选端口。可选参数 `--origin` 用于校对命令中的地址与配对原点是否一致。

MCP 工具返回操作标识、文件标识、字节数、SHA-256 和操作有效期。本机命令在当前进程的文件权限内读写文件，使用专用令牌直接向同站传输网关发送或接收二进制数据。命令输出只包含结果元数据。每个文件上限为 1 MiB。

## 上传

1. 用 `wc -c < ./example.bin` 和 `shasum -a 256 ./example.bin` 读取字节数与 SHA-256。
2. 对已确认的目标服务器调用 `prepare_upload`，传入 `serverId`、`bytes` 和 `sha256`。新上传由服务端分配 `fileId`。需要替换已有受管文件时，在此步另传它的 `replaceFileId`。
3. 把返回的 `operationId` 传给本机命令。示例中的 UUID 是占位符。

```sh
node scripts/mcp-transfer.mjs upload \
  --operation 00000000-0000-4000-8000-000000000001 \
  --file ./example.bin
```

命令核对网关确认的字节数和 SHA-256，输出 `uploaded`、可供下载的 `fileId` 和传输摘要。上传中断或回执无法确认时，命令以非零状态退出并报告 `unknown`。可使用准备步骤返回的文件标识核对远端结果。每次运行只发送一次传输请求。

## 下载

1. 对同一服务器调用 `prepare_download`，传入 `serverId` 和目标文件的 `fileId`。
2. 使用这次下载的 `operationId`，指定本机目标文件。父目录须已存在且可写。

```sh
node scripts/mcp-transfer.mjs download \
  --operation 00000000-0000-4000-8000-000000000002 \
  --file ./received.bin
```

默认保留同名本机文件。明确需要替换普通文件时，加上 `--overwrite`。命令先在目标目录创建临时文件，验证网关返回的数据和写入的内容，再原子安装。默认安装使用同目录硬链接防止并发创建的文件被覆盖。明确覆盖时使用同目录重命名。安装后再次从目标路径读取并核对字节数和 SHA-256，成功时返回 `saved` 和本机绝对路径。

操作凭证按准备响应给出的时间短期有效。结束服务器授权或撤销专用令牌后，需重新取得有效授权才能继续传输。
