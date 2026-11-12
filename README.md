# Cursor 账号工具：网页 Token 提取与客户端登录状态复制

在账号本人授权的设备之间，离线导出、导入 Cursor 客户端已经保存的登录凭据。源设备只读，
不执行退出登录；目标设备写入前自动备份。也可直接显示邮箱和网页 `WorkosCursorSessionToken`。
只依赖 Python 3.8+ 标准库，无需安装 Python 包。

**两台设备会共用复制的会话；这个工具不能创建独立会话，也不能保证两台设备长期同时在线。**
跨设备后能否请求、续期，以及一端操作是否影响另一端，取决于 Cursor 服务端。当前依据本机
Cursor 3.18.9 的存储/刷新代码实现，尚未用真实账号完成跨设备、跨刷新周期验证。
网页提取复用原来 `cursor-export-credential.py` 的 WAL/快照读取逻辑；旧的
`--snapshot --show-token` 和 `--snapshot --print-token` 用法同样支持。

## GitHub 一键运行

仓库：<https://github.com/jonathanfan-ee/cursor-login-export>。下面使用固定版本 `v0.2.0`。

macOS / Linux（打开中文菜单）：

```sh
curl -fsSL 'https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/v0.2.0/cursor_session_transfer.py' | python3 -
```

Windows PowerShell（下载后运行，兼容 PowerShell 5.1 的编码处理）：

```powershell
curl.exe -fsSL "https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/v0.2.0/cursor_session_transfer.py" -o "$env:TEMP\cursor-tool.py"; if ($LASTEXITCODE -eq 0) { py -3 "$env:TEMP\cursor-tool.py" }
```

菜单 `1` 导出客户端凭据、`2` 导入、`5` 提取网页 Token。管道运行时菜单会重新连接本机终端；
没有交互终端的环境请指定子命令。只需要网页 Token 时也可直接运行：

```sh
curl -fsSL 'https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/v0.2.0/cursor_session_transfer.py' | python3 - --snapshot --show-token
```

Windows 的对应写法是把 `python3 -` 替换为 `py -3 -`，并使用 `curl.exe`。
如果 PowerShell 管道出现中文编码问题，请使用上面的下载后运行方式，再在本地命令末尾加
`web-token` 或 `--snapshot --show-token`。

## 最简单的使用方法

把这个目录发给朋友；实际使用只需要主 Python 文件和对应系统的启动文件。
Windows 双击 `start.cmd`；macOS 从终端执行 `sh start.command`（解压后有执行权限时也可双击）；
Linux 执行 `sh start.sh`。如果尚未安装 Python，先从 <https://www.python.org/downloads/> 安装。

1. 旧设备：**完全关闭 Cursor 程序，但不要点 Sign Out/退出账号**。请从系统终端运行工具，
   不要使用 Cursor 内置终端。选择 `1. 旧设备：导出`，回车使用默认文件位置。
2. 将生成的 JSON 文件私下传到新设备。该文件包含明文 access/refresh 凭据。
3. 新设备先正常安装并启动一次 Cursor，再完全关闭程序。运行工具，选 `2. 新设备：导入`，
   粘贴 JSON 文件路径，核对邮箱，输入 `y`。
4. 重开两台设备的 Cursor，分别验证实际请求。还需要观察下一次自动续期是否正常，
   不能以显示头像/邮箱或第一次请求成功作为长期双机可用的证明。

菜单 `5. 提取网页 Token` 只读取当前设备，直接在终端显示邮箱和可复制的一整行候选值；
不导出 refreshToken，也不写入 JSON。它默认使用临时 SQLite 快照，正常结束时自动清理。
`--snapshot` 可能需要约一份数据库大小的临时磁盘空间；没有可读 WAL 帧时会明确提示结果可能过期。

脚本不会读取或改写机器 ID、系统钥匙串、设备指纹，不联网、不自动刷新、不执行退出登录。
导入只更新认证字段并清理几项账号缓存，不覆盖整份数据库，不迁移聊天、插件或设置。

## 直接运行命令

macOS / Linux：

```sh
python3 cursor_session_transfer.py

# 只提取网页 Token
python3 cursor_session_transfer.py web-token

# 旧设备
python3 cursor_session_transfer.py export --output ./cursor-session.json

# 新设备
python3 cursor_session_transfer.py import ./cursor-session.json
```

Windows PowerShell / 命令提示符：

```powershell
py -3 cursor_session_transfer.py
py -3 cursor_session_transfer.py web-token
py -3 cursor_session_transfer.py export --output .\cursor-session.json
py -3 cursor_session_transfer.py import .\cursor-session.json
```

默认自动识别的数据库位置：

| 系统 | 数据库 |
|---|---|
| macOS | `~/Library/Application Support/Cursor/User/globalStorage/state.vscdb` |
| Windows | `%APPDATA%\Cursor\User\globalStorage\state.vscdb` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/Cursor/User/globalStorage/state.vscdb` |

便携版、自定义用户目录或其他安装方式可加 `--db "完整的 state.vscdb 路径"`。
客户端迁移操作检测到 Cursor 进程时会停止；网页 Token 提取沿用只读快照逻辑，不强制检查进程。
如果环境没有 `ps`/`tasklist`，在手动确认程序完全关闭后
可以加 `--closed`；这只是跳过本地进程检查，不改变任何服务端行为。

## 恢复本机原状态

每次导入/恢复前，工具都将即将改动的原始字段备份到数据库旁的
`cursor-session-backups/`，成功时打印完整路径。选择菜单 `3`，或者：

```sh
python3 cursor_session_transfer.py restore "/完整路径/before-import-时间-随机值.json"
```

恢复只回写本机字段；**备份无法恢复已经被服务端撤销、轮换或过期的会话**。
旧设备的数据库从未被这个工具写入，但新设备对共用会话的服务端操作仍可能影响旧设备。

## 可直接转发的提醒

> 用完网页后不要点击 **Log out**，也不要在任何一台客户端点 **Sign Out** 或在会话管理页撤销会话。
> 我们之前实测过：用客户端凭证登录网页后点击 Log out，源客户端随后出现 Authentication error。
> 这次复制同样不能保证两台设备互相独立。一端退出、凭据轮换或服务端要求重新验证，都可能导致掉线。
> 你目前收不到手机验证码，掉线后可能暂时无法重新登录；这不代表永远无法恢复，但需要恢复手机号
> 或联系 Cursor 官方支持。迁移文件和备份都含登录凭据，不要公开分享。关闭网页不等于服务端退出。

## 验证范围

```sh
python3 -m unittest discover -s . -p 'test_*.py' -v
```

测试使用临时合成 SQLite/JWT；覆盖三系统默认路径、源库只读、目标无关数据保留、自动备份/恢复、
失败回滚、网页提取和旧参数兼容。GitHub Actions 将在 Windows/macOS/Linux 的 Python 3.12、
以及 Linux 的 Python 3.8 上运行这些测试；具体通过状态见仓库 Actions。
未用真实凭据进行跨机登录或长期续期测试。

## 旧版独立导出工具

原来的 `cursor-export-credential.py --snapshot --show-token` 及其启动器继续保留。
详细参数与 WAL 故障排查见 [旧版说明](LEGACY_EXPORT.md)。
