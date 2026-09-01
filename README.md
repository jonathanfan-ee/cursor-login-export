# Cursor 凭证导出工具

这个小脚本在本机离线读取 Cursor 的 `state.vscdb`，从 access JWT 生成网页端可尝试使用的
`userId::accessToken` 候选值。它不联网、不启动浏览器，也不会修改 Cursor 的业务数据。
读取 WAL 时 SQLite 可能创建或更新仅用于锁定的 `-shm` sidecar；主库业务表不会写入。
遇到 SQLite WAL 短暂切换时会自动重试；也可以显式创建临时快照。
为避免把缺失 WAL 的旧主文件误当成最新登录态，普通模式不会自动启用 `immutable`；检测到
WAL sidecar 不完整时会停止并给出下一步提示。

脚本只依赖 Python 标准库（建议 Python 3.8+），不需要 `pip install` 或虚拟环境。

## 跨设备一键运行

把这个仓库目录（或发布的便携包）复制到目标设备，不能只复制某一个启动器。
启动器会按自身所在目录寻找 `cursor-export-credential.py`，所以不再依赖
`/Users/your-name/...` 这样的本机绝对路径。

目标设备必须已经安装 Cursor，并在其中登录要导出的账号；本工具读取的是“目标设备自己的”
本地登录态，不会把源设备的 token 自动搬过去。运行前请完全退出 Cursor/FlyCursor，
并暂时停止会读取数据库的扩展（例如 SpecStory），避免 WAL 文件正在切换。

对应平台直接运行：

```text
macOS（Finder 双击）：cursor-export-token.command
macOS / Linux（终端）：./cursor-export-token.sh
Windows（命令提示符或双击）：cursor-export-token.cmd
Windows PowerShell：.\cursor-export-token.ps1
```

macOS 首次从网络下载后若被 Gatekeeper 拦截，可在 Finder 中右键该 `.command` 文件并选择“打开”，
确认后再运行。

这些入口等价于原来的命令：

```bash
python3 cursor-export-credential.py --show-token
```

第一次在新设备上使用时，可先运行不读取真实数据库的自测：

```bash
./cursor-export-credential.sh --self-test
```

若从 zip 解压后 macOS/Linux 提示没有执行权限，在目录内执行一次：

```bash
chmod +x cursor-export-credential.sh cursor-export-token.sh cursor-export-token.command
```

需要自定义参数（例如 `--db`）时，把参数接在启动器后面即可：

```bash
./cursor-export-token.sh --db "/path/to/state.vscdb"
```

如果普通读取仍提示 `unable to open database file`，先确认 Cursor/FlyCursor 和相关扩展已经完全退出，
再使用只读 SQLite backup 创建一次性临时副本：

```bash
./cursor-export-token.sh --snapshot
```

`--snapshot` 正常结束时会清理临时文件，并需要约一份数据库大小的临时磁盘空间（大型数据库可能
需要数分钟）；能够打开 WAL
时会把同一事务视图完整复制到副本，不会写入 `state.vscdb` 主库业务表（SQLite 仍可能更新仅用于
锁定的 `-shm` sidecar）。如果进程被强制中断，操作系统临时目录中可能暂时留下副本，之后可按
系统的临时文件清理策略处理。快照创建仍要求源库可被 SQLite 正常打开，且 WAL 数据库的
`state.vscdb-wal` 与 `state.vscdb-shm` 两个 sidecar 都可访问；不要在应用运行时手动拼接这些文件。
如果 WAL sidecar 已经丢失，快照无法恢复其中的内容；应从同一时刻的完整备份恢复，或重新登录，
不要把旧主库直接当成最新登录态。

仅当你已经拿到一个确认静止、完整的主库副本时，才使用高级选项：

```bash
./cursor-export-credential.sh \
  --db "/path/to/static/state.vscdb" \
  --immutable \
  --show-token
```

这个模式必须显式指定 `--db`，会忽略 WAL，可能读到旧值；它不会自动启用，也不适合正在运行的
Cursor 数据库。`--allow-stale` 是同一个选项的兼容别名。

不想默认显示完整凭据时，使用通用入口：

```bash
./cursor-export-credential.sh --info
./cursor-export-credential.sh --output ./cursor-session.txt
```

Windows 的通用入口是 `cursor-export-credential.cmd`；PowerShell 的通用入口是
`cursor-export-credential.ps1`。

PowerShell 若被执行策略拦截，可在该目录打开 PowerShell 后运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\cursor-export-token.ps1
```

Windows 命令提示符双击入口会暂停在结果画面；脚本化调用若不需要暂停，可先设置
`CURSOR_EXPORT_NO_PAUSE=1`。

## GitHub 一行命令

仓库发布后，可以直接从 GitHub 把脚本流式交给本机 Python，不需要手动下载或落盘。
终端里请粘贴纯 URL，不要带 Markdown 的 `[]()`：

```bash
curl -fsSL https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/main/cursor-export-credential.py | python3 - --show-token
```

如果遇到 WAL 读取错误，完全退出 Cursor/FlyCursor 和 SpecStory 后，可显式请求临时快照：

```bash
curl -fsSL https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/main/cursor-export-credential.py | python3 - --snapshot --show-token
```

如果两个 sidecar 已经确认丢失，`--snapshot` 不能凭空恢复 WAL；只有在你确认主文件是完整静态
副本、并接受可能读到旧值时，才显式指定路径使用最后的应急模式（会打印醒目警告）：

```bash
curl -fsSL https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/main/cursor-export-credential.py \
  | python3 - --db "$HOME/Library/Application Support/Cursor/User/globalStorage/state.vscdb" \
  --immutable --show-token
```

Windows 同样只需把参数接在 `py -3 -` 后面：

```powershell
curl.exe -fsSL https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/main/cursor-export-credential.py | py -3 - --snapshot --show-token
```

如果 Windows 上自动发现的路径不确定，可以先在 CMD 查看两个常见位置（`/a` 会显示隐藏文件）：

```bat
dir /a "%APPDATA%\Cursor\User\globalStorage\state.vscdb*"
dir /a "%LOCALAPPDATA%\Cursor\User\globalStorage\state.vscdb*"
```

然后显式指定实际存在的库。CMD 写法：

```bat
curl.exe -fsSL https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/main/cursor-export-credential.py ^
  | py -3 - --db "%APPDATA%\Cursor\User\globalStorage\state.vscdb" --snapshot --show-token
```

PowerShell 写法：

```powershell
curl.exe -fsSL https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/main/cursor-export-credential.py | py -3 - --db "$env:APPDATA\Cursor\User\globalStorage\state.vscdb" --snapshot --show-token
```

只有确认 `-wal` 已经永久丢失、并接受主库可能是旧值时，才把上面命令中的
`--snapshot` 换成 `--immutable`；该模式必须保留 `--db`。

Windows CMD 或 PowerShell 使用 Windows 自带的原生 curl 和 Python Launcher：

```powershell
curl.exe -fsSL https://raw.githubusercontent.com/jonathanfan-ee/cursor-login-export/main/cursor-export-credential.py | py -3 - --show-token
```

建议在实际分发时把 `main` 替换成已审核的完整 commit SHA，以避免远端分支变化带来的供应链风险。
Windows PowerShell 5.1 中，裸写 `curl` 可能会被解析为 `Invoke-WebRequest`，因此这里明确写 `curl.exe`。
私有仓库则不要使用公开 raw 地址；在已登录 GitHub CLI 的设备上运行：

```bash
gh api -H 'Accept: application/vnd.github.raw' \
  'repos/jonathanfan-ee/cursor-login-export/contents/cursor-export-credential.py?ref=main' \
  | python3 - --show-token
```

上述命令需要目标设备已安装 `curl`/`curl.exe` 或 `gh`，以及 Python 3.8+；不会把脚本保存到磁盘。

## 最快用法

先完全退出 Cursor/FlyCursor 和相关扩展，再运行：

```bash
python3 cursor-export-credential.py
```

默认只显示简洁信息：邮箱（如果本地有缓存）、账号 ID 和到期时间，不显示完整 token。

需要在终端看到邮箱和完整候选值时，显式运行：

```bash
python3 cursor-export-credential.py --show-token
```

输出格式是：

```text
邮箱：you@example.com
WorkosCursorSessionToken（复制下一行）：
user_xxx::<JWT>
```

只输出一行纯候选值（适合管道或直接粘贴）：

```bash
python3 cursor-export-credential.py --print-token
```

`--print` 和 `--token-only` 是 `--print-token` 的兼容别名。完整 token 只会在这些显式
选项下输出；普通状态、错误和 `--dry-run` 不会夹带 token。

## 常用选项

```bash
# 只看简洁信息，不写文件、不显示 token
python3 cursor-export-credential.py --info

# 保存为私有文件（macOS/Linux 为 0600）
python3 cursor-export-credential.py --output ./cursor-session.txt

# 配置库路径不在默认位置时
python3 cursor-export-credential.py \
  --db "/path/to/state.vscdb" \
  --show-token

# WAL sidecar 切换导致普通读取失败时，创建一次性临时快照
python3 cursor-export-credential.py --snapshot --show-token
```

需要结构化 JSON 时使用 `--format json --output PATH`；`refreshToken` 默认不导出，只有
明确需要时才加 `--include-refresh`。`--show-meta` 是诊断模式，会显示更多 JWT 元数据。

## 账号与有效期

邮箱优先读取 Cursor 的本地 `cursorAuth/cachedEmail`；没有缓存时只尝试读取 JWT 中已有的
`email` claim，不会联网查询，所以显示“未缓存”是正常的。独立的旧版/第三方
`cursorAuth/userId` 只作提示；冲突时默认按 JWT `sub` 生成。需要审计旧字段一致性时再加
`--strict-user-id`。

脚本只解析 JWT 的 `exp`，不验证签名，也不向 Cursor 在线确认会话是否仍有效；候选值不
保证网页端一定接受。网页或 IDE 拒绝时，直接使用 Cursor 官方登录流程。

## 自测

```bash
python3 cursor-export-credential.py --self-test
```

自测只使用临时合成 SQLite/JWT，不读取真实 Cursor 数据库。

## 凭据安全

`--show-token` 会把完整的 session JWT 明文写到终端；它应按密码级秘密处理。不要把输出写进
聊天记录、工单、截图、CI 日志、云盘或代码仓库，也不要把源设备的 `state.vscdb` 一起分发。
脚本不会联网验证 token；网页端是否接受仍由 Cursor 服务端决定。若只需保存候选值，优先使用
`--output`（macOS/Linux 会创建 0600 文件），并在使用后及时删除或撤销凭据。
