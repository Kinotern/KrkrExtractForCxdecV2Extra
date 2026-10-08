# KrkrExtractV2 (For CxdecV2)

本项目面向 Wamsoft / KiriKiri Z Hxv4 2021.11+ / CxdecV2 系列加密游戏，提供一套动态分析与资源整理工具。

主要功能：

- XP3 动态解包
- 运行时恢复 Hash 映射提取与资源名恢复
- Hook 撞库恢复 Hash 映射
- 静态 Key 参数提取（无需运行游戏，无需 Frida）
- 根据 `XP3 动态解包`、`运行时恢复 Hash 映射` 和 `Hook 撞库恢复 Hash 映射` 还原资源目录名、文件名和后缀。`实测成功率在90%以上`

## 环境

- 系统：Windows 7 SP1 x64 及以上，推荐 Windows 10 / Windows 11
- IDE：Visual Studio 2022
- 编译器：MSVC 2022
- 平台：x86 / Win32
- SDK：Windows 10 SDK 10.0.19041.0 或更新版本
- 存储空间：建议准备足够空间保存 `Extractor_Output`、`StringHashDumper_Output` 和恢复日志。

## 模块说明

- `CxdecExtractorLoader.exe`
  主加载器。负责启动目标游戏并注入对应模块，也内置资源文件名还原功能。

- `CxdecExtractor.dll`
  解包核心。定位游戏内部 Cxdec 接口并执行 XP3 资源提取。

- `CxdecExtractorUI.dll`
  XP3 批量解包界面。支持拖入多个 `*.xp3` 文件排队解包。

- `CxdecStringDumper.dll`
  运行时恢复 Hash 映射模块。用于记录明文目录名、文件名和 Hash 的对应关系，并可实时恢复纯 Hash 解包目录。

- `CxdecHashRestore.dll`
  Hook 撞库恢复 Hash 映射模块。用于按候选目录名、文件名批量计算 Hash，并补充 `HashRestore_RecoveredNames.lst`。

- `CxdecKeyStatic.dll`（静态密钥提取库）
  纯静态密钥提取模块。无需启动游戏、无需注入、无需 Frida/Python 等外部依赖。
  通过分析游戏 EXE 资源（TEXT/127、STARTUP.TJS、BOOTSTRAP DLL）和 FilterManager 派生，
  自动提取 HXV4 解密所需的完整密钥材料。

- `ExtractorOutputRestorer`
  Loader 早期内置的离线资源文件名还原功能。读取 `Extractor_Output` 和 `StringHashDumper_Output`，生成 `Restored_Extractor_Output`。当前更推荐使用运行时恢复 Hash 映射模块直接在 `Extractor_Output` 中实时恢复。

## 软电池游戏支持情况
LLLJ软电池版本经过测试，软件内置的调试模式，点击弹窗后会直接进入游戏开始界面，无需处理即可开始提取任务

## 当前功能

### 1. XP3 批量解包

- 支持一次拖入多个 `*.xp3` 文件排队解包。
- 支持持续追加任务，不需要等待当前任务结束后再继续拖入。
- 提供列表状态、总进度、单文件进度、成功/失败反馈。
- 支持自定义输出目录。
- 支持完成弹窗和完成提示音。
- 为了兼容宿主游戏运行时，当前采用"批量队列 + 单 worker 后台解包"模式，而不是单进程多线程并發解包。

默认输出目录：

```text
游戏目录\Extractor_Output\
```

输出内容包括：

- 解包后的 Hash 目录结构
- 与封包同名的 `.alst` 文件表

会话日志（`Extractor.log`、`ExtractorUI.log` 等）统一写在**工具目录下的 `Log\`**，不在游戏目录里，见下文「日志位置」。

### 2. 运行时恢复 Hash 映射

运行时提取目录名和文件名的 Hash 映射，并可对纯 Hash 解包目录进行实时恢复。Hash 映射输出到：

```text
游戏目录\StringHashDumper_Output\
```

主要文件：

- `DirectoryHash.log`
- `FileNameHash.log`
- `HashRestore_RecoveredNames.lst`

日志格式大致为：

```text
明文字符串#YSig##Hash
```

其中：

- `DirectoryHash.log` 用于还原目录名。
- `FileNameHash.log` 用于还原文件名和后缀。
- `Universal.log`（在工具目录 `Log\` 下）记录 Hash Seed、Salt 等辅助信息。
- `HashRestore_RecoveredNames.lst` 是跨运行时恢复和 Hook 撞库恢复共享的 `HASH:name` 映射表。

实时恢复窗口中只有一个主操作按钮：

```text
开始实时恢复 -> 停止实时恢复 -> 正在停止...
```

窗口会显示映射加载、纯 Hash 目录扫描、当前恢复文件、已恢复数量、剩余数量、失败数量和进度百分比。加载或恢复过程中会临时禁用目录选择和补充 lst 选择，避免多个恢复任务互相冲突。

### 3. Hook 撞库恢复 Hash 映射

Hook 撞库恢复模块用于批量补充 Hash 映射。它会先打开准备窗口，用户确认纯 Hash 目录、Hash 输出目录、候选表和可选补充 lst 后，再点击 `开始撞库` 启动游戏并注入 `CxdecHashRestore.dll`。

典型流程：

1. 选择纯 Hash 目录，通常是 `游戏目录\Extractor_Output`
2. 选择 Hash 输出目录，通常是 `游戏目录\StringHashDumper_Output`
3. 可选：选择补充 lst 映射
4. 制作或选择 `dirs_*.txt` / `files_*.txt` 候选表
5. 点击 `开始撞库`
6. 撞库结果直接追加到 `HashRestore_RecoveredNames.lst`

候选表和恢复映射格式详见 [Hash 恢复模块开发文档](docs/hash-restore-workflow.md)。

### 4. 静态 Key 提取（CxdecKeyStatic）

**全新的纯静态方案**，完全替代旧版 Frida 动态注入方案。无需启动游戏，无需注入进程。

通过 Loader 的 `静态提取Key` 按钮一键运行，自动完成以下流程：

1. 从游戏 EXE 中提取 TEXT/127 资源，获取 bres root key
2. 自动定位 bres salt（V2Link 标记 + TJS2100 验证）
3. 解密 STARTUP.TJS，提取 bootstrap URL 和 prefix
4. 解密并解压 BOOTSTRAP DLL
5. 解析 DLL 配置表（UNIQUE、WARNING、PARAMS）
6. LoadLibrary + FilterManager 原生调用派生 HXV4 密钥
7. 保存为 Rust 兼容的 drip_program.json/.bin + scheme.json

默认输出目录：

```text
游戏目录\ExtractKey_Output\
```

输出文件：

| 文件 | 说明 |
|------|------|
| `{exe名}_scheme.json` | 完整方案：bres key、bootstrap 参数、HXV4 密钥 |
| `{exe名}_drip_program.json` | 派生结果：hxv4_key、nonce0、nonce1、hash_key、VA 地址 |
| `{exe名}_drip_program.bin` | DRIP 二进制格式（holder_words + context_u32 + lanes） |
| `{exe名}_static_recover.summary.json` | 提取摘要 |

关键提取值：

- `hxv4_key`：32 字节，XP3 封包主解密密钥
- `hxv4_nonce0`：24 字节，nonce 参数 0
- `hxv4_nonce1`：24 字节，nonce 参数 1
- `hash_key`：32 字节，哈希密钥
- `startup_key`：bres 资源解密 key
- `bootstrap_key`：BOOTSTRAP DLL 解密 key

核心优势：

- **零依赖**：纯 C++ 实现，无需 Frida / Python / .NET 运行时
- **离线运行**：不启动游戏，不注入进程
- **全自动**：salt 自动定位、key 自动提取、输出格式标准化
- **可集成**：编译为DLL（CxdecKeyStatic.dll），可通过LoadLibrary动态加载到其他项目

### 5. 离线资源文件名还原

纯 Hash XP3 解包后，资源通常会以 Hash 目录和 Hash 文件名形式输出，例如：

```text
Extractor_Output\package_name\目录Hash\文件名Hash
```

如果已经通过运行时恢复 Hash 映射模块获得：

```text
StringHashDumper_Output\DirectoryHash.log
StringHashDumper_Output\FileNameHash.log
```

则可以在 Loader 中点击：

```text
还原资源文件名
```

工具会读取两边数据，并输出到：

```text
游戏目录\Restored_Extractor_Output\
```

还原完成后会弹出中文统计结果，包括：

- 总文件数
- 成功还原数
- 成功率
- 缺少目录 Hash 数
- 缺少文件名 Hash 数
- 复制失败数
- 各个顶层目录的还原情况

同时会生成详细报告：

```text
游戏目录\Restored_Extractor_Output\RestoreReport.txt
```

如果还原成功率不高，通常是 `FileNameHash.log` 或 `HashRestore_RecoveredNames.lst` 收集不完整。可以重新运行 `加载运行时恢复Hash映射模块`，或使用 `加载Hook撞库恢复Hash映射模块` 根据候选表批量补充映射。

## 使用方法

### 准备

发布目录使用 Loader + 模块 DLL 目录结构：
```
Release\
  CxdecExtractorLoader.exe
  CxdecExtractordll\
    CxdecExtractor.dll
    CxdecExtractorUI.dll
    CxdecStringDumper.dll
    CxdecHashRestore.dll
    CxdecKeyStatic.dll
```

Loader 会优先从自身目录下的 `CxdecExtractordll\` 子目录加载模块 DLL，便于后续继续扩展独立模块。
同时确保：

- 目标游戏确实是 Wamsoft / KiriKiri Z / Hxv4 / CxdecV2 系列
- 游戏的加壳认证已经移除或可以正常进入资源加载流程
- 工具和游戏尽量不要放在受 UAC 严格保护的位置

### 解包 XP3

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 在 Loader 中点击 `加载解包模块`
3. 在批量解包窗口中拖入一个或多个 `*.xp3`
4. 等待后台队列解包完成
5. 查看 `Extractor_Output`

### 运行时恢复 Hash 映射

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 点击 `加载运行时恢复Hash映射模块`
3. 在弹出的恢复窗口中确认纯 Hash 目录和补充 lst 映射
4. 点击 `开始实时恢复`
5. 正常运行游戏，让目标逻辑和资源加载路径尽量多地触发
6. 查看 `StringHashDumper_Output` 和 `Extractor_Output\Extractor_Log`

### 静态提取 Key

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 点击 `静态提取Key`
3. 等待弹出"Key 提取成功"提示
4. 查看 `ExtractKey_Output`

### 还原资源文件名

1. 先完成 XP3 解包，确保存在 `Extractor_Output`
2. 再运行运行时恢复 Hash 映射或 Hook 撞库恢复，确保存在 `StringHashDumper_Output`
3. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
4. 点击 `还原资源文件名`
5. 查看 `Restored_Extractor_Output`
6. 查看 `Restored_Extractor_Output\RestoreReport.txt`

## 日志位置

所有会话日志统一写在 **`loader.exe` 所在目录下的 `Log\`**：

```text
工具目录\Log\
  CxdecExtractorLoader.log
  Extractor.log
  ExtractorUI.log
  KeyInfo.log
  Universal.log
  HashCrack.log
  RuntimeHashRestore.log
  HashRestore.log
  HashRestore_Unresolved.log
  CxdecAntiMalform.log
```

- 各功能模块的 DLL 通常在 `CxdecExtractordll\` 下，会自己上跳一级定位到工具目录，所以不管哪个模块写，落点都一样。
- 工具目录写不了（例如装在 `Program Files` 下）时，退到 `%LOCALAPPDATA%\KrkrExtract\Log\`，最终位置和原因写在日志开头。
- 编码统一 UTF-8。行格式固定为 `时间 | 级别 | 线程 | 正文`：

  ```text
  2026-10-08 21:01:09 | E | T51FC | Write Failed: data\5E5F…\41D9… | stage=Open | …
  ```

  级别是 `I`/`W`/`E`（`D` 为调试，默认不写）。解包是多个线程并行跑的，`T` 后面的线程号能区分"同一个域一直失败"还是"几个线程各失败一次"。日志很大时直接搜 `| E |` 就能只看真正的失败。
- 会话日志保留上一代（`.1`）：重跑一次不会把上一次的失败现场抹掉。
- 单个日志的**日志行**有 32 MiB 上限，超过后只留一条提示就不再写（防止日志自己把盘写满）。哈希映射库那类数据写入不受此限。

注意区分**产物**与日志——下面这些虽然也叫 `.log`，但会被后续流程读回去，所以留在各自的输出目录里，不随日志搬家：

- `StringHashDumper_Output\DirectoryHash.log`
- `StringHashDumper_Output\FileNameHash.log`
- `Extractor_Output\Extractor_Log\HashRestore_Report.tsv`
- `StringHashDumper_Output\HashRestore_RecoveredNames.lst`

## 构建方法

推荐使用 Visual Studio 2022 的开发者命令行：

```bat
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x86 -host_arch=x86
msbuild KrkrZCxdecV2.sln /p:Configuration=Release /p:Platform=x86 /m
```

生成结果位于：
```text
Release\
  CxdecExtractorLoader.exe
  CxdecExtractordll\
    CxdecExtractor.dll
    CxdecExtractorUI.dll
    CxdecStringDumper.dll
    CxdecHashRestore.dll
    CxdecKeyStatic.dll
    CxdecKeyDumper.dll
    CxdecRepacker.dll
    CxdecAntiMalform.dll
    CxdecPeUnpacker.dll
    CxdecCli.exe
```

也可以直接使用 PowerShell 调用 MSBuild：

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe' 'O:\Github\KrkrExtractForCxdecV2Extra\cangku\KrkrExtractForCxdecV2Extra\KrkrZCxdecV2.sln' /p:Configuration=Release /p:Platform=x86 /m
```

## 开发调试命令行（CxdecCli.exe）

`CxdecExtractordll\CxdecCli.exe` 是不用点界面的调试入口，把**可以离线跑**的那几件事
直接走一遍，方便写脚本回归。它按自己的模块目录去找 `CxdecRepacker.dll` /
`CxdecKeyStatic.dll`，所以**必须和它们放在同一个目录**。退出码：`0` 成功、`1` 失败、`2` 用法错误。

```text
CxdecCli sniff <目录>                    判定目录形态（模式 1/2/3），不打包
CxdecCli repack <目录> <输出.xp3> [选项]  目录封成 XP3
    --exe <游戏.exe>    按这个 EXE 查参数仓库；仓库里没有就现场派生
    --keys <目录>       参数仓库根目录（默认 <工具目录>\keys）
    --media-name <盐>   覆盖盐，只在派生的那套不对时才用
    --mode <1|2|3>      覆盖嗅探结果
    --rescramble        把干净文本搅回加扰形态
CxdecCli keys <游戏.exe> [--keys <目录>]  只派生/收编参数，不打包
CxdecCli importkey <参数文件.hxv4p> [--exe X] [--keys X]
CxdecCli nextrev <游戏目录>               下一个可用的 patch@r<N> 修订号
CxdecCli keystatic <游戏.exe> [--out <目录>]  调 CxdecKeyStatic 做静态 Key 提取
CxdecCli cmp <文件A> <文件B>              逐字节比对，只报首个差异偏移
```

需要游戏进程才成立的功能（解包、运行时 Hash 映射、Hook 撞库）**不在**这个工具里——那些必须由
Loader 注入游戏进程执行。

`cmp` 是封包复刻验证的常用手段：同一份输入封两次应当逐字节一致；与原件比对时它会报出首个差异偏移，
例如 `首个差异：偏移 950（0x3B6）  A=13 B=15`，直接就能定位到出问题的那一段。

## 已知限制

- XP3 批量解包是队列化串行执行，不支持单进程内并發解包。
- 纯 Hash 封包本身不包含明文文件名，解包结果默认仍是 Hash 目录和 Hash 文件名。
- 运行时恢复 Hash 映射无法保证一次性覆盖游戏内所有路径和文件名，是否能抓到取决于运行路径。
- Hook 撞库恢复依赖候选表质量；候选名越接近真实资源路径，补充效果越好。
- 资源文件名还原依赖 `DirectoryHash.log`、`FileNameHash.log` 和 `HashRestore_RecoveredNames.lst` 的完整度。
- 若复制失败，可能与路径过长、非法文件名、文件占用或权限有关。
- **静态 Key 提取**：RVA 常量（0x0E2D0 等）为当前分析的游戏样本值，不同游戏版本可能需要调整 `GameParams` 中的 RVA 参数。

## 同类工具参考

- [GARbro](https://github.com/crskycode/GARbro)
  静态通用工具，面对 Hxv4 / Cxdec 目标时通常需要额外 key 和手工配置。

- [GARbro2](https://github.com/UserUnknownFactor/GARbro2)
  静态工具，适合配合 key 使用，配置上通常比 GARbro 更直接一些。

## 免责声明

本项目仅用于学习研究、兼容性分析、个人合法备份、汉化与资源修复等合规场景。请勿将本项目用于侵犯版权、绕过授权、传播商业游戏资源、盗利分发或其他违反当地法律法规的用途。使用者应自行确认其使用行为具备合法授权，并自行承担由使用、修改、编译或分发本项目产生的风险与责任。

本项目不提供商业游戏资源、解密后的成品资源或任何第三方专有内容。仓库只发布源码和必要的工程文件；如需使用可执行文件，建议使用者自行从源码编译，并在运行前使用可信安全软件或沙箱环境进行检查。

请谨慎使用来源不明的第三方二进制文件。历史上社区中曾出现过与 Cxdec / Hxv4 相关工具编译发布版本被报告携带恶意载荷或异常行为的讨论，相关分析可参考：

https://www.kungal.com/topic/3596

该链接仅作为安全风险提示和背景资料，不代表本项目对第三方仓库、作者或文件作出最终安全鉴定。对任何第三方 Release、压缩包、加壳程序或闭源可执行文件，建议优先选择源码构建、校验哈希、使用虚拟机测试，并避免在生产环境或存有敏感资料的主机上直接运行。

本项目后续会继续以源码透明、可复现构建和安全自查为原则进行维护。


## 致谢

- [cxdec-hxv4-static-analysis](https://github.com/hktkqj/cxdec-hxv4-static-analysis)  
  提供了 Hxv4 静态分析的完整技术文档和 Python 参考实现，本项目 CxdecKeyStatic 模块的 FilterManager 派生流程和 TJS2 解析逻辑参考了其分析成果。


