# KrkrExtractV2 (For CxdecV2)
本md与代码为GPT4.5Codex编写，完善与提升软件功能
适用于 Wamsoft / KiriKiri Z Hxv4 2021.11+ 的动态工具集，提供以下功能：

- XP3 解包
- 运行时字符串 Hash 映射提取
- 运行时 Key 提取

## 环境

- 系统：Windows 7 SP1 x64 及以上
- IDE：Visual Studio 2022
- 编译器：MSVC 2022 x86

## 模块说明

- `CxdecExtractorLoader.exe`
  负责启动游戏并注入对应模块。
- `CxdecExtractor.dll`
  解包核心，定位游戏内部接口并执行 XP3 提取。
- `CxdecExtractorUI.dll`
  XP3 批量解包界面。
- `CxdecStringDumper.dll`
  运行时字符串 Hash 映射提取模块。
- `CxdecKeyDumper.dll`
  运行时 Key 提取模块。

## 当前功能

### 1. XP3 批量解包

- 支持一次拖入多个 `*.xp3` 文件排队解包。
- 支持持续追加任务，不需要等待当前任务结束后再继续拖入。
- 提供列表状态、总进度、单文件进度、成功/失败反馈。
- 支持自定义输出目录。
- 支持完成弹窗和完成提示音。
- 为了兼容宿主游戏运行时，当前采用“批量排队 + 单 worker 后台解包”模式，而不是单进程多线程并发解包。

默认输出目录：

```text
游戏目录\Extractor_Output\
```

输出内容包括：

- 解包后的纯哈希目录结构
- 与封包同名的 `.alst` 文件表
- `Extractor.log`
- `ExtractorUI.log`

### 2. 字符串 Hash 提取

运行时提取目录名和文件名的 Hash 映射，输出到：

```text
游戏目录\StringHashDumper_Output\
```

主要文件：

- `DirectoryHash.log`
- `FileNameHash.log`
- `Universal.log`

### 3. Key 提取

原生 C++ 版 Key 提取模块已经实现，不再依赖 Frida。

运行方式：

- 通过 `CxdecExtractorLoader.exe` 选择“加载Key提取模块”
- Loader 会显示提取进度条和百分比
- 提取完成后弹出确认框
- 点击确认后关闭 Loader 窗口

当前进度为阶段式进度：

- `0%`：等待提取开始
- `33%`：已抓到一组关键数据
- `66%`：已抓到两组关键数据
- `100%`：全部完成

默认输出目录：

```text
游戏目录\ExtractKey_Output\
```

输出文件：

- `key_output.txt`
  文本格式，尽量对齐 Frida 脚本输出风格
- `KeyInfo.log`
  详细日志
- `KeyInfo.json`
  结构化结果
- `control_block.bin`

`key_output.txt` 当前会输出：

- `load ... at ...`
- `hxpoint at ...`
- `cxpoint at ...`
- `* key : ...`
- `* nonce : ...`
- `* verify : ...`
- `* filterkey : ...`
- `* mask : ...`
- `* offset : ...`
- `* randtype : ...`
- `* order : ...`
- `* PrologOrder (garbro) : ...`
- `* OddBranchOrder (garbro) : ...`
- `* EvenBranchOrder (garbro) : ...`

## 使用方法

### 准备

将以下文件放在同一目录：

- `CxdecExtractorLoader.exe`
- `CxdecExtractor.dll`
- `CxdecExtractorUI.dll`
- `CxdecStringDumper.dll`
- `CxdecKeyDumper.dll`

同时确保：

- 目标游戏确实是 Wamsoft KrkrZ Hxv4 系列
- 游戏的加密认证已经移除
- 工具和游戏尽量不要放在受 UAC 严格保护的位置

### 解包 XP3

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 在 Loader 中点击“加载解包模块”
3. 在批量解包窗口中拖入一个或多个 `*.xp3`
4. 等待后台队列解包完成

### 提取字符串 Hash

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 点击“加载字符串Hash提取模块”
3. 正常运行游戏，让目标逻辑触发
4. 到 `StringHashDumper_Output` 查看结果

### 提取 Key

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 点击“加载Key提取模块”
3. 等待 Loader 中的进度条走到 `100%`
4. 确认完成提示
5. 到 `ExtractKey_Output` 查看结果

## 已知限制

- XP3 批量解包是队列化串行执行，不支持单进程内并发解包。
- 纯哈希封包本身不包含明文文件名，解包结果默认仍是纯哈希目录和文件名。
- 字符串 Hash 提取无法保证一次性覆盖游戏内所有路径和文件名，是否能抓到取决于运行路径。

## 同类工具推荐

- `KrkrExtractV2 (For CxdecV2)`（本工具）
  类型：动态
  说明：适合批量 XP3 解包、运行时字符串 Hash 提取、运行时 Key 提取。
- [KrkrDump](https://github.com/crskycode/KrkrDump)
  类型：动态
  说明：偏运行时导出思路，适合某些需要游戏运行态配合的场景。
- [GARbro](https://github.com/crskycode/GARbro)
  类型：静态
  说明：通用性强，但面对 Hxv4 / Cxdec 这类目标通常需要额外 key 和人工配置。
- [GARbro2](https://github.com/UserUnknownFactor/GARbro2)
  类型：静态
  说明：同样适合配合 key 使用，配置上通常比 GARbro 更直接一些。
- [krkr_hxv4_dumpkey.js](https://github.com/YuriSizuku/GalgameReverse/blob/master/project/krkr/src/krkr_hxv4_dumpkey.js)
  类型：Frida 脚本
  说明：适合做原始 key 抓取和结果对照；本项目现在已内置原生 Key 提取模块，但这个脚本仍然有参考价值，感谢大佬贡献。

## 相关文档

- [XP3 纯哈希解包技术分析](docs/xp3-pure-hash-analysis.md)

## 常见问题

### 为什么解包结果没有明文文件名

因为纯哈希封包内部本来就没有明文文件名，当前工具只能还原出哈希目录结构和哈希文件名。

### 批量解包为什么不是多线程并发

因为底层依赖宿主游戏运行时接口，单进程并发调用容易导致宿主崩溃。当前采用的是稳定优先的后台队列方案。

### Key 提取为什么做成原生 DLL 而不是 Frida

为了避免额外依赖 Frida / Python / Node 运行环境，并且更方便直接集成进现有 Loader 工作流。

### 兼容 Win7 以外的系统吗

理论上兼容更高版本 Windows，但主要以当前工程配置和 x86 目标为准。
