<div align="center">

# 🔍 InvisiScan

**看不见的字，看得见的危险。**

零依赖的 Unicode 安全扫描器 —— 揪出隐形字符、Trojan Source 双向控制符与同形异义标识符。

[![CI](https://github.com/invisiscan/invisiscan/actions/workflows/ci.yml/badge.svg)](https://github.com/invisiscan/invisiscan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://github.com/invisiscan/invisiscan/blob/main/pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

**简体中文** · [繁體中文](#繁體中文) · [English](#english)

</div>

---

## 简体中文

### 🎉 项目介绍

在代码审查中，**你看到的代码不一定是编译器看到的代码**。

2021 年，剑桥大学的研究者公布了 Trojan Source 攻击（CVE-2021-42574）：往源码里插入几个 Unicode 双向控制字符（如 `U+202E`），在人眼看来是一段无害的注释，编译器却会按完全不同的逻辑解析。这类缺陷不会让单元测试变红、不会触发 linter，却能轻松绕过代码审查 —— 而它之所以能神不知鬼不觉地穿过防线，正是因为它**不占任何可见宽度**。

`InvisiScan` 就是为这一整类威胁而生：

- 🕵️ **隐形字符**：零宽空格、`.join一样对 legitimateесли` U+200B 这类看不见却能塞进标识符的字符
- 🔀 **Trojan Source**：能让代码显示顺序与解析顺序背离的双向控制符
- 📦 **隐藏载荷**：可把任意 ASCII 字节编码成「不可见」的 Unicode 标签字符
- 🎭 **同形异义**：冒充 `admin` 的西里尔字母 `аdmin`
- 🫥 **伪装空格**：长得像空格、却能摧毁一切 `==` 比较和 diff 的字符

**为什么还需要一个新的工具？** 现有方案要么依赖庞大的第三方库、要么只覆盖其中一两类问题、要么输出格式无法接入 CI。`InvisiScan` 的取舍很明确：

> **零第三方依赖 + 11 类规则全覆盖 + SARIF 原生输出 + 行级抑制 + 毫秒级扫描。**

#### ✨ 自研差异化亮点

| 能力 | InvisiScan 的做法 | 常见替代方案 |
| --- | --- | --- |
| 🎯 **覆盖广度** | 11 条分级规则（IS001–IS011）+ 词级同形异义 | 通常只查 bidi 或只查零宽 |
| 📊 **SARIF 2.1.0** | 原生输出，直传 GitHub Security 面板 | 多数工具只有自定义文本格式 |
| 🧠 **词级 skeleton** | 基于 UTS#39 对**标识符**做视觉归并，可跨文件配对 | 多为逐字符比对，误报极高 |
| 🔇 **行级抑制** | `# invisiscan:ignore=IS002` | 通常只支持整文件忽略 |
| 📦 **零依赖** | 纯标准库，随 Python 装好就能跑 | 往往拖着一堆间接依赖 |
| ⚡ **性能** | 10 万行约 1.7 秒（实测 4.5 MB 样本） | —— |

灵感来源: Unicode 标准附件 UAX #9 / UAX #15 / UAX #31 / UTS #39，以及 CVE-2021-42574、CVE-2021-42694 两则安全公告。

### ✨ 核心特性

- 🔍 **11 条分级规则** —— 每张笑脸、从 `IS001` 双向控制符到 `IS011` 非字符，按 `critical / high / medium / low` 四级定责
- 🎭 **同形异义检测（IS010）** —— 用 UTS#39 skeleton 把看起来一样的标识符归并成组，**并支持跨文件配对**
- 🚩 **SARIF 2.1.0 输出** —— `--format sarif`，一键传到 GitHub Security 面板，与 CodeQL 同屏展示
- 🔇 **行级抑制** —— `# invisiscan:ignore` 或 `# invisiscan:ignore=IS002,IS007`
- 🎚️ **灵活过滤** —— `--severity` 阈值、`--rule` 白名单、`--ignore` 黑名单、`--exclude` 路径
- 📥 **stdin 支持** —— `git diff | invisiscan --stdin`，天然适合 pre-commit
- 🤖 **CI 友好退出码** —— `0` 干净、`1` 有发现、`2` 执行错误
- 🐍 **零第三方依赖** —— 只用标准库，Python 3.9+
- 🌍 **自证清白** —— 自己的源码对自己零告警（见下方 CI 中的 self-scan）

#### 📋 规则总览

| ID | 类别 | 等级 | 说明 |
| --- | --- | --- | --- |
| `IS001` | `bidi-control` | 🔴 critical | 双向嵌入/覆写/隔离符（Trojan Source） |
| `IS002` | `zero-width` | 🟠 high | 零宽字符、BOM、软连字符 |
| `IS003` | `invisible-operator` | 🟠 high | 隐形数学运算符 |
| `IS004` | `tag-character` | 🔴 critical | 可编码隐藏载荷的标签字符 |
| `IS005` | `bidi-mark` | 🟡 medium | LRM / RLM 方向标记 |
| `IS006` | `variation-selector` | 🟢 low | 变体选择符滥用 |
| `IS007` | `space-lookalike` | 🟡 medium | NBSP、全角空格等伪空格 |
| `IS008` | `deprecated-codepoint` | 🟢 low | 已弃用控制符 |
| `IS009` | `bidi-pop-format` | 🟢 low | 孤立的 PDF / PDI |
| `IS010` | `confusable-identifier` | 🟠 high | 同形异义标识符配对 |
| `IS011` | `noncharacter` | 🟡 medium | 非字符 / 私用区码点 |

### 🚀 快速开始

#### 环境要求

- **Python 3.9 或更高版本**（仅标准库，无其他依赖）
- 支持 Linux / macOS / Windows

#### 安装

```bash
# 从源码安装（推荐，可立即获得 invisiscan 命令）
pip install .

# 开发模式（含测试依赖）
pip install -e ".[dev]"

# 不安装也能跑
python -m invisiscan --help
```

#### 三秒钟上手

```bash
# 扫描当前目录
invisiscan .

# 扫描单个文件
invisiscan src/main.py

# 只看最危险的问题
invisiscan . --severity critical

# 输出 SARIF 交给 GitHub
invisiscan . --format sarif > results.sarif
```

**正常输出示例：**

```text
src/auth.py  (42 line(s), max severity: critical)
  [CRITICAL] 7:23 IS001 (bidi-control)              U+202E '<invisible>'
  [HIGH] 15:9  IS002 (zero-width)                   U+200B '<invisible>'
  [MEDIUM] 22:4 IS007 (space-lookalike)             U+00A0 ' '
  [HIGH] IS010 (confusable-identifier) skeleton='admin' variants=[admin, аdmin]

------------------------------------------------------------------------
Scanned 128 file(s), 1 file(s) with findings, 4 total finding(s)
  critical: 1   high: 2   medium: 1   low: 0
```

### 📖 详细使用指南

#### 命令行参数

| 参数 | 作用 | 示例 |
| --- | --- | --- |
| `paths` | 要扫描的文件或目录（默认 `.`） | `invisiscan src tests` |
| `-f, --format` | `text`（默认）/ `json` / `sarif` | `--format json` |
| `--severity` | 最低报告等级：`critical`/`high`/`medium`/`low` | `--severity high` |
| `--rule ID` | 只报告指定规则（可重复） | `--rule IS001 --rule IS004` |
| `--ignore ID` | 屏蔽指定规则（可重复） | `--ignore IS006` |
| `--no-confusables` | 关闭 IS010 同形异义检测 | `--no-confusables` |
| `--min-word-length N` | 参与 IS010 的最短词长（默认 3） | `--min-word-length 5` |
| `--extension EXT` | 追加扫描扩展名（可重复） | `--extension .proto` |
| `--exclude PATTERN` | 跳过含该子串的路径（可重复） | `--exclude vendor` |
| `--stdin` | 读标准输入而非文件 | `cat f.py \| invisiscan --stdin` |
| `--stdin-name` | stdin 结果中显示的文件名 | `--stdin-name policy.yaml` |
| `-q, --quiet` | 不打印汇总尾廊 |  |
| `-V, --version` | 显示版本 |  |

#### 典型场景

**① 把它接进 GitHub Actions（推荐）**

```yaml
- name: Unicode safety scan
  run: |
    pip install -e .
    invisiscan . --format sarif --exclude .git > results.sarif || true

- name: Upload to Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

> 💡 仓库 `.github/workflows/invisiscan.yml` 里有一份可直接复制的完整版本。

**② 作为 pre-commit 钩子**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: invisiscan
        name: InvisiScan
        entry: invisiscan --severity high
        language: system
        types: [text]
```

**③ 只检查本次改动**

```bash
git diff --name-only origin/main...HEAD | xargs invisiscan --severity high
```

**④ 抑制合理的告警**

```python
LEGACY_TOKEN = "abc​def"   # invisiscan:ignore=IS002

# 数据fixture 里刻意放的同形异义词
pair = ("аdmin", "admin")  # invisiscan:ignore=IS010

# 整行全部规则都豁免
raw = snarfle("a​b")  # invisiscan:ignore
```

> ⚠️ 抑制注释只对**所在行**生效，这样审计时任何豁免都是局部且可见的。

**⑤ Python API**

```python
from invisiscan import Scanner

scanner = Scanner(min_severity="high")
result = scanner.scan_file(Path("src/main.py"))

for finding in result.findings:
    print(f"{finding.line}:{finding.column} [{finding.severity}] {finding.describe()}")

# 多文件时，词级同形异义需在全部扫描完成后统一归集
results = [scanner.scan_file(p) for p in files]
scanner.distribute_confusables(results)
```

> 📌 注意：`confusables` 是**跨文件**归集的，因此单个 `scan_text` / `scan_file` 不会自动填充该字段，请在处理完所有目标后调用 `distribute_confusables(results)`。

#### 🙂 退出码

| 码 | 含义 | 典型 CI 处理 |
| --- | --- | --- |
| `0` | 干净，没有发现 | 通过 |
| `1` | 存在符合阈值的问题 | 视分支策略决定是否阻断 |
| `2` | 执行错误（路径不存在、无匹配文件等） | 视为流水线失败 |

### 💡 设计思路与迭代规划

#### 设计取舍

- **覆盖广度优先于语法感知**。InvisiScan 不解析 AST，因此与语言无关 —— 同一套引擎能扫 Python、Go、Rust、YAML 乃至 Markdown。代价是不能区分「注释里的 bidi」和「字符串里的 bidi」；好在两者都不该出现在代码里。
- **`\n` 而不是 `splitlines()`**。Python 的 `str.splitlines()` 会把 `U+2028`/`U+2029` 也当成换行符，恰好吞掉我们要抓的目标。这是开发过程中真实踩到的坑，现已由回归测试锁住。
- **BOM 不做剥离**。直接按 UTF-8 解码，`U+FEFF` 留在文本里由 `IS002` 在第 1 列报出，报告的列号与编辑器跳转位置天然一致。
- **SSkeleton 表宁缺毋滥**。宁可漏掉一个生僻的变体，也不要把一段正常的希腊文误报成攻击 —— 安全工具一旦噪音过大就会被 `--ignore` 掉，等于失效。
- **只在真正含非 ASCII 变体的文件报 IS010**。纯 ASCII 文件只是参照，会列在分组信息里，但不会自身产生告警。

#### 迭代规划

- [ ] 🌐 接入 UTS#39 官方完整 confusables 数据集
- [ ] 🧩 `--fix` 自动净化模式（安全移除隐形字符并写回）
- [ ] 📜 支持 `.invisiscanignore` 配置文件
- [ ] 🧪 增加 `--fail-on <level>` 精细门控
- [ ] 🔤 标识符 Ada IANA 国际化域名（IDN）专项规则
- [ ] 🖥️ 交互式 TUI 逐个确认修复

### 📦 打包与部署指南

本项目属于**命令行工具 / 工具库**类型，因此**不发布 Release 附件**，而是提供标准的 Python 分发物与免依赖单文件包。

```bash
# 方式一：标准 wheel + sdist
./scripts/build.sh
pip install dist/*.whl

# 方式二：单文件 zipapp（目标机器只需 python3，无需 pip）
./scripts/build.sh bundle
python3 dist/invisiscan.pyz --help
```

| 目标 | 命令 | 产物 |
| --- | --- | --- |
| wheel / sdist | `make build` | `dist/invisiscan-1.0.0-py3-none-any.whl` |
| 单文件可执行 zipapp | `make bundle` | `dist/invisiscan.pyz` |
| 本地全量校验 | `make verify` | 测试 + 自扫描 |

**部署到 CI 的最小镜像：**

```dockerfile
FROM python:3.12-alpine
COPY dist/invisiscan-1.0.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl
ENTRYPOINT ["invisiscan"]
```

> ℹ️ `alpine` 镜像需确保 locale 支持 UTF-8；扫描器解码失败时会明确报 `UnicodeDecodeError` 而非静默跳过。

### 🤝 贡献指南

欢迎 PR！请遵守：

1. **提交规范** —— 采用 Angular 风格：`feat: ...` / `fix: ...` / `docs: ...` / `refactor: ...` / `test: ...`
2. **必须加测试** —— 新增规则请同时补充正向（恶意样本命中）与反向（正常文本不误报）用例
3. **保持零依赖** —— 运行时不得引入任何第三方包
4. **本地自检** —— 提交前运行 `make verify`（含 `pytest` 与自扫描）

提交 Issue 时请附上：最小复现文本、`--format json` 的输出、`invisiscan --version` 与 Python 版本。

### 📄 开源协议

本项目采用 **[MIT License](./LICENSE)**。你可以自由使用、修改和分发，包括商业用途。

---
---

## 繁體中文

### 🎉 專案介紹

在程式碼審查時，**你看到的程式碼不一定是編譯器看到的程式碼**。

2021 年，劍橋大學研究團隊公開了 Trojan Source 攻擊手法（CVE-2021-42574）：只要在原始碼中插入幾個 Unicode 雙向控制字元（如 `U+202E`），人眼看到的是一段無害的註解，編譯器卻會依照完全不同的邏輯執行。這類缺陷不會讓單元測試亮紅燈、不會觸發 linter，卻能在安全的第二象限輕鬆越過防線 —— 而它之所以能穿過去，正是因為它**完全不佔任何可見寬度**。

`InvisiScan` 正是為了這整類威脅而生：

- 🕵️ **隱形字元**：零寬空格這類看不見、卻能被塞進識別字裡的字元
- 🔀 **Trojan Source**：讓顯示順序與解析順序背離的雙向控制符
- 📦 **隱藏酬載**：可將任意 ASCII 位元組編碼成「不可見」的 Unicode 標籤字元
- 🎭 **同形異義**：冒充 `admin` 的西里爾字母 `аdmin`
- 🫥 **偽裝空格**：長得像空格、卻能摧毀所有 `==` 比較與 diff 的字元

**為什麼還需要一個新工具？** 現有方案往往依賴龐大的第三方套件、只覆蓋其中一兩類問題，或輸出格式無法銜接 CI。`InvisiScan` 的取捨十分明確：

> **零第三方依賴 + 11 類規則全覆蓋 + SARIF 原生輸出 + 行級抑制 + 毫秒級掃描。**

#### ✨ 自研差異化亮點

| 能力 | InvisiScan 的做法 | 常見替代方案 |
| --- | --- | --- |
| 🎯 **覆蓋廣度** | 11 條分級規則（IS001–IS011）+ 詞級同形異義 | 通常只查 bidi 或只查零寬 |
| 📊 **SARIF 2.1.0** | 原生輸出，直送 GitHub Security 面板 | 多數工具只有自訂文字格式 |
| 🧠 **詞級 skeleton** | 依 UTS#39 對**識別字**做視覺歸併，可跨檔案配對 | 多為逐字元比對，誤報極高 |
| 🔇 **行級抑制** | `# invisiscan:ignore=IS002` | 通常只支援整檔忽略 |
| 📦 **零依賴** | 純標準函式庫，裝好 Python 即可執行 | 往往拖著一堆間接依賴 |
| ⚡ **效能** | 十萬行約 1.7 秒（實測 4.5 MB 樣本） | —— |

靈感來源：Unicode 標準附件 UAX #9 / UAX #15 / UAX #31 / UTS #39，以及 CVE-2021-42574、CVE-2021-42694 兩則安全公告。

### ✨ 核心特性

- 🔍 **11 條分級規則** —— 從 `IS001` 雙向控制符到 `IS011` 非字元，按 `critical / high / medium / low` 四級究責
- 🎭 **同形異義偵測（IS010）** —— 以 UTS#39 skeleton 將外觀相同的識別字歸組，**並支援跨檔案配對**
- 🚩 **SARIF 2.1.0 輸出** —— `--format sarif`，一鍵上傳 GitHub Security 面板，與 CodeQL 並列顯示
- 🔇 **行級抑制** —— `# invisiscan:ignore` 或 `# invisiscan:ignore=IS002,IS007`
- 🎚️ **彈性過濾** —— `--severity` 門檻、`--rule` 白名單、`--ignore` 黑名單、`--exclude` 路徑
- 📥 **stdin 支援** —— `git diff | invisiscan --stdin`，天生適合 pre-commit
- 🤖 **CI 友善結束碼** —— `0` 乾淨、`1` 有發現、`2` 執行錯誤
- 🐍 **零第三方依賴** —— 僅用標準函式庫，Python 3.9+
- 🌍 **自證清白** —— 自己的原始碼對自己零告警（見 CI 中的 self-scan）

#### 📋 規則總覽

| ID | 類別 | 等級 | 說明 |
| --- | --- | --- | --- |
| `IS001` | `bidi-control` | 🔴 critical | 雙向嵌入／覆寫／隔離符（Trojan Source） |
| `IS002` | `zero-width` | 🟠 high | 零寬字元、BOM、軟連字號 |
| `IS003` | `invisible-operator` | 🟠 high | 隱形數學運算子 |
| `IS004` | `tag-character` | 🔴 critical | 可編碼隱藏酬載的標籤字元 |
| `IS005` | `bidi-mark` | 🟡 medium | LRM / RLM 方向標記 |
| `IS006` | `variation-selector` | 🟢 low | 變體選擇符濫用 |
| `IS007` | `space-lookalike` | 🟡 medium | NBSP、全形空格等偽空格 |
| `IS008` | `deprecated-codepoint` | 🟢 low | 已棄用控制符 |
| `IS009` | `bidi-pop-format` | 🟢 low | 孤立的 PDF / PDI |
| `IS010` | `confusable-identifier` | 🟠 high | 同形異義識別字配對 |
| `IS011` | `noncharacter` | 🟡 medium | 非字元／私用區碼點 |

### 🚀 快速開始

#### 環境需求

- **Python 3.9 以上**（僅標準函式庫，無其他依賴）
- 支援 Linux / macOS / Windows

#### 安裝

```bash
# 從原始碼安裝（建議，可立即取得 invisiscan 指令）
pip install .

# 開發模式（含測試依賴）
pip install -e ".[dev]"

# 不安裝也能執行
python -m invisiscan --help
```

#### 三秒上手

```bash
# 掃描目前目錄
invisiscan .

# 掃描單一檔案
invisiscan src/main.py

# 只看最危險的問題
invisiscan . --severity critical

# 輸出 SARIF 交給 GitHub
invisiscan . --format sarif > results.sarif
```

**正常輸出範例：**

```text
src/auth.py  (42 line(s), max severity: critical)
  [CRITICAL] 7:23 IS001 (bidi-control)              U+202E '<invisible>'
  [HIGH] 15:9  IS002 (zero-width)                   U+200B '<invisible>'
  [MEDIUM] 22:4 IS007 (space-lookalike)             U+00A0 ' '
  [HIGH] IS010 (confusable-identifier) skeleton='admin' variants=[admin, аdmin]

------------------------------------------------------------------------
Scanned 128 file(s), 1 file(s) with findings, 4 total finding(s)
  critical: 1   high: 2   medium: 1   low: 0
```

### 📖 詳細使用指南

#### 命令列參數

| 參數 | 作用 | 範例 |
| --- | --- | --- |
| `paths` | 要掃描的檔案或目錄（預設 `.`） | `invisiscan src tests` |
| `-f, --format` | `text`（預設）／`json`／`sarif` | `--format json` |
| `--severity` | 最低報告等級：`critical`/`high`/`medium`/`low` | `--severity high` |
| `--rule ID` | 只報告指定規則（可重複） | `--rule IS001 --rule IS004` |
| `--ignore ID` | 遮蔽指定規則（可重複） | `--ignore IS006` |
| `--no-confusables` | 關閉 IS010 同形異義偵測 | `--no-confusables` |
| `--min-word-length N` | 參與 IS010 的最短詞長（預設 3） | `--min-word-length 5` |
| `--extension EXT` | 追加掃描副檔名（可重複） | `--extension .proto` |
| `--exclude PATTERN` | 跳過含該字串的路徑（可重複） | `--exclude vendor` |
| `--stdin` | 讀標準輸入而非檔案 | `cat f.py \| invisiscan --stdin` |
| `--stdin-name` | stdin 結果中顯示的檔名 | `--stdin-name policy.yaml` |
| `-q, --quiet` | 不列印彙總尾廊 |  |
| `-V, --version` | 顯示版本 |  |

#### 典型情境

**① 接進 GitHub Actions（建議）**

```yaml
- name: Unicode safety scan
  run: |
    pip install -e .
    invisiscan . --format sarif --exclude .git > results.sarif || true

- name: Upload to Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

> 💡 儲存庫 `.github/workflows/invisiscan.yml` 中有一份可直接複製的完整版本。

**② 作為 pre-commit 鉤子**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: invisiscan
        name: InvisiScan
        entry: invisiscan --severity high
        language: system
        types: [text]
```

**③ 只檢查本次變更**

```bash
git diff --name-only origin/main...HEAD | xargs invisiscan --severity high
```

**④ 抑制合理的告警**

```python
LEGACY_TOKEN = "abc​def"   # invisiscan:ignore=IS002

# 資料 fixture 中刻意放置的同形異義詞
pair = ("аdmin", "admin")  # invisiscan:ignore=IS010

# 整行全部規則皆豁免
raw = snarfle("a​b")  # invisiscan:ignore
```

> ⚠️ 抑制註解僅對**該行**生效，因此稽核時每一個豁免都是局部且可見的。

**⑤ Python API**

```python
from invisiscan import Scanner

scanner = Scanner(min_severity="high")
result = scanner.scan_file(Path("src/main.py"))

for finding in result.findings:
    print(f"{finding.line}:{finding.column} [{finding.severity}] {finding.describe()}")

# 多檔案時，詞級同形異義需在全部掃描完成後統一歸集
results = [scanner.scan_file(p) for p in files]
scanner.distribute_confusables(results)
```

> 📌 注意：`confusables` 是**跨檔案**歸集的，因此單一 `scan_text` / `scan_file` 不會自動填入該欄位，請在處理完所有目標後呼叫 `distribute_confusables(results)`。

#### 🙂 結束碼

| 碼 | 意義 | 典型 CI 處理 |
| --- | --- | --- |
| `0` | 乾淨，沒有發現 | 通過 |
| `1` | 存在符合門檻的問題 | 視分支策略決定是否阻斷 |
| `2` | 執行錯誤（路徑不存在、無符合檔案等） | 視為管線失敗 |

### 💡 設計思路與迭代規劃

#### 設計取捨

- **覆蓋廣度優先於語法感知**。InvisiScan 不解析 AST，因此與語言無關 —— 同一套引擎能掃 Python、Go、Rust、YAML 乃至 Markdown。代價是無法區分「註解裡的 bidi」與「字串裡的 bidi」；所幸兩者都不該出現在程式碼裡。
- **用 `\n` 而非 `splitlines()`**。Python 的 `str.splitlines()` 會把 `U+2028`/`U+2029` 也視為換行符，恰好吞掉我們要抓的目標。這是開發過程中真實踩到的坑，現已由迴歸測試鎖住。
- **BOM 不做剝離**。直接以 UTF-8 解碼，`U+FEFF` 留在文字中由 `IS002` 在第 1 欄回報，報告的欄位與編輯器跳轉位置天然一致。
- **Skeleton 表寧缺毋濫**。寧可漏掉一個生僻變體，也不要把一段正常的希臘文誤報成攻擊 —— 安全工具一旦噪音過大就會被 `--ignore` 掉，等於失效。
- **只在真正含非 ASCII 變體的檔案回報 IS010**。純 ASCII 檔案只是參照，會列在分組資訊中，但不會自身產生告警。

#### 迭代規劃

- [ ] 🌐 接入 UTS#39 官方完整 confusables 資料集
- [ ] 🧩 `--fix` 自動淨化模式（安全移除隱形字元並寫回）
- [ ] 📜 支援 `.invisiscanignore` 設定檔
- [ ] 🧪 增加 `--fail-on <level>` 精細門控
- [ ] 🔤 識別字與 IDN 國際化網域名稱專項規則
- [ ] 🖥️ 互動式 TUI 逐筆確認修復

### 📦 打包與部署指南

本專案屬於**命令列工具／工具庫**類型，因此**不發布 Release 附件**，而是提供標準的 Python 散佈檔與免依賴單檔套件。

```bash
# 方式一：標準 wheel + sdist
./scripts/build.sh
pip install dist/*.whl

# 方式二：單檔 zipapp（目標機器只需 python3，無須 pip）
./scripts/build.sh bundle
python3 dist/invisiscan.pyz --help
```

| 目標 | 命令 | 產物 |
| --- | --- | --- |
| wheel / sdist | `make build` | `dist/invisiscan-1.0.0-py3-none-any.whl` |
| 單檔可執行 zipapp | `make bundle` | `dist/invisiscan.pyz` |
| 本地全量校驗 | `make verify` | 測試 + 自掃描 |

**部署到 CI 的最小映像：**

```dockerfile
FROM python:3.12-alpine
COPY dist/invisiscan-1.0.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl
ENTRYPOINT ["invisiscan"]
```

> ℹ️ `alpine` 映像請確保 locale 支援 UTF-8；掃描器解碼失敗時會明確回報 `UnicodeDecodeError`，而非靜默略過。

### 🤝 貢獻指南

歡迎 PR！請遵守：

1. **提交規範** —— 採用 Angular 風格：`feat: ...` / `fix: ...` / `docs: ...` / `refactor: ...` / `test: ...`
2. **必須加測試** —— 新增規則請同時補正向（惡意樣本命中）與反向（正常文字不誤報）案例
3. **維持零依賴** —— 執行期不得引入任何第三方套件
4. **本地自檢** —— 提交前執行 `make verify`（含 `pytest` 與自掃描）

提交 Issue 時請附上：最小重現文字、`--format json` 的輸出、`invisiscan --version` 與 Python 版本。

### 📄 開源協議

本專案採用 **[MIT License](./LICENSE)**。你可以自由使用、修改與散布，包含商業用途。

---
---

## English

### 🎉 Introduction

**The code you read is not always the code that runs.**

In 2021 researchers at the University of Cambridge disclosed Trojan Source
(CVE-2021-42574): by inserting a handful of Unicode bidirectional controls
such as `U+202E` into source code, an attacker can make a compiler parse
something entirely different from what a reviewer sees rendered. Unit tests
stay green, linters stay silent, and the smuggled logic sails straight through
review — precisely because it occupies **no visible width at all**.

`InvisiScan` targets that entire class of threat:

- 🕵️ **Invisible characters** — zero-width codepoints that hide inside identifiers
- 🔀 **Trojan Source** — bidi controls that decouple display order from parse order
- 📦 **Hidden payloads** — Unicode tag characters that losslessly encode arbitrary ASCII
- 🎭 **Homographs** — a Cyrillic `аdmin` impersonating the Latin `admin`
- 🫥 **Space look-alikes** — characters that look like whitespace and quietly break every `==`

**Why another tool?** Existing options tend to drag in heavy dependencies,
cover only one or two of these classes, or emit formats that cannot feed a CI
pipeline. `InvisiScan` makes a deliberate trade:

> **Zero dependencies + all 11 rule classes + native SARIF + inline suppression + sub-second scans.**

#### ✨ What makes it different

| Capability | InvisiScan | Typical alternatives |
| --- | --- | --- |
| 🎯 **Breadth** | 11 graded rules (IS001–IS011) plus word-level homographs | Usually bidi-only or zero-width-only |
| 📊 **SARIF 2.1.0** | Native output straight into the GitHub Security tab | Custom text formats |
| 🧠 **Word skeletons** | UTS#39 visual folding of **identifiers**, pairable across files | Per-character comparison, very noisy |
| 🔇 **Inline suppression** | `# invisiscan:ignore=IS002` | Whole-file ignores at best |
| 📦 **Zero dependencies** | Standard library only, Python 3.9+ | Large transitive trees |
| ⚡ **Speed** | ~1.7 s per 100k lines (measured on a 4.5 MB sample) | — |

Inspired by UAX #9, UAX #15, UAX #31 and UTS #39, and by advisories
CVE-2021-42574 / CVE-2021-42694.

### ✨ Features

- 🔍 **11 graded rules** — from `IS001` bidi controls to `IS011` non-characters, across `critical / high / medium / low`
- 🎭 **Homograph detection (IS010)** — UTS#39 skeletons cluster visually identical identifiers, **including across files**
- 🚩 **SARIF 2.1.0** — `--format sarif`, uploadable to GitHub Security alongside CodeQL
- 🔇 **Inline suppression** — `# invisiscan:ignore` or `# invisiscan:ignore=IS002,IS007`
- 🎚️ **Flexible filtering** — `--severity`, `--rule`, `--ignore`, `--exclude`
- 📥 **stdin support** — `git diff | invisiscan --stdin`, ideal for pre-commit
- 🤖 **CI-friendly exit codes** — `0` clean, `1` findings, `2` execution error
- 🐍 **Zero third-party runtime dependencies**
- 🌍 **Dogfooded** — the codebase reports zero findings against itself

#### 📋 Rule catalogue

| ID | Category | Severity | Detects |
| --- | --- | --- | --- |
| `IS001` | `bidi-control` | 🔴 critical | Bidi embedding/override/isolate (Trojan Source) |
| `IS002` | `zero-width` | 🟠 high | Zero-width characters, BOM, soft hyphen |
| `IS003` | `invisible-operator` | 🟠 high | Invisible mathematical operators |
| `IS004` | `tag-character` | 🔴 critical | Tag characters encoding hidden payloads |
| `IS005` | `bidi-mark` | 🟡 medium | LRM / RLM direction marks |
| `IS006` | `variation-selector` | 🟢 low | Variation-selector abuse |
| `IS007` | `space-lookalike` | 🟡 medium | NBSP, ideographic space, friends |
| `IS008` | `deprecated-codepoint` | 🟢 low | Deprecated controls |
| `IS009` | `bidi-pop-format` | 🟢 low | Orphaned PDF / PDI |
| `IS010` | `confusable-identifier` | 🟠 high | Homograph identifier pairs |
| `IS011` | `noncharacter` | 🟡 medium | Non-characters / private-use codepoints |

### 🚀 Quick start

#### Requirements

- **Python 3.9 or newer** (standard library only)
- Linux / macOS / Windows

#### Install

```bash
# From source (recommended -- gives you the `invisiscan` command)
pip install .

# Editable install with dev extras
pip install -e ".[dev]"

# Or run it without installing
python -m invisiscan --help
```

#### Three seconds to first result

```bash
# Scan the current directory
invisiscan .

# Scan one file
invisiscan src/main.py

# Only the genuinely dangerous classes
invisiscan . --severity critical

# Hand SARIF straight to GitHub
invisiscan . --format sarif > results.sarif
```

**Sample output:**

```text
src/auth.py  (42 line(s), max severity: critical)
  [CRITICAL] 7:23 IS001 (bidi-control)              U+202E '<invisible>'
  [HIGH] 15:9  IS002 (zero-width)                   U+200B '<invisible>'
  [MEDIUM] 22:4 IS007 (space-lookalike)             U+00A0 ' '
  [HIGH] IS010 (confusable-identifier) skeleton='admin' variants=[admin, аdmin]

------------------------------------------------------------------------
Scanned 128 file(s), 1 file(s) with findings, 4 total finding(s)
  critical: 1   high: 2   medium: 1   low: 0
```

### 📖 Usage guide

#### Command-line options

| Flag | Purpose | Example |
| --- | --- | --- |
| `paths` | Files or directories to scan (default `.`) | `invisiscan src tests` |
| `-f, --format` | `text` (default) / `json` / `sarif` | `--format json` |
| `--severity` | Minimum level: `critical`/`high`/`medium`/`low` | `--severity high` |
| `--rule ID` | Report only this rule (repeatable) | `--rule IS001 --rule IS004` |
| `--ignore ID` | Suppress this rule (repeatable) | `--ignore IS006` |
| `--no-confusables` | Disable IS010 homograph detection | `--no-confusables` |
| `--min-word-length N` | Shortest word fed to IS010 (default 3) | `--min-word-length 5` |
| `--extension EXT` | Add a file extension (repeatable) | `--extension .proto` |
| `--exclude PATTERN` | Skip paths containing this text (repeatable) | `--exclude vendor` |
| `--stdin` | Read stdin instead of files | `cat f.py \| invisiscan --stdin` |
| `--stdin-name` | Filename shown for stdin results | `--stdin-name policy.yaml` |
| `-q, --quiet` | Omit the summary footer |  |
| `-V, --version` | Show version |  |

#### Common scenarios

**① Wire it into GitHub Actions (recommended)**

```yaml
- name: Unicode safety scan
  run: |
    pip install -e .
    invisiscan . --format sarif --exclude .git > results.sarif || true

- name: Upload to Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

> 💡 A ready-to-copy version lives in `.github/workflows/invisiscan.yml`.

**② As a pre-commit hook**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: invisiscan
        name: InvisiScan
        entry: invisiscan --severity high
        language: system
        types: [text]
```

**③ Only review what changed**

```bash
git diff --name-only origin/main...HEAD | xargs invisiscan --severity high
```

**④ Suppress legitimate findings**

```python
LEGACY_TOKEN = "abc​def"   # invisiscan:ignore=IS002

# Intentional homographs inside a test fixture
pair = ("аdmin", "admin")  # invisiscan:ignore=IS010

# Waive every rule for this line
raw = snarfle("a​b")  # invisiscan:ignore
```

> ⚠️ Suppression applies to **that line only**, so every waiver stays local and auditable.

**⑤ Python API**

```python
from invisiscan import Scanner

scanner = Scanner(min_severity="high")
result = scanner.scan_file(Path("src/main.py"))

for finding in result.findings:
    print(f"{finding.line}:{finding.column} [{finding.severity}] {finding.describe()}")

# Homographs resolve across files, so ask once after scanning everything
results = [scanner.scan_file(p) for p in files]
scanner.distribute_confusables(results)
```

> 📌 `confusables` is resolved globally, so a single `scan_text` / `scan_file`
> will not populate it on its own. Call `distribute_confusables(results)` after
> every target has been scanned.

#### 🙂 Exit codes

| Code | Meaning | Typical CI handling |
| --- | --- | --- |
| `0` | Clean, nothing found | Pass |
| `1` | Findings at or above the threshold | Block or warn per branch policy |
| `2` | Execution error (missing path, no matches) | Treat as pipeline failure |

### 💡 Design notes and roadmap

#### Design trade-offs

- **Breadth over syntax awareness.** InvisiScan parses no AST, so it is language-agnostic — one engine covers Python, Go, Rust, YAML and Markdown alike. The cost is that it cannot distinguish a bidi control in a comment from one in a string; happily, neither belongs in either.
- **Splitting on `\n`, never `splitlines()`.** Python's `str.splitlines()` treats `U+2028`/`U+2029` as line breaks, silently swallowing exactly the characters this tool hunts. This was a real bug caught during development and is now pinned by a regression test.
- **BOMs are not stripped.** Decoding plainly as UTF-8 leaves `U+FEFF` in the text where `IS002` reports it at column 1, keeping reported columns aligned with where an editor will jump.
- **The confusable table favours precision.** Better to miss an exotic variant than to flag an ordinary Greek word as an attack — a noisy security tool gets `--ignore`d and becomes useless.
- **IS010 is reported only in files holding a non-ASCII variant.** Plain ASCII files are context and are listed in the group's locations, but are not themselves flagged.

#### Roadmap

- [ ] 🌐 Enrich the confusable table from the official UTS#39 dataset
- [ ] 🧩 `--fix` auto-remediation mode
- [ ] 📜 Support a `.invisiscanignore` config file
- [ ] 🧪 Fine-grained `--fail-on <level>` gating
- [ ] 🔤 Dedicated identifier / IDN rules
- [ ] 🖥️ Interactive TUI to confirm each fix

### 📦 Building and deployment

This project ships as a **CLI tool / library**, so it publishes **no Release
binaries** — instead you get standard Python distributions plus a dependency-free
single-file bundle.

```bash
# Option 1: standard wheel + sdist
./scripts/build.sh
pip install dist/*.whl

# Option 2: single-file zipapp (target needs python3 only, no pip)
./scripts/build.sh bundle
python3 dist/invisiscan.pyz --help
```

| Target | Command | Artifact |
| --- | --- | --- |
| wheel / sdist | `make build` | `dist/invisiscan-1.0.0-py3-none-any.whl` |
| single-file zipapp | `make bundle` | `dist/invisiscan.pyz` |
| full local verification | `make verify` | tests + self-scan |

**Minimal CI image:**

```dockerfile
FROM python:3.12-alpine
COPY dist/invisiscan-1.0.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl
ENTRYPOINT ["invisiscan"]
```

> ℹ️ On `alpine`, make sure the locale supports UTF-8. When decoding fails the
> scanner reports an explicit `UnicodeDecodeError` rather than skipping silently.

### 🤝 Contributing

Pull requests welcome. Please:

1. **Follow Angular commit style** — `feat: ...` / `fix: ...` / `docs: ...` / `refactor: ...` / `test: ...`
2. **Add tests** — every new rule needs both a positive case (malicious input is caught) and a negative case (ordinary text is not flagged)
3. **Keep it dependency-free** — no third-party packages at runtime
4. **Verify locally** — run `make verify` (pytest plus self-scan) before pushing

When filing an issue, include: a minimal reproducer, the `--format json` output,
`invisiscan --version`, and your Python version.

### 📄 License

Released under the **[MIT License](./LICENSE)**. Use, modify and distribute freely, including commercially.

---

<div align="center">

Made with ☕ and a healthy distrust of invisible characters.

</div>
