# AGENTS.md

## 项目结构

- 当前仓库是 Java Burp Suite 插件项目。
- `src/main/java/com/vibecode/payloadrunner/`：插件源码。
- `src/main/resources/payloads.yaml`：插件内置 payload 分类，来源于 `测试payload速取.xlsx`。
- `src/compileOnly/java/burp/`：编译期 Burp legacy API stub，仅用于本地 `javac`，不要打进最终 jar。
- `scripts/build.sh`：本地构建脚本。
- `scripts/extract_payloads.py`：从 `测试payload速取.xlsx` 提取 payload 并生成内置 YAML。
- `.github/workflows/ci.yml`：GitHub Actions，push/PR 自动测试和构建，`v*` tag 自动发布 jar。
- 插件运行时 payload 和命中规则编辑内容通过 Burp extension settings 保存，不直接回写 jar 内资源。
- `build/`：本地构建输出，已忽略，不提交。

## 运行命令

- 构建插件 jar：
  - `sh scripts/build.sh`
- 构建产物：
  - `build/payload-runner-burp.jar`
- 刷新内置 payload：
  - `/Users/aur4r0/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 scripts/extract_payloads.py 测试payload速取.xlsx src/main/resources/payloads.yaml`
- 运行方式：在 Burp Suite `Extensions -> Installed -> Add -> Java` 中加载构建产物。

## 测试命令

- 当前使用无依赖 Java smoke test。
- 最小测试命令：
  - `sh scripts/test.sh`
- 构建验证命令：
  - `sh scripts/build.sh`
- 不要声称 Burp 内功能已验证，除非实际在 Burp 中加载并操作过。

## 代码风格

- 默认使用 ASCII；只有文件已有非 ASCII 内容或业务明确需要时才引入非 ASCII。
- 遵循仓库已有格式化、lint、命名和目录约定；没有约定时保持简单、局部、可读。
- 不为未出现的复杂度提前加抽象。
- 注释只解释不明显的约束、边界或决策；不要写重复代码含义的注释。
- 新增依赖必须有明确用途，并优先使用项目已存在的工具链。

## 禁止事项

- 不要删除、重置或覆盖用户未要求修改的文件。
- 不要运行破坏性命令，例如 `git reset --hard`、清理未跟踪文件、批量删除目录，除非用户明确要求。
- 不要把空仓库当成某个固定技术栈处理。
- 不要提交构建产物、缓存、密钥、令牌、本地环境文件或个人 IDE 配置。
- 不要在没有验证的情况下报告“已修复”“可运行”或“测试通过”。

## 完成标准

- 改动范围只覆盖用户请求和必要的配套更新。
- 相关文件已保存，且没有引入无关格式化或元数据变更。
- 能运行的测试、格式化或检查已经运行；不能运行时说明原因。
- 新增或变更命令、目录、依赖、环境变量时，同步更新文档。
- 最终回复必须说明改了什么、验证了什么、仍有什么限制。

## Review 标准

- 先看行为风险：错误逻辑、数据丢失、权限问题、兼容性回归、安全问题。
- 所有发现必须给出具体文件和行号；没有证据不要猜测。
- 按严重程度排序，高风险问题放在最前。
- 区分阻塞问题、建议改进和测试缺口。
- 如果没有发现问题，明确说明“未发现阻塞问题”，并列出剩余风险或未运行的检查。
