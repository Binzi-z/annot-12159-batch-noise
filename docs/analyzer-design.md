# proto-guard：跨语言原型链污染分析器设计

针对三个前端仓库合并成 monorepo 后「A 包补校验、B 包深合并又覆盖回去」的修复回退问题。
本分析器把**污染源 → 跨包传播 → 污染落点**的完整链路画出来，输出 SARIF 并在 CI 阻断新增。

实现约束：不使用任何现成规则集（Semgrep/CodeQL 规则等）。只用语法解析库
（tree-sitter 负责 JS/TS/TSX，CPython `ast` 负责 Python），符号表、污点引擎、
规则判定全部自建（`analyzer/`）。

## 规则与链路模型

| 规则 | 落点 | 说明 |
|---|---|---|
| PP001 | 深合并函数 | 受控对象进入 merge/extend/defaults 类汇点（本地识别为 merge-like 的函数，或外部同名调用） |
| PP002 | 递归 Object.assign | `Object.assign(target, 受控源)` |
| PP003 | JSON.parse 直接赋值 | `JSON.parse(受控输入)` 结果直接赋进成员/被 assign 合并 |
| PP004 | 动态键写入 | `target[k] = v`，k 来自对受控对象的键迭代（原型污染核心 gadget） |
| PP005 | 显式 `__proto__` 写 | 写位置出现 `__proto__`/`constructor`/`prototype` 字面键 |
| PY001/PY002 | Python 侧 | `setattr(obj, 受控名, v)`、`__dict__.update(受控映射)`（独立编号段，见下文边界） |

**源**：`req.body/query/params/headers/cookies`（含 `ctx.req.*`，值与键双重受控）、
`location.search/hash`（经 `URLSearchParams.get`）、`localStorage/sessionStorage.getItem`、
`fetch().json()`。`JSON.parse(受控)` 派生「键受控」标记。

**净化识别**（在函数体内识别后，该函数摘要标记 `sanitizes_keys`，其返回值被剥掉键受控标记）：

- `Object.prototype.hasOwnProperty.call(obj, k)` 守卫（正/反两种写法）；
- 键黑名单：`if (k === '__proto__' || ...) continue/return`；
- 键白名单：`ALLOWED.includes(k)` / `indexOf(k)` 守卫；
- `Object.create(null)` 作为合并目标（调用点级抑制）。

## 跨包传播与爆炸半径控制

monorepo 里链路跨包：`web` 的 handler 调 `@mono/core` 的 `merge`，`@mono/mid` 再 re-export。
解析顺序：相对路径 → 最近 tsconfig 的 `paths`/`baseUrl` 别名 → workspace 包名
（根 package.json `workspaces`  glob + 各包 `main`）→ 都不中则是外部 npm 依赖。

爆炸半径用四道闸控制在常数级：

1. **函数摘要是唯一的跨边界载体。** 包间传播的不是数据流图节点，而是每个函数的
   摘要（参数→返回、参数→汇点、merge_like、sanitizes_keys、调用记录）。
   调用方只实例化摘要，从不展开被调方函数体——分析量 = O(函数数)，不是 O(调用路径数)。
2. **不动点上限 `MAX_ROUNDS = 8`。** 摘要迭代收敛即停（实测 2–3 轮），8 轮硬顶，
   等价于跨包传播深度 ≤ 8 跳；摘要不再变化时提前终止。
3. **外部依赖一律不透明。** 解析不到仓库内文件的 import（lodash 等）不展开、不建模，
   只按名字启发式在调用点判一次（`defaultsDeep(cfg, req.body)`），切断向 npm 图的扩散。
4. **全局实例化是单趟平铺。** 跨包 finding 由一趟对调用记录的扫描产生，无递归；
   同一 (rule, file, line, message) 去重，同一包对同一汇点的重复链路只报一次。

效果：20 万行合成 monorepo（40 包 × 25 文件）全量 30s、增量 2s（见 `scripts/bench.py`），
 finding 数随真实问题数线性增长，不随包间组合数爆炸。

## 多语言边界：如何避免把 Python 误判进 JS

混合仓库里最大的误报来源是「用 JS 的规则看 Python 的代码」（Python 里也有
`merge`、`update`、`__dict__` 这些词）。边界设计：

1. **按扩展名硬路由。** `.js/.jsx/.ts/.tsx/.mjs/.cjs` 进 tree-sitter 引擎，`.py` 进
   `ast` 引擎。两个引擎**不共享符号表**，Python 文件永远不会出现在 JS 模块图里，
   JS 的 `req.body` 源规则永远不会作用到 Python 函数参数上。
2. **污点不跨语言隐式传播。** JS ↔ Python 之间的数据交换（HTTP/JSON 文件/队列）
   不建模为符号流动；到达另一侧的数据按该语言的**源规则重新引入**（如 Python 侧
   的 `request.get_json()`）。宁可断链，不可错链——断链漏报可由样本层验收兜住，
   错链会把整片 Python 代码染成 JS 污点。
3. **Python 有自己的规则编号段（PY001/PY002）**，针对 Python 真实存在的等价问题
   （`setattr` 动态属性、`__dict__.update`），而不是把 JS 的 `__proto__` 概念硬套过去
   ——Python 没有原型链，`target["__proto__"]` 在 Python 里只是普通字典键，报了就是误报
   （语料 n07 专门覆盖这一条）。
4. **解析隔离区。** tree-sitter 解析错误节点超过阈值（>3）的文件不强行猜测，
   降级为 META001 note 并跳过——防止把非标准语法（如混进 JS 目录的 Python 片段、
   模板文件）误解析出假链路。

## 增量与 CI

- 缓存（`.proto-guard/cache.json`）按文件 SHA1 存摘要/局部 finding/调用记录；
  增量只重解析变更文件，全局实例化每跑都基于最新摘要重算，保证跨包结果一致。
- CI（`.github/workflows/proto-guard.yml`）：PR 上全量扫描出 SARIF，
  `python -m analyzer gate` 比对 `ci/proto-guard-baseline.json` 的指纹集，
  **新增指纹即失败**；已有指纹不重复报警。基线只能在 main 上经 review 用
  `gate --update` 更新——这正是防「修复互相回退」的机制：B 包一旦把 A 包的
  校验覆盖回去，会作为新指纹被门禁拦下。

## 验收对照

| 层 | 指标 | 结果 |
|---|---|---|
| 基础层 | 50 样本召回 ≥85%、误报 ≤15% | `tests/analyzer`：召回 30/30 = 100%，误报 0/20 = 0% |
| 性能层 | 20 万行全量 <3min、增量 <15s | `scripts/bench.py`：204,400 行全量 ~30s，增量（改 3 文件）~2s |
| 解释层 | 爆炸半径控制、多语言边界 | 本文档上文两节 |

已知限制（有意取舍）：函数内净化按流不敏感处理（守卫在函数任意位置即生效）；
类实例方法的跨模块解析按名字 best-effort；外部 npm 依赖不建模。这些都在
「宁漏勿错」的一侧，由 85% 召回预算兜底。
