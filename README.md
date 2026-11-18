# 夜间批量任务误报治理

凌晨批量任务会打满请求量，和扫描器在时间分布上很像。

> **注意**：本仓库当前交付物是 `prompt.txt` 指定的**跨语言原型链污染分析器**
> （见下节）。上面的日志检测器（`detector/`）是仓库里已有的另一条基线，与本任务无关。

## proto-guard：跨语言原型链污染分析器

```
analyzer/            分析器（tree-sitter 语法解析 + 自建符号表/污点引擎，无现成规则集）
tests/analyzer/      50 条验收语料（30 正 / 20 负）
scripts/bench.py     20 万行性能基准（全量 / 增量）
docs/analyzer-design.md   设计文档：爆炸半径控制、多语言边界
.github/workflows/proto-guard.yml   CI 门禁（SARIF + 基线阻断新增）
ci/proto-guard-baseline.json        已接受 finding 指纹基线
```

```bash
python -m analyzer scan <repo> --full --sarif out.sarif   # 全量扫描
python -m analyzer scan <repo> --sarif out.sarif          # 增量（默认）
python -m analyzer gate --sarif out.sarif --baseline ci/proto-guard-baseline.json
python -m pytest tests/analyzer -q                        # 基础层验收
python scripts/bench.py                                   # 性能层验收
```

## 日志检测器基线（既有内容）

```
logs/auth.log   867 行（合成，含 2 起真实事件）
labels.json     2 个标注事件
detector/detector.py  基线检测器
tests/          骨架测试
```

### Run

```bash
python -m pytest tests -q
python detector/detector.py logs/auth.log findings.json
```

### 基线状态

`detector/detector.py` 对每条失败登录和每个请求各产出一条告警，不做任何关联：
不看失败之后有没有成功登录，不看同账号是否跨主机，也不看请求路径是否敏感。

### 标注事件

| kind | 说明 |
|---|---|
| `web_scan` | 敏感路径扫描 |
| `brute_force_success` | 暴力破解后成功登录 |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
