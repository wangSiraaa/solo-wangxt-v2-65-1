# 路由策略离线推演工作台 (Routing Policy Rehearsal Workbench)

在**发布前**离线看清前缀策略会放行/拒绝哪些前缀。完全本地，**不连接任何生产设备**。

* **React**：前缀树 + 命中链可视化、规则编辑、遮蔽检查、语义差异（最小见证前缀集）、有序回放、FRR 交叉验证、**验证/审批/模拟发布/回滚闭环**
* **FastAPI**：REST API（状态机 + 幂等），判定核心用 Python 标准库 **`ipaddress`**
* **PostgreSQL**：邻居、有序规则、不可变配置快照、场景、验证运行、**发布记录与审计事件**（也可用 SQLite 免依赖运行；Alembic 迁移）
* **FRRouting 容器**（router-a / router-b，隔离 bridge）：用 FRR 自己的 prefix-list 匹配器做交叉验证，模拟发布也只写入这两个本地容器

---

## 1. 语义模型（模拟器）

每条规则 `(seq, prefix, action, ge, le)`，规则按 **seq 升序，首条匹配即终止**：

1. **包含关系**：候选前缀必须是规则基址的子网（`candidate subnet-of base`）；
2. **掩码长度窗口**：`effective_min = ge ?? base_len`，`effective_max = le ?? (ge ?? base_len) : base_len`，即
   * 无 ge/le：精确匹配基址长度；
   * 仅 `le`：窗口 `[base_len, le]`；
   * 仅 `ge`：窗口 `[ge, 32|128]`（Cisco 语义）；
3. 第一个同时满足包含与窗口的规则决定 permit/deny；
4. 都不命中 → 策略的**隐式默认动作**（可配，通常 deny）；
5. **IPv4 与 IPv6 严格隔离**：混合规则在构造/分类时直接报错。

`IPv4Network/IPv6Network` 完成全部地址与掩码计算；引擎与 FRR 的 ge/le 边界一致（见下“FRR 一致性”）。

## 2. 不是文本 diff：最小行为见证集

用户改完规则后，系统计算两个**不可变快照**之间的语义差异，输出**行为发生变化的最小前缀集合**，而不是规则文本差异：

* 前缀空间被精确切分为单元（规则基址边界 + ge/le 长度边界），**全枚举、非采样**；
* 同状态单元用并查集合并成“最大等价区域”（同深度地址相邻 + 跨深度包含且获胜规则/窗口一致），区域被更粗的获胜规则切断时不会跨越；
* 每个发生动作变化的区域给出**一个最浅代表前缀**作为探针，并标注旧/新命中 seq；
* `deny→deny` 只是命中规则换了、转发结果没变，**不会**出现；纯文本改写（如改备注）得到空集。

同时提供**遮蔽分析**：完全遮蔽（永不可达，给出被截获的代表前缀）与部分重叠。

### 三个内置示例（`backend/app/seed.py`，含 before/after 快照与有序探针，可回放）

| 场景 | 说明 | 关键见证 |
|---|---|---|
| **over-permit** 更具体路由误放行 | `192.168.0.0/16 le 24` 过宽，把本应拒绝的 DC /24（如 `192.168.100.0/24`）放了进来；收紧到 `le 23` 并加显式 guard | `192.168.0.0/24`、`192.168.100.0/24` 等 `permit→deny` |
| **reorder** 规则换序 | 宽 `172.16/12 le32 permit` 从 seq 20 换到 seq 5，压过窄 `172.31/16 deny`（后者变完全遮蔽） | `172.31.0.0/16 deny→permit` |
| **default-flip** 默认动作变化 | 删掉 `0/0 permit` 风格兜底、默认从 permit 翻成 deny | `0.0.0.0/0 permit→deny`（最宽代表） |

另含 IPv6 示例 **over-permit-v6**（`2001:db8::/32 le 48` 过宽）。

## 3. 回放：输入与生效次序

* 每次“发布候选”都生成**不可变快照**（含有序规则、默认动作、族、渲染好的 FRR 配置）；
* 场景保存**有序探针列表**，`/api/scenarios/{id}/replay` 以相同顺序对 before/after 两个快照确定性回放，返回每条命中链与差异；
* 快照 payload 自包含，后续再编辑规则不影响历史回放——满足“可回放输入及生效次序”。

## 4. FRR 容器交叉验证

两个 FRR 8.4 节点在隔离的 internal bridge（`172.30.10.0/24`，无外部连通）上。验证流程（`backend/app/validate.py`）：

1. 把快照渲染成 `ip/ipv6 prefix-list NAME seq N permit/deny PREFIX [ge X] [le Y]` 下发到容器；
2. 对每个探针执行 FRR 原生命令
   `vtysh -c "debug ip prefix-list NAME match PREFIX"`
   —— 输出由 **FRR 自己的匹配代码**给出 `PERMIT/DENY` 与 `matching entry #seq`；
3. 与 `ipaddress` 模拟器逐条比对动作与 seq，结果写入 `runs` 表；
4. 结束后删除该 prefix-list。

FRR 语义已对照其源码 `lib/plist.c` 核对（包含关系、无 ge/le 精确匹配、窗口、首条最小 seq、未命中 DENY）。注意 FRR 对**空** prefix-list 返回 PERMIT，因此空策略会被报为 lab setup error 而非静默一致。

传输默认 `docker exec`（`RLAB_FRR_TRANSPORT=docker`），也可切到 SSH（`RLAB_FRR_TRANSPORT=ssh`，见 `backend/app/config.py`）。容器不在线时相关测试自动 skip，UI 显示离线徽标。无 Docker 的环境（CI、评审机）可设 `RLAB_FRR_TRANSPORT=stub`：进程内实现同一份 FRR `prefix_list_apply` 语义，发布管线全流程可跑、可注入容器失败（仅实验室用途）。

## 4b. 可审查发布流程（验证 → 审批 → 模拟发布 → 回滚）

推演通过的快照不再直接"生效"，而是进入一个显式状态机（`backend/app/release.py`，UI 第 ④ 页）：

```
draft 草稿
  └─ validate ─▶ validating 验证中
                  ├─▶ validation_failed 验证失败（可重试）
                  └─▶ pending_approval 待审批
                         └─ approve ─▶ approved 已批准
                                          └─ publish ─▶ simulated_published 已模拟发布
任意非终态 ─▶ superseded 已替代（规则后续编辑 / 被更新版本取代）
```

**冻结的审批证据**（批准时整体再做一次校验和冻结，存 `releases.evidence/approval` JSON）：

1. **规则顺序**：快照内有序规则 + `rules_checksum`；
2. **邻居**：当时全部邻居绑定（名称/IP/族/ASN/入出站策略）+ 邻居校验和；
3. **默认动作**与地址族；
4. **语义差异**：相对当前生效版本（首个版本相对隐式空策略 deny-all）的**最小见证前缀集**；
5. **探针结果**：确定性生成的探针（每个规则基址、窗口内/边界前缀、默认区域、全部见证前缀，去重且限量）+ 审批人自定义探针的有序模拟器判定；
6. **FRRouting 交叉验证证据**：每个发布节点（默认 router-a、router-b）一条 `runs` 记录、状态、逐条 FRR 原生匹配结果；
7. **默认拒绝守卫**：外部探针（v4 `192.0.2.255/32`、v6 `2001:db8:ffff::/64`）在 default-deny 快照下必须 deny，否则验证失败。

**后续编辑即新草稿**：`PUT /rules`、默认动作变化、邻居变更都会把该策略所有非终态发布记录置为 `superseded`；对陈旧草稿点验证、对陈旧待审批点批准都会被 409 拒绝。历史快照本身永不改写。

**模拟发布只写隔离 FRR**：配置以独立稳定名 `rlabpub{policy_id}` 安装（与交叉验证临时使用的"策略名"列表互不干扰），流程严格保证数据库与容器不漂移：

1. 先逐节点 `remove → install → show 校验每条 seq/action`，任一节点失败即停止；
2. 已改动的节点**尽力回滚为上一个生效配置**（同一发布名），行状态留在 `approved` + `last_error`，可直接重试；
3. 全部节点确认后才开事务翻转数据库：新版本 `simulated_published`、旧生效版本 `superseded`；
4. 进程锁 + 部分唯一索引
   `CREATE UNIQUE INDEX ... ON releases(policy_id) WHERE state='simulated_published'`
   保证重复/并发发布**只有一个版本生效**（重复发布是返回同一条目的幂等 no-op；被更新版本超越的旧批准发布返回 409）。

**回滚不改写历史**：`POST /api/releases/{id}/rollback` 从该历史记录的**快照**创建一条全新的 `kind=rollback` 记录（`rollback_of_id` 指回来源），重新走 validate → approve → publish；回滚记录豁免"快照必须等于当前编辑态"的新鲜度检查。回滚后可核对：前/后两个快照、最小见证前缀（`/api/snapshots/diff`）、以及 `GET /api/releases/{id}/live-config` 读回的**容器实际 prefix-list**（含校验和）。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/policies/{id}/releases/draft` | 当前规则铸造新快照并生成草稿（同内容重复 POST 幂等复用） |
| GET | `/api/policies/{id}/releases`、`/api/releases` | 发布历史（可按 state/policy 过滤） |
| GET | `/api/releases/{id}` | 发布记录 + 冻结证据 + append-only 事件 |
| POST | `/api/releases/{id}/validate` | 验证（可带自定义 probes/nodes），失败可重试 |
| POST | `/api/releases/{id}/approve` | 批准（审批人/意见），冻结证据并替代其他待审批/已批准 |
| POST | `/api/releases/{id}/publish` | 模拟发布（幂等；容器失败返回 200+approved+last_error，可重试） |
| POST | `/api/releases/{id}/rollback` | 从历史快照创建新的回滚草稿 |
| GET | `/api/policies/{id}/releases/active` | 当前唯一生效版本 |
| GET | `/api/releases/{id}/live-config` | 各隔离节点实际安装配置与发布校验和比对 |

数据库迁移（Alembic，`backend/migrations/`）：`0001_baseline`（原始表）→ `0002_releases`（发布/事件表 + 部分唯一索引）。API 启动与 `app.seed` 自动升级；老的 `create_all` 库会被自动 stamp 到 baseline 再升级，升级幂等。手动执行：`python -m app.migrate`。

## 5. 快速开始

### 免容器 / 免 Postgres（SQLite，最快体验）

```bash
cd backend
python -m pip install -r requirements.txt
python -m app.seed                       # 建表 + 写入示例（数据在 backend/data/）
python -m uvicorn app.main:app --port 8765
# API 文档 http://127.0.0.1:8765/docs

cd ../frontend
npm install && npm run dev               # http://localhost:5173 （已配 /api 代理）
```

### 完整本地栈（PostgreSQL + FRR）

```bash
docker compose up -d postgres router-a router-b
cd backend
DATABASE_URL=postgresql+psycopg://rlab:rlab@127.0.0.1:5432/rlab \
  python -m app.seed
RLAB_FRR_TRANSPORT=docker python -m uvicorn app.main:app --port 8765
```

在 UI “④ 回放 / FRR 交叉验证”页选快照与节点（router-a / router-b），点“推送 FRR 并比对”，或：

```bash
curl -s localhost:8765/api/frr/status
curl -s -XPOST localhost:8765/api/snapshots/<id>/cross-validate \
  -H 'content-type: application/json' \
  -d '{"probes":["192.168.100.0/24","10.1.2.3/32"],"node":"a"}'
```

## 6. 测试

```bash
pip install pytest httpx
python -m pytest tests/ -q
```

* `test_engine.py`：精确匹配、ge/le 窗口、首条匹配、默认拒绝、v4/v6 隔离、三个示例决策；
* `test_properties.py`：在完整枚举的 /0../6（v4）与 /32../34（v6）格子上，对数百个随机策略用暴力预言机验证**遮蔽判定**与**最小见证集**逐区域一致（非采样）；
* `test_api.py`：编辑→快照→差异→回放的端到端 REST；
* `test_release_pipeline.py`：发布状态机验收——验证/审批证据冻结可回放、规则变更使旧审批失效、重复/并发发布仅一个生效、容器应用失败后 DB 可重试且恢复成功、回滚新建记录且前后快照/见证前缀/实际隔离配置可核对、IPv4/IPv6 与默认拒绝不回归；
* `test_frr_consistency.py`：FRR 输出解析、随机 400 例与 FRR `prefix_list_apply` 移植模型逐条一致；`test_live_frr_consistency` 在检测到容器时自动对真实 FRR 运行。

## 7. 主要 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/policies` | 策略列表（含规则与渲染的 FRR 配置） |
| PUT | `/api/policies/{id}/rules` | 整表有序替换规则（经 ipaddress 校验、族隔离、ge/le 校验） |
| GET | `/api/policies/{id}/analyze` | 完全/部分遮蔽分析 |
| POST | `/api/policies/{id}/classify` | 单条命中链（含 trie_path、每条规则包含/窗口判定与原因） |
| POST | `/api/policies/{id}/classify/batch` | 批量有序推演（坏输入逐条隔离报错） |
| GET | `/api/policies/{id}/trie` | 前缀树视图 |
| POST | `/api/policies/{id}/snapshots` | 创建不可变快照 |
| POST | `/api/snapshots/diff` | 两个快照的最小见证集差异 |
| POST | `/api/snapshots/{id}/replay` | 有序探针确定性回放 |
| POST | `/api/snapshots/{id}/cross-validate` | 推送 FRR 容器并逐条比对 |
| GET/POST | `/api/scenarios`、`/api/scenarios/{id}/replay` | 场景（输入+两个快照+结果） |
| GET/POST | `/api/neighbors` | 本地实验室邻居 |
| GET | `/api/frr/status`、`/api/runs` | 容器在线状态、历史验证运行 |

## 目录

```
backend/app/   engine.py(匹配/遮蔽) trie.py(精确单元+最小见证) service.py db.py
               validate.py frr_bridge.py(含无Docker环境的 stub 传输)
               release.py(发布状态机/证据/模拟发布/回滚)
               migrate.py routers/(api.py, releases.py) seed.py
backend/migrations/  Alembic: 0001_baseline -> 0002_releases
frontend/src/  App.jsx + components/(PolicyEditor/TrieView/DiffView/
               ReleaseGate+EvidencePanel/ReplayLab/Neighbors)
frr/           两个节点的 daemons/vtysh/frr.conf 与独立 docker-compose
tests/         引擎/属性/API/发布管线/FRR 一致性
docker-compose.yml   postgres + backend + router-a/b
```
