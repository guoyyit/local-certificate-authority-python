# Local Certificate Authority

一套完全本地运行的证书签发与域名所有权验证服务。客户端依次完成
**账户注册 → 授权请求 → 质询响应 → 证书签发/吊销**。
不依赖任何外部 CA、真实 DNS 或付费服务：CA 根密钥在本地生成并自签，
域名所有权通过确定性应答（`sha256(token.account_id)`）校验。

## 运行

```bash
uv sync
uv run uvicorn main:app --port 8000
```

数据库与 CA 密钥路径可用环境变量覆盖：`LOCAL_CA_DB`、`LOCAL_CA_KEYS`。

## 测试

```bash
uv run pytest tests/ -q
```

## 状态机

```
Account:       (register) ──▶ ACTIVE ──▶ DEACTIVATED
Authorization: PENDING ──应答成功──▶ VALID
                  │  └──应答失败/超时──▶ (质询 INVALID/EXPIRED，可重新发起)
                  └──超过 authz_ttl──▶ EXPIRED
Challenge:     PENDING ──▶ VALID | INVALID | EXPIRED
Certificate:   VALID ──▶ REVOKED
```

所有状态迁移都是 SQLite 条件更新（`UPDATE ... WHERE status = ...`），
并发或重复请求不会互相覆盖；多行写入包裹在事务中，崩溃不会留下半份记录。

### 账户
- `POST /accounts` 幂等：同名账户返回既有记录，`UNIQUE(name)` + `INSERT OR IGNORE`
  保证并发注册绝不产生重复账户。
- 角色：`admin` / `operator` / `viewer`。签发、质询、吊销需要 `operator` 以上；
  吊销他人证书需要 `admin`；`viewer` 只读。越权返回 403。

### 授权（Authorization）
- `POST /authorizations`：同一账户同一域名存在未过期的 PENDING/VALID 授权时直接复用。
- 授权有效期 `authz_ttl`（默认 24h），过期后需重新请求。

### 质询（Challenge）
- `POST /challenges`：**同一域名同一时间只允许一个 PENDING 质询**；
  并发或重复创建返回同一个质询。
- 应答为确定性摘要：`sha256(token + "." + account_id)`，客户端可本地计算。
- 应答错误 → `INVALID`；超过 `challenge_ttl`（默认 10 分钟）→ `EXPIRED`。
  两种终态都允许立即重新发起新质询。
- 质询 VALID 后，对应授权推进为 VALID 并顺延有效期。

### 签发（Issuance）
- `POST /certificates`：必须存在未过期的 VALID 授权，否则拒绝（422）。
- 同一域名的签发按域名锁串行化；并发签发得到**同一张证书**（确定性结果，
  不产生重复记录）。在授权仍有效且已有有效证书时重复调用是幂等的。
- 证书与私钥同事务持久化，可查询：`GET /certificates`、`GET /certificates/{id}`。

### 轮换（Rotation）
- `POST /certificates/rotate` 为域名签发新证书。**旧证书不立即失效**：
  它在自己的 `not_before..not_after` 窗口内继续通过校验，直到过期或被吊销。
- 新旧证书通过 `not_before` / `serial` 区分生效时间。
- CA 根密钥轮换（`CAKeyStore.rotate()`）同理：历史 CA 代际保留在磁盘，
  重启后自动加载，旧 CA 签发的证书仍可验证。

### 吊销（Revocation）
- `POST /certificates/{id}/revoke`：原子迁移 VALID → REVOKED，记录时间与原因。
- **幂等**：重复吊销返回首次结果，不重复写审计。
- 已吊销证书 `GET /certificates/{id}/verify` 返回 `valid: false`。

### 校验语义
证书通过校验当且仅当：
1. 状态不是 REVOKED；
2. 当前时间处于 `not_before..not_after` 窗口内；
3. 签名可由任一已知 CA 代际（含轮换前的旧代际）验证。

### 崩溃恢复
- 已确认的签发、吊销、审计记录全部持久化在 SQLite（WAL 模式），重启不丢。
- 服务启动时 `recover()`：加载全部 CA 代际；把已过期的 PENDING 质询/授权
  清扫为 EXPIRED，使未完成流程回到可重试状态。
- 签发记录单事务写入，CA 密钥文件 tmp+rename 原子落盘，
  不会留下半份证书或半份密钥。

### 审计
- 每次状态变更写入 `audit_events`（账户、动作、对象、详情、时间）：
  `GET /audit?account_id=&action=`。

## HTTP 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/accounts` | 注册账户（幂等） |
| GET | `/accounts/{id}` | 查询账户 |
| POST | `/authorizations` | 请求域名授权 |
| GET | `/authorizations/{id}` | 查询授权 |
| POST | `/challenges` | 创建质询（每域名唯一活跃） |
| POST | `/challenges/{id}/respond` | 提交质询应答 |
| GET | `/challenges/{id}` | 查询质询 |
| POST | `/certificates` | 签发证书（需 VALID 授权） |
| POST | `/certificates/rotate` | 轮换证书 |
| GET | `/certificates` | 按域名/账户查询 |
| GET | `/certificates/{id}` | 查询证书与私钥 |
| GET | `/certificates/{id}/verify` | 校验证书 |
| POST | `/certificates/{id}/revoke` | 吊销证书（幂等） |
| GET | `/audit` | 查询审计事件 |

错误码：404 不存在，403 越权，409 并发冲突，422 状态不允许，400 参数错误。

## 代码结构

```
local_ca/
  models.py    # 枚举与数据类（状态机定义）
  storage.py   # SQLite 持久化，条件更新保证原子迁移
  crypto.py    # CA 密钥生成/轮换、证书签发与验证
  service.py   # 业务编排：权限、状态推进、审计、恢复
  api.py       # FastAPI HTTP 层
main.py        # uvicorn 入口
tests/         # 重复请求、并发签发、质询超时、轮换、吊销、崩溃恢复
```
