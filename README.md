# Local Certificate Authority (Python)

一套完全本地运行的证书签发与域名所有权验证服务。不依赖任何外部 CA、真实
DNS 解析或付费服务：CA 根密钥在首次启动时本地生成并持久化，域名所有权通过
客户端回显质询值（模拟 DNS TXT 记录）完成验证。

## 架构

```
main.py            入口：读取环境变量，装配 service + HTTP 层
local_ca/
  models.py        状态枚举与不可变数据模型
  errors.py        类型化异常（404/409/403/400 语义的来源）
  storage.py       SQLite 持久化：唯一约束 + BEGIN IMMEDIATE 事务
  crypto.py        RSA 密钥生成、自签 CA 证书、服务端证书签发与验签
  service.py       业务编排：账户/授权/质询/签发/轮换/吊销/审计
  api.py           FastAPI 薄层，Bearer token 认证，异常到状态码映射
tests/             pytest 自动化测试（含并发与崩溃恢复场景）
```

持久化使用单文件 SQLite（WAL 模式）。CA 根密钥与证书存放在库内 `meta`
表，与业务数据共享同一事务存储，因此进程重启后 CA 身份稳定，且不会出现
"业务数据已提交但 CA 密钥丢失"之类的分裂状态。

## 运行

```bash
uv sync
uv run uvicorn main:app --port 8080
# 环境变量：
#   LOCAL_CA_DB           SQLite 路径（默认 ./local-ca.db）
#   LOCAL_CA_ADMIN_TOKEN  管理员 Bearer token（默认 dev-admin-token）
```

测试：`uv run pytest`

## 签发流程（客户端视角）

1. `POST /accounts` 注册账户（contact + 自选 token）。
2. `POST /authorizations` 为域名创建授权请求。
3. `POST /challenges` 基于授权创建质询，得到 `expected_value`。
4. 客户端"发布"该值（本地语义：持有并回显），调用
   `POST /challenges/{id}/respond` 提交。
5. 验证通过后 `POST /certificates` 签发证书，响应包含证书与私钥 PEM。
6. 之后可 `POST /certificates/rotate` 轮换、`POST /certificates/{serial}/revoke`
   吊销、`GET /certificates/{serial}/status` 查询吊销状态。

除注册与查询类接口外，所有写操作都需要 `Authorization: Bearer <token>`。

## 状态机

### 账户（Account）

```
register ──> ACTIVE ──> DISABLED
```

- 注册按 `contact`（归一化后）幂等：重复注册返回同一账户，不会产生重复账户。
- 非 ACTIVE 账户的 token 一律拒绝（403）。

### 授权请求（Authorization）

```
PENDING ──(质询验证通过)──> VALID
PENDING ──(超过 expires_at)──> EXPIRED ──(重新发起)──> PENDING
```

- 以 `(account_id, domain)` 唯一：重复/并发创建返回同一条记录。
- EXPIRED 后再次创建会把原记录重置回 PENDING 并刷新过期时间（可重试）。
- VALID 授权在 `expires_at` 之后同样不可用于签发。

### 质询（Challenge）

```
PENDING ──(回显值匹配)──> VALID
PENDING ──(回显值不匹配)──> INVALID
PENDING ──(超过 expires_at)──> EXPIRED
```

- **同一域名同一时间最多一个 PENDING 质询**（数据库部分唯一索引保证）。
  - 同一授权重复创建：返回既有质询（幂等）。
  - 其他账户的授权创建：409 冲突。
- INVALID / EXPIRED 不占位，必须也允许重新创建新质询。
- 验证失败会被**持久化**为 INVALID（错误在事务提交后才抛出），
  避免失败质询残留占用域名。
- 过期由每次写操作前的惰性清扫（sweep）生效，无需后台线程。

### 证书（Certificate）

```
issue/rotate ──> ACTIVE ──(revoke)──> REVOKED
ACTIVE ──(超过 not_after)──> EXPIRED（查询时派生，不落库）
```

- 签发前置校验（缺一不可，全部在单个事务内完成）：
  1. 账户存在且 ACTIVE；
  2. `(account, domain)` 的授权为 VALID 且未过期；
  3. 该授权下存在 VALID 且未过期的质询。
- **幂等签发**：同一账户对同一域名已有 ACTIVE 证书时，重复/并发请求
  返回既有证书（同一 serial），不会重复签发。
- **轮换**：`rotate` 总是生成新密钥、新 serial、新 `not_before`；
  旧证书保持 ACTIVE 直至自身 `not_after` 或被吊销——既有校验不会立即
  失效，新旧证书凭 serial 与生效时间可区分。
- **吊销**：仅管理员或证书所属账户可执行；重复吊销幂等（返回既有状态，
  审计记录 `certificate.revoke.duplicate`）。`GET .../status` 对已吊销
  证书返回 `revoked`，对过期证书返回 `expired`。

## 并发与崩溃恢复语义

- 所有多步写入包裹在 `BEGIN IMMEDIATE` 事务中，进程内写操作经
  `threading.RLock` 串行化：并发注册/授权/质询/签发结果确定，且满足
  各自的幂等语义（同账户同域名并发签发只会产生一张证书）。
- 事务要么整体提交要么整体回滚：签发中途崩溃不会留下半张证书或半条
  审计记录；质询状态迁移中途崩溃后质询保持 PENDING，可直接重试。
- 已提交的签发与吊销结果落库（WAL），进程重启后完整可见；未完成的
  流程（PENDING 质询/授权）重启后处于可重试状态。
- 内部写方法在外层事务内不再独立提交（`Storage._write`），这是
  原子性的关键实现细节。

## 权限与审计

- 账户 token 只能操作本账户的授权、质询与证书；越权返回 403。
- 吊销权限：管理员 token 或证书所属账户 token。
- `/audit` 仅管理员可读。
- 每次状态变更都追加一条审计记录（actor、action、target、detail、
  时间戳），包括被拒绝前的重复吊销尝试等，可全程追溯。

## HTTP 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/accounts` | 注册账户（幂等） |
| POST | `/authorizations` | 创建/复用授权请求 |
| POST | `/challenges` | 创建质询（每域名一个活跃） |
| POST | `/challenges/{id}/respond` | 提交质询回显值 |
| POST | `/certificates` | 签发（幂等） |
| POST | `/certificates/rotate` | 轮换（总是出新证书） |
| GET  | `/certificates` | 列表（可按 domain 过滤） |
| GET  | `/certificates/{serial}` | 查询证书与私钥 |
| POST | `/certificates/{serial}/revoke` | 吊销（幂等） |
| GET  | `/certificates/{serial}/status` | 吊销/过期状态 |
| GET  | `/audit` | 审计日志（管理员） |
| GET  | `/ca.pem` | 本地 CA 根证书 |
