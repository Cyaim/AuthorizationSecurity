# Sample.Cluster —— 生产集群演示

多个实例共享**同一个数据库**组成集群：共享数据 + 共享签名密钥 + 数据库集群版本驱动的跨实例缓存失效，**无需 Redis**。用 EF Core + SQLite 文件模拟共享库（生产换成 PostgreSQL / SQL Server 只改连接串）。

## 跑起来（同机两实例）

在两个终端分别运行，用环境变量 `CYAIM_DB` 指向**同一个** `.db` 文件：

```bash
# 实例 A
CYAIM_DB=./cluster-shared.db CYAIM_INSTANCE=A dotnet run --urls http://127.0.0.1:5401

# 实例 B（等 A 建好库后再启动，避免首次并发建表；或先跑一次迁移）
CYAIM_DB=./cluster-shared.db CYAIM_INSTANCE=B dotnet run --urls http://127.0.0.1:5402
```

> Windows PowerShell：`$env:CYAIM_DB="./cluster-shared.db"; $env:CYAIM_INSTANCE="A"; dotnet run --urls http://127.0.0.1:5401`

演示账户：`admin / Admin!123`、`alice / alice123`。

## 观察跨实例缓存失效

```bash
# 两实例初始集群版本一致
curl http://127.0.0.1:5401/instance   # {"instance":"A","clusterVersion":7}
curl http://127.0.0.1:5402/instance   # {"instance":"B","clusterVersion":7}

# 在实例 A 改某角色权限（经管理面板或管理 API）——A 的版本立即 +1，B 尚未轮询
# 约 3 秒（RefreshInterval）后，B 轮询数据库集群版本，追上 A，其权限集缓存随之失效重建
curl http://127.0.0.1:5402/instance   # {"instance":"B","clusterVersion":8}
```

即：任一实例的授权变更在一个轮询间隔内传播到全集群。

## 关键点

- **共享签名密钥**：示例用固定 `HmacSigningKey`（生产从配置/密钥管理注入）。所有实例必须一致，令牌与 SSO Cookie 才能跨实例互认。
- **共享数据库**：`AddCyaimAuthEntityFrameworkStores(db => db.UseSqlite(conn))`。令牌存储共享 → 刷新令牌轮换、重放检测、授权码一次性跨实例正确。
- **集群版本**：`EfClusterVersionStore` 用数据库单行 `UPDATE ... SET Version = Version + 1` 原子递增；`ClusterAuthStoreVersion` 轮询它同步各实例本地版本。
- **首次建表**：示例用 `EnsureCreated`（已容忍并发竞态）；**生产用 EF 迁移**，扩容前先迁移一次，而非每实例并发建表。

详见文档中心：[集群部署（多实例）](../../docs/guides/clustering.md)。
