---
name: lark-cli
description: lark-cli (飞书 CLI) 封装 — 读取/写入飞书文档、Wiki、多维表格、消息等。认证使用环境变量 FEISHU_APP_SECRET，无需每次申请权限。注意：lark-cli 自身的 device auth 和 MCP 在本环境不可用，所有操作走直接 API 调用。
category: productivity
triggers:
  - 读飞书文档
  - 写飞书文档
  - 查飞书 wiki
  - 读飞书多维表格
  - 写飞书多维表格
  - 发飞书消息
  - lark-cli
  - 飞书文件
  - feishu drive
  - feishu docs
---

# lark-cli Skill

## 认证

**不要用 `lark-cli auth`**（device auth 在本环境不可用）。直接用环境变量：

```bash
FEISHU_APP_ID=cli_a964a24c23789cdb
FEISHU_APP_SECRET=从环境变量读取（不要硬编码）
```

获取 token：
```bash
TOKEN=$(curl -s -X POST "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal" \
  -H "Content-Type: application/json" \
  -d "{\"app_id\":\"$FEISHU_APP_ID\",\"app_secret\":\"$FEISHU_APP_SECRET\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('tenant_access_token',''))")
```

## Wiki 节点查询

```bash
# 查询 wiki 节点（支持 wiki URL）
curl -s "https://open.feishu.cn/open-apis/wiki/v2/spaces/get_node?token={wiki_token}" \
  -H "Authorization: Bearer $TOKEN"
```

返回 `obj_type`：bitable / docx / sheet / mindnote 等。

## 文档读取 (docs)

```bash
# 读取文档块
DOC_TOKEN="..."  # 从 wiki obj_token 获取
curl -s "https://open.feishu.cn/open-apis/docx/v1/documents/${DOC_TOKEN}/blocks?document_revision_id=-1&page_size=500" \
  -H "Authorization: Bearer $TOKEN"
```

## 多维表格 (bitable)

```bash
APP_TOKEN="..."   # bitable 的 app_token
TABLE_ID="..."   # table_id，从 wiki 节点 obj_token 对应

# 列出记录（page_size 最大 100，total>100 时需分页）
curl -s "https://open.feishu.cn/open-apis/bitable/v1/apps/${APP_TOKEN}/tables/${TABLE_ID}/records?page_size=100" \
  -H "Authorization: Bearer $TOKEN"

# ⚠️ sort 参数不支持（API 返回 InvalidSort 1254016），客户端排序：
# record_id 倒序 = 最新创建的记录在前
# 或按创建时间字段倒序
```

**Pitfall — Bitable sort 参数无效**：
飞书 Bitable Records API **不支持** `sort=CreatedAt` 等排序参数，传入会返回 `InvalidSort (1254016)`。
正确做法：获取所有记录后在客户端排序。
## 多维表格 (bitable)

```bash
APP_TOKEN="..."   # bitable app_token
TABLE_ID="..."    # table_id

# 列出记录（page_size 最大 100，total>100 时需分页或用 page_size=200）
curl -s "https://open.feishu.cn/open-apis/bitable/v1/apps/${APP_TOKEN}/tables/${TABLE_ID}/records?page_size=200" \
  -H "Authorization: Bearer $TOKEN"

# 客户端排序取最新记录（API 不支持 server-side sort by time）：
# sort=CreatedAt 返回 InvalidSort (1254016)，必须本地排序
# 按 record_id 倒序 ≈ 按创建时间倒序（record_id 递增）
# 或按 "创建时间" 字段值排序
```

### 查最新 N 条记录的坑

- ❌ `sort=CreatedAt` → `InvalidSort (1254016)`，API 不支持
- ✅ 一次性拉全部记录（page_size=200），客户端排序：
  ```python
  sorted_items = sorted(items, key=lambda x: x.get('record_id',''), reverse=True)
  # 或按时间字段
  sorted_items = sorted(items, key=lambda x: x['fields'].get('创建时间',0), reverse=True)
  ```

### 写入记录（DateTime 字段用毫秒时间戳）

```bash
TS=$(date +%s)000
curl -s -X POST "https://open.feishu.cn/open-apis/bitable/v1/apps/${APP_TOKEN}/tables/${TABLE_ID}/records" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"fields\":{\"待办事项\":\"任务内容\",\"创建时间\":${TS},\"是否已完成\":true,\"优先级\":\"🟡P1-一般\",\"执行人\":[{\"id\":\"ou_fe6053b8bebb3e0846025b32a5615584\",\"name\":\"AIX\",\"en_name\":\"AIX\",\"email\":\"\",\"avatar_url\":\"\"}]}}"

# 更新记录
curl -s -X PUT "https://open.feishu.cn/open-apis/bitable/v1/apps/${APP_TOKEN}/tables/${TABLE_ID}/records/{record_id}" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fields":{"是否已完成":true,"完成日期":'"$(date +%s)000"'}}'
```

### token 失效处理

- 症状：`Invalid access token (99991663)`
- 解决：重新获取 tenant_access_token，不要复用超过 2 小时的旧 token

> 完整查询/排序参考见 `references/bitable-query-patterns.md`

## 文件/云文档 (drive)

```bash
# 下载文件
FILE_TOKEN="..."
curl -s -L "https://open.feishu.cn/open-apis/drive/v1/files/${FILE_TOKEN}/download" \
  -H "Authorization: Bearer $TOKEN" -o filename

# 搜索文件
curl -s -X POST "https://open.feishu.cn/open-apis/suite/docs-api/search/object" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"search_key":"关键词","count":10,"offset":0}'
```

## 消息 (im)

```bash
# 发消息
curl -s -X POST "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"receive_id":"ou_...","msg_type":"text","content":"{\"text\":\"消息内容\"}"}'
```

## 常用 API 端头

| 服务 | Base URL |
|------|----------|
| 认证 | `https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal` |
| Wiki | `https://open.feishu.cn/open-apis/wiki/v2/spaces/get_node?token=` |
| 文档 | `https://open.feishu.cn/open-apis/docx/v1/documents/` |
| 多维表格 | `https://open.feishu.cn/open-apis/bitable/v1/apps/` |
| 云文档 | `https://open.feishu.cn/open-apis/drive/v1/files/` |
| 消息 | `https://open.feishu.cn/open-apis/im/v1/messages` |

## 已知限制

- `lark-cli auth login` — Device Auth 在本环境不可用（client secret invalid）
- `lark-cli docs +fetch` — MCP 不可用，改为直接 API
- 用户身份操作（如某些需要 user token 的接口）— Bot token 覆盖大部分场景，少数场景需 user token
