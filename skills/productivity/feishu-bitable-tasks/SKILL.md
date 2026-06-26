---
name: feishu-bitable-tasks
description: 写入任务到飞书多维表格（Bitable）
---

# 飞书多维表格任务写入

**每次写入都必须从用户发来的 wiki URL 解析，绝不使用记忆中的旧链接。**

## 认证信息（固定）
- App ID: `cli_a964a24c23789cdb`
- App Secret: 环境变量 `FEISHU_APP_SECRET`

## 完整流程

### Step 1: 获取 tenant_access_token
```bash
curl -s -X POST "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal" \
  -H "Content-Type: application/json" \
  -d '{"app_id": "cli_a964a24c23789cdb", "app_secret": "'"$FEISHU_APP_SECRET"'"}'
```

### Step 2: 从 wiki 链接获取 app_token
用户发来的 wiki URL 格式：`https://xxx.feishu.cn/wiki/{wiki_token}`

```bash
curl -s "https://open.feishu.cn/open-apis/wiki/v2/spaces/get_node?token={wiki_token}" \
  -H "Authorization: Bearer {token}"
```
返回的 `obj_token` 即为多维表格 app_token（`obj_type` 应为 `bitable`）。

### Step 3: 获取 table_id
```bash
curl -s "https://open.feishu.cn/open-apis/bitable/v1/apps/{app_token}/tables" \
  -H "Authorization: Bearer {token}"
```

### Step 4: 查看字段（首次写入时）
```bash
curl -s "https://open.feishu.cn/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/fields" \
  -H "Authorization: Bearer {token}"
```

### Step 5: 写入记录（完整字段）
```bash
TS=$(date +%s)000  # unix timestamp，毫秒级（重要：必须乘以1000，表格要求毫秒）
curl -s -X POST "https://open.feishu.cn/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/records" \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d "{
    \"fields\": {
      \"待办事项\": \"任务内容\",
      \"是否已完成\": true,
      \"创建时间\": ${TS},
      \"优先级\": \"🟡P1-一般\",
      \"执行人\": [{\"id\": \"ou_fe6053b8bebb3e0846025b32a5615584\", \"name\": \"AIX\", \"en_name\": \"AIX\", \"email\": \"\", \"avatar_url\": \"\"}]
    }
  }"
```

**注意**：创建时间、优先级、执行人三个字段每次都必须写入，不能遗漏。

## 字段说明（常见字段）
| 字段 | 类型 | 说明 |
|------|------|------|
| 待办事项 | text | 主字段，必填 |
| 是否已完成 | checkbox | boolean，设为 true |
| 创建时间 | datetime | unix timestamp **毫秒级**（`$(date +%s)000`） |
| 优先级 | single_select | 默认 🟡P1-一般 |
| 执行人 | user | AIX: ou_fe6053b8bebb3e0846025b32a5615584 |

## 关键原则
- **每次写入必须从用户发来的 wiki URL 解析**，绝不使用记忆/旧链接
- wiki token 从 URL path 中提取，例如 `wiki/EVq6wyv1xicuCHkQLhBcVUgZngd` → token = `EVq6wyv1xicuCHkQLhBcVUgZngd`
- tenant_access_token 有效期约2小时，超时重新获取即可
- 不需要每次登录，用固化凭证直接调用 API
