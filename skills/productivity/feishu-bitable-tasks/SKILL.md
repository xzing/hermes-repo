---
name: feishu-bitable-tasks
description: 写入任务到飞书多维表格（Bitable）
---
# 飞书多维表格任务写入

写入已完成任务到飞书多维表格。**通用流程，从对话上下文获取文档信息，获取不到时让用户发送文件或链接。**

## 认证信息（固化）
- App ID: `cli_a964a24c23789cdb`
- App Secret: `***`（见记忆）
- 获取 token: `POST https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal`

## 写入流程

### Step 1: 获取 tenant_access_token
```bash
curl -s -X POST "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal" \
  -H "Content-Type: application/json" \
  -d '{"app_id": "cli_a964a24c23789cdb", "app_secret": "见记忆文件"}'
```

### Step 2: 写入记录
```bash
curl -s -X POST "https://open.feishu.cn/open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/records" \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": {
      "待办事项": "任务内容",
      "是否已完成": true,
      "优先级": "🟡P1-一般",
      "执行人": [{"id": "ou_***", "name": "AIX"}]
    }
  }'
```

## 字段说明
| 字段 | 类型 | 说明 |
|------|------|------|
| 待办事项 | text | 主字段，必填 |
| 是否已完成 | checkbox | boolean，设为 true |
| 优先级 | single_select | 默认 🟡P1-一般 |
| 执行人 | user | AIX |

## 上下文获取优先级
1. 从对话历史/记忆获取 app_token 和 table_id
2. 从用户发送的飞书文档链接解析（URL 格式: `.../bitable/app{app_token}/...`）
3. 都获取不到 → 让用户提供

## 注意事项
- 完成日期是公式字段，传入 `是否已完成=true` 后自动计算，无需手动传入
- 不需要每次登录，直接用固化凭证调用 API
