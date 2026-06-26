---
name: feishu-leming-bitable
description: 写入飞书多维表格任务（从用户提供的 wiki 链接获取）
tags: []
related_skills:
  - feishu-bitable-tasks  # 泛化版，也覆盖多维表格写入
---

# 飞书多维表格写入流程

**每次写入都需要从用户发来的 wiki 链接解析，绝不使用记忆中的旧链接。**

## 完整流程

### Step 1: 获取 tenant_access_token
```bash
TOKEN=$(curl -s -X POST "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal" \
  -H "Content-Type: application/json" \
  -d '{"app_id": "cli_a964a24c23789cdb", "app_secret": "'"$FEISHU_APP_SECRET"'"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('tenant_access_token',''))")
```

### Step 2: 从 wiki 链接获取 app_token
用户发来的 wiki URL 格式：`https://xxx.feishu.cn/wiki/{wiki_token}`

用 wiki token 调用节点 API：
```bash
curl -s "https://open.feishu.cn/open-apis/wiki/v2/spaces/get_node?token=${WIKI_TOKEN}" \
  -H "Authorization: Bearer ${TOKEN}"
```
返回的 `obj_token` 即为多维表格的 app_token，`obj_type` 应为 `bitable`。

### Step 3: 获取 table_id
```bash
curl -s "https://open.feishu.cn/open-apis/bitable/v1/apps/${APP_TOKEN}/tables" \
  -H "Authorization: Bearer ${TOKEN}"
```

### Step 4: 查看字段（首次写入时）
```bash
curl -s "https://open.feishu.cn/open-apis/bitable/v1/apps/${APP_TOKEN}/tables/${TABLE_ID}/fields" \
  -H "Authorization: Bearer ${TOKEN}"
```

### Step 5: 写入记录（完整字段）
```bash
TS=$(date +%s)000   # unix timestamp，毫秒级（必须 ×1000，Bitable 日期字段要求毫秒）
RESP=$(curl -s -X POST "https://open.feishu.cn/open-apis/bitable/v1/apps/${APP_TOKEN}/tables/${TABLE_ID}/records" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"fields\": {
      \"待办事项\": \"任务内容\",
      \"是否已完成\": true,
      \"创建时间\": ${TS},
      \"优先级\": \"🟡P1-一般\",
      \"执行人\": [{\"id\": \"ou_fe6053b8bebb3e0846025b32a5615584\"}]
    }
  }")
echo "Response code: $(echo $RESP | python3 -c 'import sys,json; print(json.load(sys.stdin).get("code"))')"
```

**注意**：创建时间、优先级、执行人三个字段每次都必须写入，不能遗漏。

## 安全原则

**🚨 绝对禁止**：在任何输出（终端 / 消息回复 / 日志）中暴露真实 token。

| 场景 | 正确做法 | 错误做法 |
|------|---------|---------|
| 获取 token | `TOKEN=$(curl ... \| python3 -c "...")` | `curl ...` 直接输出 |
| 使用 token 调用 API | `curl -H "Authorization: Bearer ${TOKEN}"` | 单独 echo token |
| 调试/确认 | `echo "Token: ${TOKEN:0:8}***"` 或 `echo "Token: ${TOKEN:0:4}***"` | `echo $TOKEN` / `echo "token=$TOKEN"` |
| 响应处理 | 存变量或重定向 `> /tmp/resp.txt` | 直接打印包含 token 的原始 JSON |

**示例**：
```bash
# ✅ 正确：只打印 mask 后的前缀
echo "Token: ${TOKEN:0:8}***"

# ✅ 正确：重定向避免 stdout 暴露
curl ... > /tmp/resp.txt 2>&1

# ❌ 错误：终端直接打印真实 token
echo $TOKEN
```

## 认证信息（固定）
- App ID: `cli_a964a24c23789cdb`
- App Secret: 已在环境变量中配置，通过 session_search 查找有效值

## 关键原则
- **每次写入必须从用户发来的 wiki URL 获取信息**，绝不使用记忆/旧链接
- wiki token 从 URL path 中提取，例如 `wiki/EVq6wyv1xicuCHkQLhBcVUgZngd` → token = `EVq6wyv1xicuCHkQLhBcVUgZngd`
- tenant_access_token 有效期约2小时，超时需要重新获取
