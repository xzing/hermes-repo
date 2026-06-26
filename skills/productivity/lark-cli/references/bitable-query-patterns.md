# Bitable 查询参考（已验证）

## 获取 token 并查询最新记录

```bash
TOKEN=... # 重新获取，不要复用过期 token
curl -s "https://open.feishu.cn/open-apis/bitable/v1/apps/${APP_TOKEN}/tables/${TABLE_ID}/records?page_size=200" \
  -H "Authorization: Bearer ${TOKEN}"
```

## 客户端排序取最新 N 条（Python）

```python
import json, datetime

response = ...  # curl 结果
data = json.loads(response)
items = data['data']['items']

# 按 record_id 倒序 ≈ 按创建时间倒序
sorted_items = sorted(items, key=lambda x: x.get('record_id', ''), reverse=True)

# 或按时间字段
sorted_items = sorted(items, key=lambda x: x['fields'].get('创建时间', 0), reverse=True)

for r in sorted_items[:5]:
    f = r['fields']
    ct = f.get('创建时间')
    ft = f.get('完成日期')
    ctdt = datetime.datetime.fromtimestamp(int(ct)/1000).strftime('%Y-%m-%d %H:%M') if ct else '?'
    ftdt = datetime.datetime.fromtimestamp(int(ft)/1000).strftime('%Y-%m-%d %H:%M') if ft else '?'
    print(f"[{ctdt}] 完成({ftdt}): {f.get('待办事项', '?')}")
```

## 已知错误码

| 错误码 | 含义 | 解决 |
|--------|------|------|
| 1254016 `InvalidSort` | API 不支持 `sort=CreatedAt` 参数 | 客户端排序 |
| 99991663 `Invalid access token` | token 过期 | 重新获取 tenant_access_token |
| 10014 `app secret invalid` | App Secret 错误 | 检查 FEISHU_APP_SECRET 环境变量 |

## 忠林的 Bitable（默认表）

- app_token: `SCYEbjfSrauCuhso5ZJcB7uZnzb`
- table_id: `tblHvzylVBhxv2Q0`
- 总记录数: 192（2026-06-26）
