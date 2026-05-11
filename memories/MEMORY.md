飞书多维表格写入 (Bitable)：文档「📋忠林的工作事项」
- URL token: EVq6wyv1xicuCHkQLhBcVUgZngd
- App token (bitable): SCYEbjfSrauCuhso5ZJcB7uZnzb
- Table ID: tblHvzylVBhxv2Q0
- 字段:
  - 待办事项 (fldO8jwfSy/text): 主字段，必填
  - 创建时间 (fldS52UyHF): 自动填充，毫秒时间戳
  - 截止日期 (fldl33zx7C): 毫秒时间戳
  - 是否已完成 (fld76NRu00): checkbox，boolean
  - 完成日期 (fldd2w9mio): 毫秒时间戳，注意是公式字段，已完成时自动填充当前时间
  - 优先级 (fldaR9enAV): 单选，字符串如 "🟡P1-一般"
  - 执行人 (fldqVXMJ5f): 用户/多选，格式 [{"id": "ou_fe6053b8bebb3e0846025b32a5615584", "name": "AIX", "en_name": "AIX", "email": "", "avatar_url": "..."}]
- 写入步骤:
  1. POST /open-apis/auth/v3/tenant_access_token/internal 获取 token
  2. POST /open-apis/bitable/v1/apps/{app_token}/tables/{table_id}/records 写入
- 日期格式: 毫秒时间戳 = $(date +%s)000 或 $(date +%s)*1000
- 默认值: 优先级="🟡P1-一般", 执行人=[{"id": "ou_fe6053b8bebb3e0846025b32a5615584", "name": "AIX"}]
- 注意: 完成日期是公式字段，不需要手动传入，设置 是否已完成=true 后自动计算