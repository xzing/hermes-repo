安全红线（绝对禁止）：禁止在回复消息（send_message/终端输出/browser输出）中输出任何 token、secret、id 等敏感信息，遇到一律用 *** 替代或省略。Skill 文件内的代码正常使用环境变量，不受此限。
§
飞书写入流程：每次从用户发来的 wiki URL 解析（绝不用旧链接）。App ID: cli_a964a24c23789cdb，App Secret 通过 session_search 在历史会话中查找有效值（2026-05-13验证）。
§
飞书（2026-06-26）：lark-cli 的 Device Auth 和 MCP 在本环境均不可用（前者报 "client secret invalid"，后者 mcp.feishu.cn 网络不通）。但 Bot API（tenant_access_token）完全正常。已创建技能 lark-cli（~/.hermes/skills/productivity/lark-cli/）作为直接 API 封装。FEISHU_APP_SECRET 环境变量已注入且有效（32位，code:0 验证）。
§
飞书Bot身份（默认）：App ID=cli_a964a24c23789cdb，App Secret用环境变量$FEISHU_APP_SECRET（已注入，32位）。Bot API完全可用，读写Wiki/多维表格/文档/消息均无需每次授权。token获取：POST https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal。lark-cli的Device Auth和MCP不可用，已创建skill ~/.hermes/skills/productivity/lark-cli/ 封装直接API替代。
飞书Bitable默认表：app_token=SCYEbjfSrauCuhso5ZJcB7uZnzb，table_id=tblHvzylVBhxv2Q0（忠林的工作事项）。
飞书写入默认字段：待办事项、创建时间（毫秒时间戳）、截止日期、是否已完成、完成日期（毫秒时间戳）、优先级（默认"🟡P1-一般"）、执行人（默认open_id=ou_fe6053b8bebb3e0846025b32a5615584）。