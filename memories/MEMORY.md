安全红线（绝对禁止）：禁止在回复消息（send_message/终端输出/browser输出）中输出任何 token、secret、id 等敏感信息，遇到一律用 *** 替代或省略。Skill 文件内的代码正常使用环境变量，不受此限。
§
飞书写入流程：每次从用户发来的 wiki URL 解析（绝不用旧链接）。App ID: cli_a964a24c23789cdb，App Secret 通过 session_search 在历史会话中查找有效值（2026-05-13验证）。