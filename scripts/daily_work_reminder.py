#!/home/agentuser/.hermes/hermes-agent/venv/bin/python
"""
每日工作提醒检查脚本
检查当天是否为工作日（中国节假日调休），是则发群通知
"""
import os
import datetime
import chinese_calendar
from chinese_calendar import is_workday, is_holiday

def is_workday_today():
    """检查今天是否需要上班（考虑节假日和调休）"""
    today = datetime.date.today()
    return is_workday(today)

if __name__ == "__main__":
    import sys
    sys.path.insert(0, '/home/agentuser/.hermes/hermes-agent')
    
    if is_workday_today():
        print("WORKDAY")
        # 通过飞书 API 获取 tenant token 并发送消息
        import urllib.request
        import json
        
        # 获取 tenant token
        app_id = "cli_a964a24c23789cdb"
        app_secret = os.environ.get("FEISHU_APP_SECRET", "")
        if not app_secret:
            print("ERROR: FEISHU_APP_SECRET not set")
            exit(1)
        
        token_req = urllib.request.Request(
            "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
            data=json.dumps({"app_id": app_id, "app_secret": app_secret}).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(token_req) as resp:
            token_data = json.loads(resp.read())
        
        token = token_data.get("tenant_access_token", "")
        if not token:
            print("ERROR: Failed to get token")
            exit(1)
        
        # 获取 AI 专项小组 的 chat_id
        # 先搜索群
        import urllib.parse
        group_name = "AI专项小组"
        search_req = urllib.request.Request(
            f"https://open.feishu.cn/open-apis/im/v1/chats?search_key={urllib.parse.quote(group_name)}",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(search_req) as resp:
            chat_data = json.loads(resp.read())
        
        items = chat_data.get("data", {}).get("items", [])
        chat_id = None
        for item in items:
            if item.get("name", "") == "AI 专项小组":
                chat_id = item.get("chat_id", "")
                break
        
        if not chat_id:
            print("ERROR: AI专项小组 not found")
            exit(1)
        
        # 发送消息
        today_str = datetime.date.today().strftime("%Y年%m月%d日")
        msg = {
            "receive_id": chat_id,
            "msg_type": "text",
            "content": json.dumps({
                "text": f"📌 提醒：今天是 {today_str} 工作日！\n\n请各位同事及时在飞书文档中更新今日工作内容，整理待办事项。\n\n📋 文档：https://kcneu9fo2d0e.feishu.cn/wiki/NespwSnAyicS7YkO4ZZcruoYnjh"
            })
        }
        send_req = urllib.request.Request(
            f"https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id",
            data=json.dumps(msg).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(send_req) as resp:
            result = json.loads(resp.read())
        
        if result.get("code") == 0:
            print("SUCCESS: Message sent to AI专项小组")
        else:
            print(f"ERROR: Failed to send message: {result.get('msg')}")
    else:
        print("HOLIDAY: No work reminder needed")
