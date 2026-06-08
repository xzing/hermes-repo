#!/usr/bin/env python3
"""
检查当天是否为中国工作日（节假日调休也算上班），是则发送飞书群消息提醒
"""

import sys
import subprocess
from datetime import datetime, date
import urllib.request
import urllib.error
import json

# ============ 配置 ============
FEISHU_APP_ID = "cli_a964a24c23789cdb"
FEISHU_APP_SECRET = ""  # 从环境变量 FEISHU_APP_SECRET 获取
FEISHU_GROUP_ID = "oc_9632e08952cb974eb35198a280584f6a"  # AI 专项小组群 ID
GROUP_NAME = "AI专项小组"
MESSAGE_TEMPLATE = """📌 提醒：今天是 {date} 工作日！
请各位同事及时在飞书文档中更新今日工作内容，整理待办事项。"""

# ============ 中国法定节假日判断 ============
def get_chinese_holidays(year: int) -> set:
    """获取指定年份的法定节假日（不含调休）"""
    # 2026年法定节假日
    holidays = {
        # 元旦
        date(year, 1, 1): "元旦",
        # 春节
        date(year, 2, 17): "春节",
        date(year, 2, 18): "春节",
        date(year, 2, 19): "春节",
        date(year, 2, 20): "春节",
        date(year, 2, 21): "春节",
        date(year, 2, 22): "春节",
        date(year, 2, 23): "春节",
        date(year, 2, 24): "春节",
        # 清明节
        date(year, 4, 4): "清明节",
        date(year, 4, 5): "清明节",
        date(year, 4, 6): "清明节",
        # 劳动节
        date(year, 5, 1): "劳动节",
        date(year, 5, 2): "劳动节",
        date(year, 5, 3): "劳动节",
        date(year, 5, 4): "劳动节",
        date(year, 5, 5): "劳动节",
        # 端午节
        date(year, 6, 19): "端午节",
        date(year, 6, 20): "端午节",
        date(year, 6, 21): "端午节",
        # 中秋节
        date(year, 9, 25): "中秋节",
        date(year, 9, 26): "中秋节",
        date(year, 9, 27): "中秋节",
        # 国庆节
        date(year, 10, 1): "国庆节",
        date(year, 10, 2): "国庆节",
        date(year, 10, 3): "国庆节",
        date(year, 10, 4): "国庆节",
        date(year, 10, 5): "国庆节",
        date(year, 10, 6): "国庆节",
        date(year, 10, 7): "国庆节",
        date(year, 10, 8): "国庆节",
    }
    return holidays

def get_chinese_workdays_adjustments(year: int) -> set:
    """获取调休上班日（周末被调整为工作日）"""
    # 2026年调休上班日（周末上班）
    adjustments = {
        date(year, 2, 15): "春节调休",   # 周日 -> 工作日
        date(year, 2, 28): "春节调休",   # 周六 -> 工作日
        date(year, 4, 26): "五一调休",   # 周日 -> 工作日
        date(year, 9, 28): "中秋调休",   # 周一 -> 工作日
        date(year, 10, 11): "国庆调休",  # 周日 -> 工作日
    }
    return adjustments

def is_chinese_workday(d: date) -> bool:
    """判断是否为工作日（考虑法定节假日和调休）"""
    # 周末（周六、周日）
    is_weekend = d.weekday() in (5, 6)  # 5=周六, 6=周日
    
    holidays = get_chinese_holidays(d.year)
    adjustments = get_chinese_workdays_adjustments(d.year)
    
    # 调休上班日 -> 工作日
    if d in adjustments:
        return True
    
    # 法定节假日 -> 非工作日
    if d in holidays:
        return False
    
    # 普通周末 -> 非工作日
    if is_weekend:
        return False
    
    # 其他为工作日（周一~周五）
    return True

# ============ 飞书发消息 ============
def get_tenant_access_token() -> str:
    """获取 tenant_access_token"""
    import os
    app_secret = os.environ.get("FEISHU_APP_SECRET", "")
    if not app_secret:
        print("错误: 未找到 FEISHU_APP_SECRET 环境变量")
        return None
    payload = json.dumps({"app_id": FEISHU_APP_ID, "app_secret": app_secret}).encode("utf-8")
    req = urllib.request.Request(
        "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("code") == 0:
                return result.get("tenant_access_token", "")
            else:
                print(f"认证错误: {result}")
                return None
    except urllib.error.URLError as e:
        print(f"网络错误: {e}")
        return None

def send_feishu_message(content: str) -> bool:
    """通过飞书 IM API 发送消息到群组"""
    token = get_tenant_access_token()
    if not token:
        return False

    msg_payload = {
        "msg_type": "text",
        "receive_id": FEISHU_GROUP_ID,
        "content": json.dumps({"text": content})
    }

    data = json.dumps(msg_payload).encode("utf-8")
    req = urllib.request.Request(
        "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id",
        data=data,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("code") == 0:
                return True
            else:
                print(f"飞书 API 错误: {result}")
                return False
    except urllib.error.URLError as e:
        body = e.read().decode("utf-8")
        print(f"网络错误: {e},响应体: {body}")
        return False

# ============ 主逻辑 ============
def main():
    today = date.today()
    is_workday = is_chinese_workday(today)
    
    date_str = today.strftime("%Y年%m月%d日")
    
    print(f"今日日期: {date_str} ({'工作日' if is_workday else '非工作日'})")
    
    if not is_workday:
        print("今天不是工作日，不发送提醒消息。")
        sys.exit(0)
    
    # 发送飞书消息
    message = MESSAGE_TEMPLATE.format(date=date_str)
    print(f"\n发送消息到 {GROUP_NAME}:")
    print(message)
    print()
    
    success = send_feishu_message(message)
    if success:
        print("✅ 消息发送成功！")
        sys.exit(0)
    else:
        print("❌ 消息发送失败！")
        sys.exit(1)

if __name__ == "__main__":
    main()