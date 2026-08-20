from typing import Any, Dict

from app.modules.training_camp.service import DEFAULT_USER_ID, build_game_report


def build_profile_summary(user_id: str = DEFAULT_USER_ID) -> Dict[str, Any]:
    training_report = build_game_report(user_id=user_id)
    return {
        "message": "个人中心数据生成完成",
        "user_id": user_id,
        "training": training_report,
        "learning_records_source": "browser_local_storage",
        "report_records_source": "browser_local_storage",
    }

