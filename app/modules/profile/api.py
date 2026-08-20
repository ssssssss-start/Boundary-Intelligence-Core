from fastapi import APIRouter, Query

from app.modules.profile.service import build_profile_summary
from app.modules.training_camp.service import DEFAULT_USER_ID


router = APIRouter(tags=["module:profile"])


@router.get("/profile/summary")
async def profile_summary(user_id: str = Query(DEFAULT_USER_ID, description="用户ID")):
    return build_profile_summary(user_id=user_id)
