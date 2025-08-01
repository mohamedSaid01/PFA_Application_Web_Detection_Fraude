from pydantic import BaseModel
from datetime import datetime
from typing import List

class LogResponse(BaseModel):
    id: int
    user_id: int | None
    action: str
    description: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class LogSummaryResponse(BaseModel):
    logs: List[LogResponse]
    login_success_count: int
    login_failed_count: int
    update_profile_success_count: int
    update_profile_failed_count: int
    change_password_success_count: int
    change_password_failed_count: int