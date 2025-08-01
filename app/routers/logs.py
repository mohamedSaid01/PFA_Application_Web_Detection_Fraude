from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.users.user import User
from app.models.log import Log
from app.schemas.log import LogResponse, LogSummaryResponse
from app.models.enum.enums import Role
from app.utils.jwt import get_current_user

router = APIRouter(prefix="/logs", tags=["Logs"])

@router.get("/", response_model=LogSummaryResponse)
def get_logs(db: Session = Depends(get_db), user_id: str = Depends(get_current_user)):
    try:
        user_id_int = int(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")

    current_user = db.query(User).filter(User.id == user_id_int).first()
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Réservé aux administrateurs")

    # Get all logs
    logs = db.query(Log).all()

    # Count specific actions
    counts = db.query(Log.action, func.count(Log.id)).group_by(Log.action).all()
    count_dict = {action: count for action, count in counts}

    # Extract counts for specific actions
    login_success_count = count_dict.get("login_success", 0)
    login_failed_count = count_dict.get("login_failed", 0)
    update_profile_success_count = count_dict.get("update_profile_success", 0)
    update_profile_failed_count = count_dict.get("update_profile_failed", 0)
    change_password_success_count = count_dict.get("change_password_success", 0)
    change_password_failed_count = count_dict.get("change_password_failed", 0)

    # Return logs and counts
    return {
        "logs": logs,
        "login_success_count": login_success_count,
        "login_failed_count": login_failed_count,
        "update_profile_success_count": update_profile_success_count,
        "update_profile_failed_count": update_profile_failed_count,
        "change_password_success_count": change_password_success_count,
        "change_password_failed_count": change_password_failed_count
    }