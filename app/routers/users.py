from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.users.user import User
from app.models.users.ResetToken import ResetToken
from app.schemas.user import UserResponse, UserUpdate, UserAdminCreate, ResetPassword
from app.utils.jwt import get_current_user
from app.utils.email  import send_reset_password_email
from app.models.enum.enums import Role
from passlib.context import CryptContext
from typing import List
from secrets import token_urlsafe
from datetime import datetime, timedelta

router = APIRouter(prefix="/users", tags=["Users"])

# Configuration pour le hachage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Récupérer tous les utilisateurs (admin uniquement)
@router.get("/", response_model=List[UserResponse])
def get_all_users(db: Session = Depends(get_db), user_id: str = Depends(get_current_user)):
    try:
        user_id_int = int(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")
    
    current_user = db.query(User).filter(User.id == user_id_int).first()
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Réservé aux administrateurs")
    
    users = db.query(User).all()
    return users

# Récupérer un utilisateur par ID
@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db), current_user_id: str = Depends(get_current_user)):
    try:
        current_user_id_int = int(current_user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")
    
    current_user = db.query(User).filter(User.id == current_user_id_int).first()
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur connecté non trouvé")
    
    # Les utilisateurs peuvent voir leurs propres données, les admins peuvent voir tout
    if current_user.role != Role.ADMIN and str(current_user.id) != str(user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Non autorisé à accéder à cet utilisateur")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")
    return user

# Créer un utilisateur (admin uniquement, sans mot de passe)
@router.post("/", response_model=UserResponse)
def create_user(user: UserAdminCreate, db: Session = Depends(get_db), current_user_id: str = Depends(get_current_user)):
    try:
        current_user_id_int = int(current_user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")
    
    current_user = db.query(User).filter(User.id == current_user_id_int).first()
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur connecté non trouvé")
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Réservé aux administrateurs")
    
    # Vérifier si l'email existe déjà
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email déjà enregistré")
    
    # Créer un nouvel utilisateur sans mot de passe
    new_user = User(
        email=user.email,
        password=None,  # Pas de mot de passe
        firstName=user.firstName,
        lastName=user.lastName,
        phoneNumber=user.phoneNumber,
        department=user.department,
        role=user.role
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Générer un token de réinitialisation
    token = token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    reset_token = ResetToken(
        user_id=new_user.id,
        token=token,
        expires_at=expires_at,
        used=False
    )
    
    db.add(reset_token)
    db.commit()
    
    # Envoyer l'email de réinitialisation
    try:
        send_reset_password_email(new_user.email, token)
    except Exception as e:
        db.delete(new_user)  # Annuler la création si l'email échoue
        db.delete(reset_token)
        db.commit()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erreur lors de l'envoi de l'email : {str(e)}")
    
    return new_user

# Réinitialiser le mot de passe
@router.post("/reset-password")
def reset_password(data: ResetPassword, db: Session = Depends(get_db)):
    # Vérifier le token
    reset_token = db.query(ResetToken).filter(ResetToken.token == data.token).first()
    if not reset_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token invalide")
    
    if reset_token.used:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token déjà utilisé")
    
    if reset_token.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token expiré")
    
    # Récupérer l'utilisateur
    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")
    
    # Mettre à jour le mot de passe
    user.password = pwd_context.hash(data.new_password)
    reset_token.used = True
    
    db.commit()
    db.refresh(user)
    return {"message": "Mot de passe défini avec succès"}

# Mettre à jour un utilisateur
@router.put("/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db), current_user_id: str = Depends(get_current_user)):
    try:
        current_user_id_int = int(current_user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")
    
    current_user = db.query(User).filter(User.id == current_user_id_int).first()
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur connecté non trouvé")
    
    # Les utilisateurs peuvent mettre à jour leurs propres données, les admins peuvent tout mettre à jour
    if current_user.role != Role.ADMIN and str(current_user.id) != str(user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Non autorisé à modifier cet utilisateur")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")
    
    # Mettre à jour les champs fournis
    update_data = user_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(user, key, value)
    
    db.commit()
    db.refresh(user)
    return user

# Supprimer un utilisateur (admin uniquement)
@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), current_user_id: str = Depends(get_db)):
    try:
        current_user_id_int = int(current_user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")
    
    current_user = db.query(User).filter(User.id == current_user_id_int).first()
    if not current_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur connecté non trouvé")
    if current_user.role != Role.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Réservé aux administrateurs")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")
    
    db.delete(user)
    db.commit()
    return {"message": "Utilisateur supprimé avec succès"}