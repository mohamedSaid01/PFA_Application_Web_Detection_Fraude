from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.users.user import User
from app.schemas.user import (
    UserCreate, 
    UserLogin, 
    UserResponse,
    UserUpdateProfil,
    ChangePasswordRequest
)
from passlib.context import CryptContext
from app.utils.jwt import create_access_token, get_current_user
from app.config import ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Configuration pour le hachage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@router.post("/signup", response_model=UserResponse)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    # Vérifier si l'email existe déjà
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email déjà enregistré"
        )
    
    # Hacher le mot de passe
    hashed_password = pwd_context.hash(user.password)
    
    # Créer un nouvel utilisateur
    new_user = User(
        email=user.email,
        password=hashed_password,
        firstName=user.firstName,
        lastName=user.lastName,
        phoneNumber=user.phoneNumber,
        department=user.department,
        role=user.role
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

@router.post("/signin")
def signin(user: UserLogin, db: Session = Depends(get_db), response: Response = None):
    # Vérifier si l'utilisateur existe
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect"
        )
    
    # Vérifier le mot de passe
    if not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect"
        )
    
    # Générer le token JWT
    access_token = create_access_token(data={"sub": str(db_user.id)})
    
    # Stocker le token dans un cookie sécurisé
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=False,   # Mettre à True en production avec HTTPS
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    return {"message": "Connexion réussie", "user_id": db_user.id}

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    user_id: str = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    # Récupérer l'utilisateur depuis la base de données
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    return db_user

@router.post("/signout")
def signout(response: Response):
    # Supprimer le cookie access_token
    response.delete_cookie(
        key="access_token",
        httponly=True,
        secure=False,  # Mettre à True en production avec HTTPS
        samesite="lax"
    )
    return {"message": "Déconnexion réussie"}

@router.put("/update-profile", response_model=UserResponse)
def update_profile(
    user_update: UserUpdateProfil,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Met à jour les informations du profil utilisateur
    """
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    
    # Vérifier si l'email est modifié et existe déjà
    if user_update.email and user_update.email != db_user.email:
        existing_user = db.query(User).filter(User.email == user_update.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email déjà utilisé par un autre utilisateur"
            )
    
    # Mettre à jour tous les champs non-None de user_update
    update_data = user_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_user, field, value)
    
    db.commit()
    db.refresh(db_user)
    
    return db_user


@router.put("/change-password")
def change_password(
    password_data: ChangePasswordRequest,
    user_id: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change le mot de passe de l'utilisateur
    """
    # Vérifier que les nouveaux mots de passe correspondent
    if password_data.new_password != password_data.confirm_new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Les nouveaux mots de passe ne correspondent pas"
        )
    
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    
    # Vérifier l'ancien mot de passe
    if not pwd_context.verify(password_data.old_password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ancien mot de passe incorrect"
        )
    
    # Vérifier que le nouveau mot de passe est différent
    if pwd_context.verify(password_data.new_password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le nouveau mot de passe doit être différent de l'ancien"
        )
    
    # Mettre à jour le mot de passe
    db_user.password = pwd_context.hash(password_data.new_password)
    db.commit()
    
    return {"message": "Mot de passe mis à jour avec succès"}