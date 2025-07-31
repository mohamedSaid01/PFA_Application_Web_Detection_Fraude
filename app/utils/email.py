import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, FRONTEND_URL

def send_reset_password_email(email: str, token: str): 
    msg = MIMEMultipart()
    msg["From"] = SMTP_USERNAME
    msg["To"] = email
    msg["Subject"] = "Réinitialisation de votre mot de passe"

    # Lien de réinitialisation
    reset_link = f"{FRONTEND_URL}/reset-password?token={token}"
    body = f"""  
    Bonjour,

    Vous avez été invité à créer un mot de passe pour votre compte.
    Cliquez sur le lien suivant pour définir votre mot de passe :
    {reset_link}

    Ce lien est valable pendant 1 heure et ne peut être utilisé qu'une seule fois.
    Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.

    Cordialement,
    Votre équipe
    """
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, email, msg.as_string())
    except Exception as e:
        raise Exception(f"Erreur lors de l'envoi de l'email : {str(e)}")


