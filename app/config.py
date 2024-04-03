from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    email: str = "lokesh.ksn@mind-graph.com"  
    API_V1_STR: str = "/api/v1"
    MONGODB_URL: str = "mongodb+srv://loki_user:loki_password@clmdemo.1yw93ku.mongodb.net/?retryWrites=true&w=majority&appName=Clmdemo"
    MONGODB_DB_NAME: str = "CLMDigiSignDB"
    # MONGODB_COLLECTION_NAME: str = "CLMDigiSignDB"
    OTP_LENGTH: int = 6
    OTP_EXPIRY_MINUTES: int = 5
    MAIL_SSL_TLS: bool = True  # Specify whether SSL/TLS should be used for email
    USE_CREDENTIALS: bool = True  # Specify whether credentials should be used
    MAIL_STARTTLS: bool = True
    support_email:str = "karun.addala@gmail.com"
    support_phone_number:str = "1234567890"
    company_name:str= "MindGraph Technologies"
    name:str="Karun"
    role:str="CEO"
settings = Settings()

