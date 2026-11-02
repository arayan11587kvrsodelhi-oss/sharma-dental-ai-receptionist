"""Application configuration for Sharma Dental AI."""
import os
from typing import Literal

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY: Keep the secret key used in production secret!
SECRET_KEY = os.environ.get("SECRET_KEY", "django-insecure-dev-key-do-not-use-in-production")

# API Settings
DEBUG = os.environ.get("DEBUG", "True").lower() == "true"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

# Timezone
TIMEZONE = os.environ.get("TIMEZONE", "Asia/Kolkata")

# Clinic Settings
CLINIC_NAME = os.environ.get("CLINIC_NAME", "Sharma Dental Clinic")
CLINIC_CITY = os.environ.get("CLINIC_CITY", "Delhi")
CLINIC_OPEN_TIME = os.environ.get("CLINIC_OPEN_TIME", "10:00")
CLINIC_CLOSE_TIME = os.environ.get("CLINIC_CLOSE_TIME", "20:00")
APPOINTMENT_DURATION_MINUTES = int(os.environ.get("APPOINTMENT_DURATION_MINUTES", "30"))

# Supabase
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

# AI
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

# Telephony
TELEPHONY_PROVIDER = os.environ.get("TELEPHONY_PROVIDER", "mock")
ALLOW_LIVE_CALLS = os.environ.get("ALLOW_LIVE_CALLS", "false").lower() == "true"

# Environment
APP_ENV = os.environ.get("APP_ENV", "development")
APP_NAME = os.environ.get("APP_NAME", "Sharma Dental AI")

# CORS
CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

# Rate limiting
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))

# Security
ENVIRONMENT: Literal["development", "staging", "production"] = (
    os.environ.get("ENVIRONMENT", "development")
)


class Settings:
    """Settings container for backwards compatibility."""
    SECRET_KEY = SECRET_KEY
    DEBUG = DEBUG
    HOST = HOST
    PORT = PORT
    TIMEZONE = TIMEZONE
    CLINIC_NAME = CLINIC_NAME
    CLINIC_CITY = CLINIC_CITY
    CLINIC_OPEN_TIME = CLINIC_OPEN_TIME
    CLINIC_CLOSE_TIME = CLINIC_CLOSE_TIME
    APPOINTMENT_DURATION_MINUTES = APPOINTMENT_DURATION_MINUTES
    SUPABASE_URL = SUPABASE_URL
    SUPABASE_ANON_KEY = SUPABASE_ANON_KEY
    SUPABASE_SERVICE_ROLE_KEY = SUPABASE_SERVICE_ROLE_KEY
    GEMINI_API_KEY = GEMINI_API_KEY
    GEMINI_MODEL = GEMINI_MODEL
    TELEPHONY_PROVIDER = TELEPHONY_PROVIDER
    ALLOW_LIVE_CALLS = ALLOW_LIVE_CALLS
    APP_ENV = APP_ENV
    APP_NAME = APP_NAME
    CORS_ORIGINS = CORS_ORIGINS
    RATE_LIMIT_ENABLED = RATE_LIMIT_ENABLED
    RATE_LIMIT_PER_MINUTE = RATE_LIMIT_PER_MINUTE
    ENVIRONMENT = ENVIRONMENT


settings = Settings()