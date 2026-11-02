"""Main FastAPI application for Sharma Dental AI."""

import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from .core.config import settings
from .api.patients import router as patients_router
from .api.appointments import router as appointments_router
from .api.calls import router as calls_router
from .api.settings import router as settings_router

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="Sharma Dental AI - AI Dental Clinic Receptionist",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Store limiter in app state for access in tests
app.state.limiter = limiter

# Add slowapi middleware
app.add_middleware(SlowAPIMiddleware, limiter=limiter)

# Add rate limit exception handler
@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"error": "429 Too Many Requests - rate limit exceeded"},
    )

# CORS middleware - configure from env
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health", tags=["root"])
async def health_check():
  """Health check endpoint."""
  return {
    "status": "healthy",
    "service": settings.APP_NAME,
    "environment": settings.APP_ENV,
  }

# Include API routers
app.include_router(patients_router, prefix="/api/patients", tags=["patients"])
app.include_router(appointments_router, prefix="/api/appointments", tags=["appointments"])
app.include_router(calls_router, prefix="/api/calls", tags=["calls"])
app.include_router(settings_router, prefix="/api/settings", tags=["settings"])