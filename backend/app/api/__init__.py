"""API routes initialization for Sharma Dental AI.

The actual FastAPI app setup is in backend/app/main.py,
which includes these routers via app.include_router().
This file exists to ensure the route modules are importable.
"""

# Import all route modules so they are available for registration
from .patients import router as patients_router  # noqa: F401
from .appointments import router as appointments_router  # noqa: F401
from .calls import router as calls_router  # noqa: F401
from .settings import router as settings_router  # noqa: F401
# from .webhooks.exotel.status import router as exotel_router  # noqa: F401 - to be implemented