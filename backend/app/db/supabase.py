"""Supabase database client for Sharma Dental AI.

Provides table() and rpc() helpers used across all backend API routes.
Must be configured with SUPABASE_URL and SUPABASE_ANON_KEY environment variables.
"""

from __future__ import annotations

import os
from typing import Any

from supabase import create_client, Client


def get_supabase_client() -> Client:
  """Get or create the Supabase client instance."""
  global _supabase_instance

  if _supabase_instance is not None:
    return _supabase_instance

  supabase_url = os.environ.get("SUPABASE_URL", "")
  supabase_anon_key = os.environ.get("SUPABASE_ANON_KEY", "")
  supabase_service_role_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

  # Anon client for ordinary operations (reads, public RPCs)
  anon_client = create_client(supabase_url, supabase_anon_key)

  # Privileged client for admin operations (only if service role key available)
  service_role_client = None
  if supabase_service_role_key:
    service_role_client = create_client(supabase_url, supabase_service_role_key)

  _supabase_instance = anon_client

  # Store service client separately for admin RPCs
  global _supabase_service_role_client
  _supabase_service_role_client = service_role_client

  return _supabase_instance


def get_supabase_service_role_client():
  """Return the privileged service-role Supabase client, or None if not configured."""
  global _supabase_service_role_client
  return _supabase_service_role_client if '_supabase_service_role_client' in globals() else None


# Module-level instance (lazy-initialized)
_supabase_instance: Client | None = None

# Convenience functions used by API routes


def table(name: str):
  """Get a table builder from the Supabase client."""
  return get_supabase_client().table(name)


def rpc(name: str, **kwargs: Any):
  """Call a Supabase stored procedure."""
  return get_supabase_client().rpc(name, kwargs)