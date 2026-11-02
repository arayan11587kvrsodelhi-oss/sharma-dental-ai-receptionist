-- Migration: Harden table privileges and fix RLS policy bugs
-- Changes:
-- 1. Revoke TRUNCATE, REFERENCES, TRIGGER, MAINTAIN from anon/authenticated on all app tables
-- 2. Fix consent_events RLS policy that claims to restrict to "own" but doesn't actually check ownership
-- 3. Adjust default privileges for future tables
--
-- Notes:
-- - consent_events has columns: id, patient_id, consent_type, consent_given, consent_at,
--   consent_withdrawn_at, source, notes, created_at (NO user_id)
-- - The existing "Users can read own consent events" policy only checks
--   EXISTS (SELECT 1 FROM profiles WHERE id=auth.uid()) which allows ALL authenticated users
--   to read ALL consent_events. Fixed to check patient_id via profiles.

-- =============================================================================
-- 1. REVOKE UNNECESSARY PRIVILEGES FROM anon AND authenticated
-- =============================================================================

-- The application uses RLS policies for all access control.
-- TRUNCATE, REFERENCES, TRIGGER, MAINTAIN are never needed by the frontend or PostgREST.
-- These privileges are only dangerous if RLS is somehow bypassed.

REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.appointments FROM anon, authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.call_logs FROM anon, authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.call_queue FROM anon, authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.clinic_settings FROM anon, authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.consent_events FROM anon, authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.patients FROM anon, authenticated;
REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.profiles FROM anon, authenticated;

-- =============================================================================
-- 2. FIX CONSENT_EVENTS RLS POLICY BUG
-- =============================================================================

-- Drop the broken policy that only checks authentication, not ownership
DROP POLICY IF EXISTS "Users can read own consent events" ON public.consent_events;

-- Fix: Only allow users to read consent events for their own patient profile,
-- or admins to read all consent events.
CREATE POLICY "Users can read own consent events" ON public.consent_events
  FOR SELECT USING (
    -- Admins can read all
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE profiles.id = auth.uid() AND profiles.role = 'admin'
    )
    OR
    -- Regular users can only read their own consent events (via patient ownership)
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.id = consent_events.patient_id
        AND p.id = auth.uid()
    )
  );

-- Add INSERT policy: users can create consent events for themselves
DROP POLICY IF EXISTS "Users can insert own consent events" ON public.consent_events;
CREATE POLICY "Users can insert own consent events" ON public.consent_events
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.id = consent_events.patient_id
        AND p.id = auth.uid()
    )
  );

-- =============================================================================
-- 3. ADJUST DEFAULT PRIVILEGES FOR FUTURE TABLES
-- =============================================================================

-- Revoke unnecessary default privileges for anon/authenticated
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLES FROM anon, authenticated;

-- Ensure service_role retains full privileges on future tables
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLES TO service_role;

-- Ensure anon/authenticated retain CRUD on future tables (RLS will restrict actual access)
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO anon, authenticated;
