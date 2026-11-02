-- Migration: Fix RLS for patient data tables
-- Adds is_clinic_member helper and rewrites RLS on all patient-facing tables

CREATE OR REPLACE FUNCTION public.is_clinic_member(p_user_id uuid, p_clinic_id uuid)
RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.clinic_memberships m
    WHERE m.member_id = p_user_id
      AND m.clinic_id = p_clinic_id
      AND m.revoked_at IS NULL
  )
$$ LANGUAGE sql SECURITY DEFINER SET search_path = '';

GRANT EXECUTE ON FUNCTION public.is_clinic_member(uuid, uuid) TO service_role;
REVOKE EXECUTE ON FUNCTION public.is_clinic_member(uuid, uuid) FROM PUBLIC, anon, authenticated;

-- =============================================================================
-- appointments
-- =============================================================================
DROP POLICY IF EXISTS "Appointments are viewable by authenticated users" ON public.appointments;
DROP POLICY IF EXISTS "Admins can insert appointments" ON public.appointments;
DROP POLICY IF EXISTS "Admins can update appointments" ON public.appointments;
DROP POLICY IF EXISTS "Admins can delete appointments" ON public.appointments;

CREATE POLICY "Users can view own appointments" ON public.appointments
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.id = appointments.patient_id
        AND (p.patient_owner_id = auth.uid() OR public.is_clinic_member(auth.uid(), p.clinic_id))
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Admins can read appointments" ON public.appointments
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can insert appointments" ON public.appointments
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update appointments" ON public.appointments
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete appointments" ON public.appointments
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- =============================================================================
-- call_queue
-- =============================================================================
DROP POLICY IF EXISTS "Call queue is viewable by authenticated users" ON public.call_queue;
DROP POLICY IF EXISTS "Admins can insert call queue entries" ON public.call_queue;
DROP POLICY IF EXISTS "Admins can update call queue entries" ON public.call_queue;
DROP POLICY IF EXISTS "Admins can delete call queue entries" ON public.call_queue;

CREATE POLICY "Staff can view clinic call queue" ON public.call_queue
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.id = call_queue.patient_id
        AND public.is_clinic_member(auth.uid(), p.clinic_id)
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Admins can read call queue" ON public.call_queue
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can insert call queue" ON public.call_queue
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update call queue" ON public.call_queue
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete call queue" ON public.call_queue
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- =============================================================================
-- call_logs
-- =============================================================================
DROP POLICY IF EXISTS "Call logs are viewable by authenticated users" ON public.call_logs;
DROP POLICY IF EXISTS "Admins can insert call logs" ON public.call_logs;
DROP POLICY IF EXISTS "Admins can update call logs" ON public.call_logs;
DROP POLICY IF EXISTS "Admins can delete call logs" ON public.call_logs;

CREATE POLICY "Staff can view clinic call logs" ON public.call_logs
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.id = call_logs.patient_id
        AND public.is_clinic_member(auth.uid(), p.clinic_id)
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Admins can read call logs" ON public.call_logs
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can insert call logs" ON public.call_logs
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update call logs" ON public.call_logs
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete call logs" ON public.call_logs
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- =============================================================================
-- consent_events
-- =============================================================================
DROP POLICY IF EXISTS "Users can read own consent events" ON public.consent_events;
DROP POLICY IF EXISTS "Users can insert own consent events" ON public.consent_events;
DROP POLICY IF EXISTS "Admins can insert consent events" ON public.consent_events;
DROP POLICY IF EXISTS "Admins can update consent events" ON public.consent_events;
DROP POLICY IF EXISTS "Admins can delete consent events" ON public.consent_events;

CREATE POLICY "Users can view own consent events" ON public.consent_events
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.id = consent_events.patient_id
        AND (p.patient_owner_id = auth.uid() OR public.is_clinic_member(auth.uid(), p.clinic_id))
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Admins can read consent events" ON public.consent_events
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can insert consent events" ON public.consent_events
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update consent events" ON public.consent_events
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete consent events" ON public.consent_events
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- =============================================================================
-- clinic_settings (add clinic_id scoping)
-- =============================================================================
DROP POLICY IF EXISTS "Clinic settings are viewable by authenticated users" ON public.clinic_settings;
DROP POLICY IF EXISTS "Admins can upsert clinic settings" ON public.clinic_settings;

ALTER TABLE public.clinic_settings ADD COLUMN IF NOT EXISTS clinic_id uuid REFERENCES public.clinics(id);
UPDATE public.clinic_settings SET clinic_id = (SELECT id FROM public.clinics LIMIT 1) WHERE clinic_id IS NULL;
ALTER TABLE public.clinic_settings ALTER COLUMN clinic_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_clinic_settings_clinic_id ON public.clinic_settings(clinic_id);

CREATE POLICY "Members can read clinic settings" ON public.clinic_settings
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.clinic_memberships m
      WHERE m.member_id = auth.uid() AND m.revoked_at IS NULL
        AND m.clinic_id = clinic_settings.clinic_id
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Admins can read clinic settings" ON public.clinic_settings
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can insert clinic settings" ON public.clinic_settings
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update clinic settings" ON public.clinic_settings
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete clinic settings" ON public.clinic_settings
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
