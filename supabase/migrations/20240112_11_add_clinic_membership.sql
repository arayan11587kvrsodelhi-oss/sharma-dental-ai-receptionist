-- Migration: Add clinic membership and patient ownership
-- Adds clinic_memberships table and patient scoping columns

CREATE TABLE IF NOT EXISTS public.clinic_memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES public.clinics(id) ON DELETE CASCADE,
  member_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('admin', 'staff', 'receptionist')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE (clinic_id, member_id, role)
);

ALTER TABLE public.clinic_memberships ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Members can read own membership" ON public.clinic_memberships
  FOR SELECT USING (
    member_id = auth.uid() AND revoked_at IS NULL
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Admins can insert memberships" ON public.clinic_memberships
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update memberships" ON public.clinic_memberships
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete memberships" ON public.clinic_memberships
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.clinic_memberships FROM anon, authenticated;

ALTER TABLE public.patients ADD COLUMN IF NOT EXISTS clinic_id uuid NOT NULL DEFAULT (SELECT id FROM public.clinics LIMIT 1);
ALTER TABLE public.patients ADD COLUMN IF NOT EXISTS patient_owner_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_patients_clinic_id ON public.patients(clinic_id);
CREATE INDEX IF NOT EXISTS idx_patients_owner_id ON public.patients(patient_owner_id);

DROP POLICY IF EXISTS "Patients are viewable by authenticated users" ON public.patients;
DROP POLICY IF EXISTS "Admins can insert patients" ON public.patients;
DROP POLICY IF EXISTS "Admins can update patients" ON public.patients;
DROP POLICY IF EXISTS "Admins can delete patients" ON public.patients;

CREATE POLICY "Staff can view clinic patients" ON public.patients
  FOR SELECT USING (
    patient_owner_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.clinic_memberships m
      WHERE m.member_id = auth.uid()
        AND m.revoked_at IS NULL
        AND m.clinic_id = clinic_id
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Staff can insert patients" ON public.patients
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.clinic_memberships m
      WHERE m.member_id = auth.uid()
        AND m.revoked_at IS NULL
        AND m.clinic_id = clinic_id
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Staff can update patients" ON public.patients
  FOR UPDATE USING (
    patient_owner_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM public.clinic_memberships m
      WHERE m.member_id = auth.uid()
        AND m.revoked_at IS NULL
        AND m.clinic_id = clinic_id
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Admins can delete patients" ON public.patients
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE public.patients FROM anon, authenticated;
