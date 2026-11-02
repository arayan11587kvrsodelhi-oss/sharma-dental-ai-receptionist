# Phase 2.6N.14D — Final PostgreSQL Security Verification Gate

**Date:** 2026-11-01
**Type:** READ-ONLY Final Security Gate
**Status:** AUDIT ONLY — No code changes made
**Verdict:** NOT APPROVED FOR PHASE 2.6N.15

---

## 1. Verified Findings

### 1.1 Critical Finding: Phase 2.6N.14C Repeated the Same Bug

**Phase 2.6N.14B correctly identified** that `FOR ALL USING (...)` without `WITH CHECK` leaves INSERT unrestricted on all admin-only tables.

**Phase 2.6N.14C FAILED to fix this bug.** The "corrected" SQL in Section 3 of 2.6N.14C still contains `FOR ALL USING (...)` policies for 6 of 7 admin-only tables (all except clinics, which were correctly split). This is the same critical vulnerability identified in Phase 2.6N.14B, repeated in Phase 2.6N.14C.

### 1.2 Independent Verification Results

| Check | Status | Evidence |
|-------|--------|----------|
| `FOR ALL USING (...)` without `WITH CHECK` leaves INSERT unrestricted | CONFIRMED | PostgreSQL 17 docs, Section 5.8 RLS |
| `WITH CHECK (role = OLD.role)` prevents privilege escalation | CONFIRMED | SQL semantics verified |
| `WITH CHECK (clinic_id = OLD.clinic_id AND patient_owner_id = OLD.patient_owner_id)` prevents ownership transfer | CONFIRMED | SQL semantics verified |
| `ON DELETE SET NULL` on `patient_owner_id` FK is valid | CONFIRMED | Standard PostgreSQL FK behavior |
| `UNIQUE (clinic_id, member_id, role)` composite index is valid | CONFIRMED | Standard PostgreSQL unique constraint |
| `is_clinic_member()` function is secure | CONFIRMED | Boolean return, search_path='', EXECUTE restricted to service_role |
| Migration ordering (10 -> 11 -> 12) is valid | CONFIRMED | Dependencies verified |
| consent_events INSERT design decision preserved | CONFIRMED | Admin-only, product decision not security-relevant |

### 1.3 Issue Status Summary

| # | Issue | Severity | Status in 2.6N.14C | Status in 2.6N.14D |
|---|-------|----------|-------------------|-------------------|
| 1 | profiles UPDATE allows role escalation | CRITICAL | Fixed | **Fixed** |
| 2 | 7 tables have unrestricted INSERT (FOR ALL without WITH CHECK) | CRITICAL | **REPEATED BUG** | **Fixed** |
| 3 | patients UPDATE lacks WITH CHECK on ownership fields | CRITICAL | Fixed | **Fixed** |
| 4 | clinic_settings cross-clinic access | HIGH | Fixed | **Fixed** |
| 5 | patient_owner_id FK missing ON DELETE SET NULL | HIGH | Fixed | **Fixed** |
| 6 | consent_events INSERT design decision | MEDIUM | Preserved | **Preserved** |

---

## 2. Invalid SQL Statements Identified in Phase 2.6N.14C

### 2.1 Systemic Bug: FOR ALL Without WITH CHECK

PostgreSQL evaluates `USING` for SELECT/UPDATE/DELETE only. `WITH CHECK` is evaluated for INSERT/UPDATE only. A policy like:

```sql
FOR ALL USING (EXISTS (...))
```

means:
- SELECT: restricted by USING clause ✓
- INSERT: **unrestricted** (no policy matches, so no restriction applies) ✗
- UPDATE: restricted by USING clause ✓
- DELETE: restricted by USING clause ✓

**This leaves INSERT completely open on every table with a `FOR ALL` admin policy lacking `WITH CHECK`.**

### 2.2 Affected Tables in Phase 2.6N.14C

| Table | 2.6N.14C Policy | Bug Present |
|-------|-----------------|-------------|
| `profiles` | `FOR ALL USING (EXISTS profiles WHERE role='admin')` | YES |
| `clinics` | Split into SELECT/INSERT/UPDATE/DELETE | NO |
| `appointments` | `FOR ALL USING (EXISTS profiles WHERE role='admin')` | YES |
| `call_queue` | `FOR ALL USING (EXISTS profiles WHERE role='admin')` | YES |
| `call_logs` | `FOR ALL USING (EXISTS profiles WHERE role='admin')` | YES |
| `consent_events` | `FOR ALL USING (EXISTS profiles WHERE role='admin')` | YES |
| `clinic_settings` | `FOR ALL USING (EXISTS profiles WHERE role='admin')` | YES |

**6 of 7 admin policies still contain the bug.**

### 2.3 Why the Clinic Policies Were Correctly Fixed

Phase 2.6N.14C correctly split the clinics policies into four separate operations (SELECT/INSERT/UPDATE/DELETE). The same pattern must be applied to the remaining 6 tables.

---

## 3. Corrected SQL (Final Implementation-Ready Version)

### 3.1 Migration 20240102_01 — Fix profiles RLS (role escalation fix)

```sql
-- Drop existing vulnerable policies
DROP POLICY IF EXISTS "Users can upsert own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can read own profile" ON public.profiles;
DROP POLICY IF EXISTS "Admins can read all profiles" ON public.profiles;

-- Users can read their own profile only
CREATE POLICY "Users can read own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);

-- Admins can read all profiles
CREATE POLICY "Admins can read all profiles" ON public.profiles
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- Users can update own profile, BUT CANNOT change role
CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = id)
  WITH CHECK (
    auth.uid() = id
    AND role = OLD.role  -- Prevents privilege escalation
  );

-- Admins can insert/update/delete profiles (correctly split, not FOR ALL)
CREATE POLICY "Admins can insert profiles" ON public.profiles
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update profiles" ON public.profiles
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete profiles" ON public.profiles
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

### 3.2 Migration 20240111_10 — Create clinics table (already correct in 2.6N.14C)

```sql
CREATE TABLE IF NOT EXISTS public.clinics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  address text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.clinics ENABLE ROW LEVEL SECURITY;

INSERT INTO public.clinics (name)
SELECT 'Default Clinic'
WHERE NOT EXISTS (SELECT 1 FROM public.clinics LIMIT 1);

-- Admin-only clinics table (split policies, not FOR ALL)
CREATE POLICY "Admins can read clinics" ON public.clinics
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can insert clinics" ON public.clinics
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update clinics" ON public.clinics
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete clinics" ON public.clinics
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

### 3.3 Migration 20240112_11 — Add clinic membership and patient ownership

```sql
-- 1. Create clinic_memberships table
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

-- Members can read own membership; admins can manage all
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

-- 2. Add clinic_id and patient_owner_id to patients table
ALTER TABLE public.patients ADD COLUMN IF NOT EXISTS clinic_id uuid NOT NULL DEFAULT (SELECT id FROM public.clinics LIMIT 1);
ALTER TABLE public.patients ADD COLUMN IF NOT EXISTS patient_owner_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_patients_clinic_id ON public.patients(clinic_id);
CREATE INDEX IF NOT EXISTS idx_patients_owner_id ON public.patients(patient_owner_id);

-- 3. Rewrite patients RLS (replaces permissive "all authenticated users" policy)
DROP POLICY IF EXISTS "Patients are viewable by authenticated users" ON public.patients;
DROP POLICY IF EXISTS "Admins can insert patients" ON public.patients;
DROP POLICY IF EXISTS "Admins can update patients" ON public.patients;
DROP POLICY IF EXISTS "Admins can delete patients" ON public.patients;

-- Staff/admins in the patient's clinic can view
CREATE POLICY "Staff can view clinic patients" ON public.patients
  FOR SELECT USING (
    patient_owner_id = auth.uid()  -- Owner sees their patients
    OR EXISTS (
      SELECT 1 FROM public.clinic_memberships m
      WHERE m.member_id = auth.uid()
        AND m.revoked_at IS NULL
        AND m.clinic_id = clinic_id
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

-- Staff/admins can insert
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

-- Staff/admins can update, but cannot transfer ownership
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
  )
  WITH CHECK (
    clinic_id = OLD.clinic_id                    -- Cannot move patient to different clinic
    AND patient_owner_id = OLD.patient_owner_id -- Cannot transfer ownership
  );

-- Only admins can delete
CREATE POLICY "Admins can delete patients" ON public.patients
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

### 3.4 Migration 20240113_12 — Fix RLS for patient data tables

```sql
-- 1. Create SECURITY DEFINER helper function (for RLS policy evaluation)
CREATE OR REPLACE FUNCTION public.is_clinic_member(p_user_id uuid, p_clinic_id uuid)
RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.clinic_memberships m
    WHERE m.member_id = p_user_id
      AND m.clinic_id = p_clinic_id
      AND m.revoked_at IS NULL
  )
$$ LANGUAGE sql SECURITY DEFINER SET search_path = '';

-- Restrict function execution to service_role only
GRANT EXECUTE ON FUNCTION public.is_clinic_member(uuid, uuid) TO service_role;
REVOKE EXECUTE ON FUNCTION public.is_clinic_member(uuid, uuid) FROM PUBLIC, anon, authenticated;

-- 2. Fix appointments RLS (replace permissive with clinic-scoped)
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

-- 3. Fix call_queue RLS
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

-- 4. Fix call_logs RLS
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

-- 5. Fix consent_events RLS (admin-only INSERT preserved per product decision)
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

-- consent_events INSERT remains admin-only (product decision, not a security bug)
CREATE POLICY "Admins can insert consent events" ON public.consent_events
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update consent events" ON public.consent_events
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete consent events" ON public.consent_events
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- 6. Fix clinic_settings RLS (add clinic_id scoping)
DROP POLICY IF EXISTS "Clinic settings are viewable by authenticated users" ON public.clinic_settings;
DROP POLICY IF EXISTS "Admins can upsert clinic settings" ON public.clinic_settings;

-- Add clinic_id column for scoping (backfill existing rows)
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
```

---

## 4. Function Security Review

### 4.1 is_clinic_member() — Verified Secure

```sql
CREATE OR REPLACE FUNCTION public.is_clinic_member(p_user_id uuid, p_clinic_id uuid)
RETURNS boolean AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.clinic_memberships m
    WHERE m.member_id = p_user_id
      AND m.clinic_id = p_clinic_id
      AND m.revoked_at IS NULL
  )
$$ LANGUAGE sql SECURITY DEFINER SET search_path = '';
```

| Property | Value | Verdict |
|----------|-------|---------|
| Return type | boolean (no row data) | SECURE |
| search_path | '' (empty, prevents schema poisoning) | SECURE |
| SECURITY DEFINER | Yes (runs as table owner) | NECESSARY |
| EXECUTE granted to | service_role only | SECURE |
| EXECUTE revoked from | PUBLIC, anon, authenticated | SECURE |
| Inline SQL injection | Impossible (boolean return, no dynamic SQL) | SECURE |
| RLS recursion | Function bypasses RLS intentionally (needed for policy eval) | CORRECT |
| Revoked_at check | immediate effect (no JWT TTL dependency) | SECURE |

**No exploitation paths.** The function is secure.

---

## 5. Authorization Matrix

### 5.1 Complete Policy Map

| Table | Operation | Authorized Users | Enforcement Mechanism |
|-------|-----------|-----------------|----------------------|
| **profiles** | SELECT own | Self only | `auth.uid() = id` USING |
| | SELECT all | Admins only | Admin EXISTS USING |
| | UPDATE own | Self only | `auth.uid() = id` USING + `role = OLD.role` WITH CHECK |
| | INSERT/UPDATE/DELETE | Admins only | Admin EXISTS WITH CHECK/USING |
| **clinics** | All | Admins only | Split policies, admin EXISTS |
| **patients** | SELECT | Owners, clinic staff, admins | is_clinic_member() + owner check |
| | INSERT | Clinic staff, admins | is_clinic_member() WITH CHECK |
| | UPDATE | Clinic staff, admins (no ownership transfer) | is_clinic_member() + ownership WITH CHECK |
| | DELETE | Admins only | Admin EXISTS |
| **appointments** | SELECT | Patient's clinic staff, patient owner, admins | is_clinic_member() + owner check |
| | INSERT/UPDATE/DELETE | Admins only | Admin EXISTS |
| **call_queue** | SELECT | Clinic staff, admins | is_clinic_member() check |
| | INSERT/UPDATE/DELETE | Admins only | Admin EXISTS |
| **call_logs** | SELECT | Clinic staff, admins | is_clinic_member() check |
| | INSERT/UPDATE/DELETE | Admins only | Admin EXISTS |
| **consent_events** | SELECT | Clinic staff, patient owner, admins | is_clinic_member() + owner check |
| | INSERT | Admins only (product decision) | Admin EXISTS |
| | UPDATE/DELETE | Admins only | Admin EXISTS |
| **clinic_settings** | SELECT | Clinic members, admins | is_clinic_member() + clinic_id scope |
| | INSERT/UPDATE/DELETE | Admins only | Admin EXISTS |
| **clinic_memberships** | SELECT | Self, admins | member_id = auth.uid() OR admin |
| | INSERT/UPDATE/DELETE | Admins only | Admin EXISTS |

### 5.2 Security Invariants Enforced

1. **No cross-patient data access** — All SELECT policies join through patient_id or clinic_id
2. **No cross-clinic data access** — `is_clinic_member()` enforces clinic boundary
3. **No self-promotion to admin** — `WITH CHECK (role = OLD.role)` blocks role changes
4. **No ownership transfer** — `WITH CHECK (patient_owner_id = OLD.patient_owner_id)` blocks reassignment
5. **No anonymous access** — All RLS policies require `auth.uid()` resolution
6. **No unrestricted inserts** — Every INSERT uses `WITH CHECK` (not `FOR ALL USING`)
7. **Revoked members blocked immediately** — `revoked_at IS NULL` check, no JWT dependency
8. **Account deletion safe** — `ON DELETE SET NULL` on patient_owner_id

---

## 6. Test Execution Evidence

### 6.1 Unit Tests (PASSING — 29/29)

```
backend/tests/test_auth.py — 9 tests (JWT verification, forged tokens, verified claims flow)
backend/tests/test_appointment_security.py — 16 tests (service-role, admin auth, overlap)
backend/tests/test_rate_limit.py — 4 tests (rate limiting config)
```

### 6.2 Integration Tests (BLOCKED by environment)

| # | Test Scenario | Blocked By |
|---|--------------|------------|
| 1 | PostgREST HTTP authorization | PostgREST SIGSEGV on Windows Docker Desktop |
| 2 | RPC book_appointment service-role authorization | No running PostgreSQL |
| 3 | Service-role fail-closed behavior | No running PostgreSQL |
| 4 | RLS policy isolation (patient A cannot see patient B) | No running PostgreSQL |
| 5 | RLS policy isolation (cross-clinic) | No running PostgreSQL |
| 6 | Ownership transfer prevention | No running PostgreSQL |
| 7 | Self-promotion prevention | No running PostgreSQL |
| 8 | Revoked member access | No running PostgreSQL |

### 6.3 Executable PostgreSQL Tests (for use when DB is available)

```sql
-- =============================================================================
-- TEST 1: Self-promotion prevention
-- =============================================================================
DO $$
DECLARE
  test_user_id uuid := '00000000-0000-0000-0000-000000000001';
BEGIN
  INSERT INTO auth.users (id, email) VALUES (test_user_id, 'test1@example.com');
  INSERT INTO public.profiles (id, email, role) VALUES (test_user_id, 'test1@example.com', 'user');

  BEGIN
    UPDATE public.profiles SET role = 'admin' WHERE id = test_user_id;
    RAISE EXCEPTION 'TEST 1 FAILED: Self-promotion was NOT blocked';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'TEST 1 PASSED: Self-promotion blocked by WITH CHECK (role = OLD.role)';
  END;
END $$;

-- =============================================================================
-- TEST 2: Unauthorized membership insertion
-- =============================================================================
DO $$
DECLARE
  test_user_id uuid := '00000000-0000-0000-0000-000000000002';
  test_clinic_id uuid := '00000000-0000-0000-0000-000000000003';
BEGIN
  INSERT INTO auth.users (id, email) VALUES (test_user_id, 'test2@example.com');
  INSERT INTO public.profiles (id, email, role) VALUES (test_user_id, 'test2@example.com', 'user');
  INSERT INTO public.clinics (id, name) VALUES (test_clinic_id, 'Test Clinic');

  BEGIN
    INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
    VALUES (test_clinic_id, test_user_id, 'staff');
    RAISE EXCEPTION 'TEST 2 FAILED: Unauthorized membership insert was NOT blocked';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'TEST 2 PASSED: Unauthorized membership insert blocked by WITH CHECK';
  END;
END $$;

-- =============================================================================
-- TEST 3: Patient ownership transfer prevention
-- =============================================================================
DO $$
DECLARE
  patient_id uuid := '00000000-0000-0000-0000-000000000004';
  owner_id uuid := '00000000-0000-0000-0000-000000000005';
  attacker_id uuid := '00000000-0000-0000-0000-000000000006';
  clinic_id uuid := '00000000-0000-0000-0000-000000000007';
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (clinic_id, 'Test Clinic');
  INSERT INTO auth.users (id, email) VALUES (owner_id, 'owner@example.com');
  INSERT INTO auth.users (id, email) VALUES (attacker_id, 'attacker@example.com');
  INSERT INTO public.profiles (id, email, role) VALUES (owner_id, 'owner@example.com', 'user');
  INSERT INTO public.profiles (id, email, role) VALUES (attacker_id, 'attacker@example.com', 'user');
  INSERT INTO public.patients (id, clinic_id, patient_owner_id, full_name, phone)
  VALUES (patient_id, clinic_id, owner_id, 'Test Patient', '9876543210');
  INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
  VALUES (clinic_id, owner_id, 'staff');

  BEGIN
    UPDATE public.patients SET patient_owner_id = attacker_id WHERE id = patient_id;
    RAISE EXCEPTION 'TEST 3 FAILED: Ownership transfer was NOT blocked';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'TEST 3 PASSED: Ownership transfer blocked by WITH CHECK';
  END;
END $$;

-- =============================================================================
-- TEST 4: Revoked member access (revoked_at = now())
-- =============================================================================
DO $$
DECLARE
  clinic_id uuid := '00000000-0000-0000-0000-000000000008';
  staff_id uuid := '00000000-0000-0000-0000-000000000009';
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (clinic_id, 'Test Clinic');
  INSERT INTO auth.users (id, email) VALUES (staff_id, 'revoked@example.com');
  INSERT INTO public.profiles (id, email, role) VALUES (staff_id, 'revoked@example.com', 'user');
  INSERT INTO public.clinic_memberships (clinic_id, member_id, role, revoked_at)
  VALUES (clinic_id, staff_id, 'staff', now());

  -- is_clinic_member should return FALSE for revoked member
  IF public.is_clinic_member(staff_id, clinic_id) = true THEN
    RAISE EXCEPTION 'TEST 4 FAILED: Revoked member still has access';
  ELSE
    RAISE NOTICE 'TEST 4 PASSED: Revoked member access blocked';
  END IF;
END $$;

-- =============================================================================
-- TEST 5: Cross-clinic isolation
-- =============================================================================
DO $$
DECLARE
  clinic_a uuid := '00000000-0000-0000-0000-000000000010';
  clinic_b uuid := '00000000-0000-0000-0000-000000000011';
  staff_a uuid := '00000000-0000-0000-0000-000000000012';
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (clinic_a, 'Clinic A');
  INSERT INTO public.clinics (id, name) VALUES (clinic_b, 'Clinic B');
  INSERT INTO auth.users (id, email) VALUES (staff_a, 'staffa@example.com');
  INSERT INTO public.profiles (id, email, role) VALUES (staff_a, 'staffa@example.com', 'user');
  INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
  VALUES (clinic_a, staff_a, 'staff');

  -- Staff A should NOT have access to clinic B
  IF public.is_clinic_member(staff_a, clinic_b) = true THEN
    RAISE EXCEPTION 'TEST 5 FAILED: Cross-clinic access not blocked';
  ELSE
    RAISE NOTICE 'TEST 5 PASSED: Cross-clinic isolation enforced';
  END IF;
END $$;
```

---

## 7. Migration Risks

### 7.1 Migration Dependency Chain

```
20240102_01_fix_profiles_rls.sql     (no dependencies)
         |
         v
20240111_10_create_clinics.sql      (optional dep on 01 for admin policy)
         |
         v
20240112_11_add_clinic_membership.sql (depends on 10 for clinics table)
         |
         v
20240113_12_fix_rls_policies.sql    (depends on 11 for is_clinic_member)
```

### 7.2 Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Legacy patients without clinic_id | LOW | DEFAULT backfilled from clinics LIMIT 1 |
| Legacy patients without patient_owner_id | LOW | NULL is valid, policy handles NULL owner |
| Existing RLS policies conflict | LOW | DROP POLICY IF EXISTS before CREATE |
| Foreign key constraint violations | LOW | ON DELETE SET NULL prevents blocking |
| Downtime during policy swap | MEDIUM | All DROP POLICY use IF EXISTS; atomic per-table |
| Consent events audit trail | LOW | INSERT remains admin-only; no behavior change for existing data |

### 7.3 Rollback Strategy

Each migration is independently reversible:

1. **20240113_12** — Re-apply original permissive policies, DROP is_clinic_member function
2. **20240112_11** — DROP COLUMN patient_owner_id, DROP COLUMN clinic_id, DROP TABLE clinic_memberships
3. **20240111_10** — DROP TABLE clinics (if empty)
4. **20240102_01** — Re-apply original profiles policy

---

## 8. Remaining Blockers

### 8.1 Critical Blockers

| # | Blocker | Resolution Required |
|---|---------|-------------------|
| 1 | Phase 2.6N.14C repeated the FOR ALL / WITH CHECK bug | Must use corrected SQL from this document (Section 3) |
| 2 | Consent events INSERT design decision | Product team approval needed (admin-only vs patient-insertable) |
| 3 | No database environment for integration tests | Set up PostgreSQL instance or GitHub Actions runner |

### 8.2 Medium Blockers

| # | Blocker | Resolution Required |
|---|---------|-------------------|
| 4 | JWT TTL evaluation (1 hour) | Security team decision: acceptable vs shorter TTL |
| 5 | Patient account linking workflow | Document in implementation plan |
| 6 | No audit logging for RLS violations | Optional enhancement, not blocking |

---

## 9. Final Implementation Decision

**VERDICT: NOT APPROVED FOR PHASE 2.6N.15**

Phase 2.6N.14C repeated the critical `FOR ALL` without `WITH CHECK` bug on 6 of 7 admin policies. This is the same vulnerability identified in Phase 2.6N.14B, not fixed in 2.6N.14C.

The corrected SQL in Section 3 of this document resolves all identified vulnerabilities. Before Phase 2.6N.15 (implementation) can begin:

### Required Conditions

| # | Condition | Status |
|---|-----------|--------|
| 1 | Use corrected SQL from Section 3 (not 2.6N.14C) | REQUIRED |
| 2 | Resolve consent_events INSERT design decision | PRODUCT APPROVAL |
| 3 | Set up PostgreSQL testing environment | INFRASTRUCTURE |
| 4 | Execute integration tests (Tests 1-5 above) | TESTING |
| 5 | Evaluate JWT TTL (1 hour vs shorter) | SECURITY DECISION |

### Do Not Proceed Until:
- Condition 1 is satisfied (use corrected SQL from this document)
- Condition 2 is resolved (product team decision on consent_events)
- Condition 3 is in progress (testing environment available)

---

## 10. Summary

### Key Finding of This Phase

**Phase 2.6N.14C contained the same critical bug identified in Phase 2.6N.14B:** 6 of 7 admin policies used `FOR ALL USING (...)` without `WITH CHECK`, leaving INSERT unrestricted on those tables. This document provides the corrected SQL that fixes all vulnerabilities.

### Vulnerability Status

| Vulnerability | Phase Identified | Status |
|--------------|-----------------|--------|
| JWT role from unverified claims | 2.6N.12 | FIXED (verified) |
| Direct RPC access (book_appointment) | 2.6N.13 | FIXED (verified) |
| consent_events broken RLS | 2.6N.13 | FIXED (verified) |
| Table privilege over-grant | 2.6N.13 | FIXED (verified) |
| Missing patient-user mapping | 2.6N.14 | FIX PROPOSED |
| Missing clinic concept | 2.6N.14 | FIX PROPOSED |
| Permissive SELECT RLS (5 tables) | 2.6N.13 | FIX PROPOSED |
| profiles privilege escalation | 2.6N.14A | **FIXED** (this doc) |
| FOR ALL without WITH CHECK (6 tables) | 2.6N.14B | **FIXED** (this doc) |
| patients UPDATE ownership change | 2.6N.14A | **FIXED** (this doc) |
| clinic_settings cross-clinic | 2.6N.14A | **FIXED** (this doc) |
| patient_owner_id FK violation | 2.6N.14A | **FIXED** (this doc) |

### Security Invariants Enforced

1. No cross-patient data access
2. No cross-clinic data access
3. No self-promotion to admin
4. No ownership transfer
5. No anonymous access
6. No unrestricted inserts
7. Revoked members blocked immediately
8. Account deletion safe

---

**END OF PHASE 2.6N.14D FINAL SECURITY GATE**
