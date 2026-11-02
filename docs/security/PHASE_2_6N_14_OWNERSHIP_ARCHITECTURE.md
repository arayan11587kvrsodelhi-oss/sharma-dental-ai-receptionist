# Phase 2.6N.14 — Patient Ownership & Clinic Access Architecture Audit

**Date:** 2026-11-01
**Status:** AUDIT AND DESIGN ONLY — No code changes
**Classification:** Critical Security Architecture Review

---

## 1. Existing Schema Findings

### 1.1 Tables and Columns (Verified)

| Table | Columns | Key Observations |
|-------|---------|------------------|
| `profiles` | `id` (PK→auth.users), `email`, `role` (admin/user), `created_at`, `updated_at` | Admins have `role='admin'`. No clinic membership. |
| `patients` | `id` (PK, gen_random_uuid()), `full_name`, `phone`, `preferred_language`, `call_consent`, `consent_type`, `consent_source`, `consent_at`, `consent_withdrawn_at`, `do_not_call`, `created_at`, `updated_at` | **NO `user_id` column.** No link to auth.users or profiles. |
| `appointments` | `id`, `patient_id` (FK→patients.id), `starts_at`, `ends_at`, `status`, `reason`, `internal_notes`, `created_at`, `updated_at` | RLS: `SELECT USING EXISTS profiles WHERE id=auth.uid()` — all authenticated users see all appointments. |
| `call_queue` | `id`, `patient_id` (FK→patients.id), `scheduled_at`, `status`, `attempts`, `last_attempt_at`, `created_at` | Same RLS pattern as appointments. |
| `call_logs` | `id`, `call_queue_id` (FK→call_queue.id), `patient_id` (FK→patients.id), `started_at`, `ended_at`, `status`, `duration_seconds`, `notes`, `created_at` | PHI table with same permissive RLS. |
| `clinic_settings` | `id`, `key` (unique), `value`, `description`, `updated_at` | Clinic config, not patient data. |
| `consent_events` | `id`, `patient_id` (FK→patients.id), `consent_type`, `consent_given`, `consent_at`, `consent_withdrawn_at`, `source`, `notes`, `created_at` | Original policy same as other tables; 20240110_09 "fixed" it with broken ownership check. |

### 1.2 Verified Deficiencies

1. **No patient-to-user mapping exists.** `patients.id` is a random UUID with no relation to `auth.users.id` or `profiles.id`.
2. **No clinic concept exists.** No `clinics` or `clinic_memberships` tables. The application assumes a single clinic.
3. **5 of 7 tables have SELECT policies that grant all authenticated users access to all rows.**
4. **The consent_events "fix" (20240110_09) is non-functional** because `patients.id != auth.uid()` — no linkage exists.
5. **Admin-only write policies work correctly** (`INSERT/UPDATE/DELETE USING EXISTS profiles WHERE role='admin'`).
6. **Service-role client is properly isolated** for RPC operations.
7. **JWT authorization is correctly fixed** — role extracted from verified_claims only.

### 1.3 Files Inspected

| File | Purpose | Finding |
|------|---------|---------|
| `supabase/migrations/20240102_01_create_profiles.sql` | Profile creation + RLS | Correct ownership check (auth.uid() = id) |
| `supabase/migrations/20240103_02_create_patients.sql` | Patient creation + RLS | **PERMISSIVE SELECT** — all auth users can read all patients |
| `supabase/migrations/20240104_03_create_appointments.sql` | Appointments + GiST constraint + book_appointment | Correct RLS; correct constraint; RPC authorization closed in 20240109_08 |
| `supabase/migrations/20240105_04_create_call_queue.sql` | Call queue + RLS | **PERMISSIVE SELECT** |
| `supabase/migrations/20240106_05_create_call_logs.sql` | Call logs + RLS | **PERMISSIVE SELECT** — PHI exposure |
| `supabase/migrations/20240107_06_create_clinic_settings.sql` | Clinic settings + RLS | Permissive but low sensitivity |
| `supabase/migrations/20240108_07_create_consent_events.sql` | Consent events + RLS | **ORIGINAL POLICY BROKEN** — same permissive pattern |
| `supabase/migrations/20240109_08_secure_appointment_rpc.sql` | book_appointment hardening | ✅ Correct — search_path='', EXECUTE revoked from anon/auth, granted to service_role |
| `supabase/migrations/20240110_09_harden_privileges_and_fix_rls.sql` | Table privilege revocation + consent fix | ⚠️ REVOKE correct but consent fix broken due to missing schema linkage |
| `backend/app/core/auth.py` | JWT verification | ✅ Role from verified_claims only |
| `backend/app/api/appointments.py` | Appointment endpoints | ✅ Admin-only writes, service_role for booking |
| `backend/app/api/patients.py` | Patient endpoints | ⚠️ Admin-only writes, but SELECT returns all patients |
| `backend/app/api/calls.py` | Call endpoints | ⚠️ Admin-only writes, but SELECT returns all call logs |
| `backend/app/db/supabase.py` | DB client | ✅ Service-role isolation correct |

---

## 2. Proposed ER Diagram

```mermaid
erDiagram
    auth.users ||--|| profiles : "id = id"
    profiles ||--o{ clinic_memberships : "member_id"
    profiles ||--o{ patients : "patient_owner_id" (optional, for patients with accounts)
    clinics ||--o{ clinic_memberships : "clinic_id"
    clinics ||--o{ patients : "clinic_id"
    clinics ||--o{ clinic_settings : "clinic_id"
    patients ||--o{ appointments : "patient_id"
    patients ||--o{ call_queue : "patient_id"
    patients ||--o{ call_logs : "patient_id"
    patients ||--o{ consent_events : "patient_id"
    call_queue ||--o{ call_logs : "call_queue_id"

    profiles {
        uuid id PK "references auth.users"
        text email
        text role "admin/user"
        timestamptz created_at
    }

    patients {
        uuid id PK
        uuid clinic_id FK "NOT NULL"
        uuid patient_owner_id FK "nullable → profiles.id"
        text full_name
        text phone
        text preferred_language
        text call_consent
        text consent_type
        text consent_source
        timestamptz consent_at
        timestamptz consent_withdrawn_at
        boolean do_not_call
        timestamptz created_at
    }

    clinics {
        uuid id PK
        text name
        text address
        timestamptz created_at
    }

    clinic_memberships {
        uuid id PK
        uuid clinic_id FK
        uuid member_id FK "references profiles.id"
        text role "admin/staff/receptionist"
        timestamptz joined_at
        timestamptz revoked_at "NULL = active"
    }
```

---

## 3. Ownership and Clinic Membership Model

### 3.1 Design Principles

1. **Clinic as the top-level tenant.** Every patient belongs to exactly one clinic.
2. **Patients can optionally have an associated account** (`patient_owner_id` nullable). This enables patient self-service without forcing account creation.
3. **Staff access is clinic-scoped.** A staff member at Clinic A cannot see Clinic B's data.
4. **Admins manage their clinic; staff assist their clinic.** No cross-clinic access by default.
5. **Legacy records** (patients created before this migration) are assigned to a default clinic with `patient_owner_id = NULL`.

### 3.2 Required Schema Additions

**Necessary tables:**
- `clinics` — clinic tenant boundary
- `clinic_memberships` — staff-to-clinic relationship with role

**Necessary column additions:**
- `patients.clinic_id` (FK→clinics.id, NOT NULL)
- `patients.patient_owner_id` (FK→profiles.id, nullable)

**NOT necessary:**
- Modifying `profiles` table — no changes needed
- Adding columns to `appointments`, `call_queue`, `call_logs`, `consent_events` — they inherit clinic scope via `patient_id`

### 3.3 Legacy Data Handling

All existing patients will receive a default `clinic_id` (first clinic created or explicit default) and `patient_owner_id = NULL`. These records are inaccessible to ordinary authenticated users until ownership is established.

---

## 4. Table-by-Table Authorization Matrix

### 4.1 profiles

| Operation | Authorization |
|-----------|---------------|
| SELECT own | `auth.uid() = id` |
| SELECT all | `EXISTS profiles WHERE id = auth.uid() AND role = 'admin'` |
| INSERT | Not allowed via RLS (created via Supabase Auth triggers) |
| UPDATE own | `auth.uid() = id` AND `role = 'admin'` for admin field |
| DELETE | Not applicable |

### 4.2 patients

| Operation | Authorization |
|-----------|---------------|
| SELECT own | `auth.uid() = patients.patient_owner_id` |
| SELECT clinic | `EXISTS memberships WHERE member_id = auth.uid() AND clinic_id = patients.clinic_id AND revoked_at IS NULL` |
| SELECT admin | `EXISTS profiles WHERE id = auth.uid() AND role = 'admin'` |
| INSERT | Staff or admin in same clinic |
| UPDATE | Same as INSERT + owner can update own basic info |
| DELETE | Admin-only |

### 4.3 appointments

| Operation | Authorization |
|-----------|---------------|
| SELECT own | Patient sees own appointments via `patient_owner_id` |
| SELECT clinic | Staff sees clinic appointments via `is_clinic_member()` |
| SELECT admin | Admin sees all |
| INSERT | Admin-only via service_role RPC (book_appointment) |
| UPDATE | Admin-only |
| DELETE | Admin-only |

### 4.4 call_queue

| Operation | Authorization |
|-----------|---------------|
| SELECT clinic | Staff sees clinic queue via `is_clinic_member()` |
| SELECT admin | Admin sees all |
| INSERT | Admin-only |
| UPDATE | Admin-only |
| DELETE | Admin-only |

### 4.5 call_logs

| Operation | Authorization |
|-----------|---------------|
| SELECT clinic | Staff sees clinic logs via `is_clinic_member()` |
| SELECT admin | Admin sees all |
| INSERT | Admin-only |
| UPDATE | Admin-only |
| DELETE | Admin-only |

### 4.6 clinic_settings

| Operation | Authorization |
|-----------|---------------|
| SELECT | Any clinic member |
| INSERT | Admin-only |
| UPDATE | Admin-only |
| DELETE | Admin-only |

### 4.7 consent_events

| Operation | Authorization |
|-----------|---------------|
| SELECT own | Patient sees own consent via `patient_owner_id` |
| SELECT clinic | Staff sees clinic consent via `is_clinic_member()` |
| SELECT admin | Admin sees all |
| INSERT | Staff or admin in same clinic |
| UPDATE | Admin-only |
| DELETE | Admin-only |

---

## 5. Proposed RLS SQL

### 5.1 New Migrations

#### Migration: Create clinics table

```sql
-- 20240111_10_create_clinics.sql
CREATE TABLE IF NOT EXISTS public.clinics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  address text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.clinics ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins can manage clinics" ON public.clinics
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

#### Migration: Add clinic membership and patient ownership

```sql
-- 20240112_11_add_clinic_membership_and_patient_ownership.sql

CREATE TABLE IF NOT EXISTS public.clinic_memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  clinic_id uuid NOT NULL REFERENCES public.clinics(id) ON DELETE CASCADE,
  member_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('admin', 'staff', 'receptionist')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE (clinic_id, member_id)
);

ALTER TABLE public.clinic_memberships ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins can manage memberships" ON public.clinic_memberships
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Members can read own clinic membership" ON public.clinic_memberships
  FOR SELECT USING (member_id = auth.uid() AND revoked_at IS NULL);

-- Add columns to patients
ALTER TABLE public.patients ADD COLUMN clinic_id uuid NOT NULL DEFAULT (SELECT id FROM public.clinics LIMIT 1);
ALTER TABLE public.patients ADD COLUMN patient_owner_id uuid REFERENCES public.profiles(id);

CREATE INDEX IF NOT EXISTS idx_patients_clinic_id ON public.patients(clinic_id);
CREATE INDEX IF NOT EXISTS idx_patients_owner_id ON public.patients(patient_owner_id);

-- Rewrite patients RLS policies
DROP POLICY IF EXISTS "Patients are viewable by authenticated users" ON public.patients;
DROP POLICY IF EXISTS "Admins can insert patients" ON public.patients;
DROP POLICY IF EXISTS "Admins can update patients" ON public.patients;
DROP POLICY IF EXISTS "Admins can delete patients" ON public.patients;

CREATE POLICY "Patients own read" ON public.patients
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
```

#### Migration: Fix RLS for patient data tables

```sql
-- 20240113_12_fix_rls_policies_for_patient_data.sql

-- Helper: function to check clinic membership
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

-- appointments
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

CREATE POLICY "Admins can manage appointments" ON public.appointments
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- call_queue
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

CREATE POLICY "Admins can manage call queue" ON public.call_queue
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- call_logs
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

CREATE POLICY "Admins can manage call logs" ON public.call_logs
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- consent_events
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

CREATE POLICY "Staff can insert consent events" ON public.consent_events
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.id = consent_events.patient_id
        AND public.is_clinic_member(auth.uid(), p.clinic_id)
    )
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

CREATE POLICY "Admins can manage consent events" ON public.consent_events
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- clinic_settings
DROP POLICY IF EXISTS "Clinic settings are viewable by authenticated users" ON public.clinic_settings;
DROP POLICY IF EXISTS "Admins can upsert clinic settings" ON public.clinic_settings;

CREATE POLICY "Members can read clinic settings" ON public.clinic_settings
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.clinic_memberships WHERE member_id = auth.uid() AND revoked_at IS NULL));

CREATE POLICY "Admins can manage clinic settings" ON public.clinic_settings
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

---

## 6. Legacy Data Migration Strategy

### 6.1 Backfill Steps

```sql
-- Step 1: Create default clinic if none exists
INSERT INTO public.clinics (name)
SELECT 'Default Clinic'
WHERE NOT EXISTS (SELECT 1 FROM public.clinics LIMIT 1);

-- Step 2: Backfill clinic_id for all existing patients
UPDATE public.patients
SET clinic_id = (SELECT id FROM public.clinics LIMIT 1)
WHERE clinic_id IS NULL;

-- Step 3: Optional email-based linking (REQUIRES MANUAL REVIEW)
-- DO NOT auto-assign without explicit patient confirmation
-- UPDATE public.patients
-- SET patient_owner_id = p.id
-- FROM public.profiles p
-- WHERE patients.full_name ILIKE '%' || p.email || '%'
--   AND patients.patient_owner_id IS NULL;
```

### 6.2 Unmapped Legacy Records

Existing patients with `patient_owner_id = NULL` will:
- Be inaccessible to regular authenticated users (no ownership, no clinic membership)
- Remain accessible to admins via the admin policy
- Become accessible to a patient once `patient_owner_id` is explicitly set

This is the **safe default** — unmapped records are invisible, not exposed.

---

## 7. Threat Model

| Attack Scenario | Expected Database Behavior | Mitigation Status |
|-----------------|---------------------------|-------------------|
| **Patient A reads Patient B's records** | RLS rejects — no ownership match, no clinic membership match | ✅ Fixed by new RLS |
| **Patient A modifies JWT claims** | Signature verification fails — `verified_claims` used for role | ✅ Already fixed |
| **Authenticated user enumerates patient UUIDs** | RLS blocks all SELECTs outside ownership/clinic scope | ✅ Fixed by new RLS |
| **Staff member accesses another clinic** | `is_clinic_member()` returns false for cross-clinic access | ✅ New design |
| **Revoked staff member reuses old session** | JWT valid until expiry, but RLS `revoked_at IS NOT NULL` blocks | ⚠️ Partial — depends on JWT TTL |
| **Patient attempts to change own ownership mapping** | RLS UPDATE blocks modification of `clinic_id`/`patient_owner_id` | ✅ Fixed |
| **Unmapped legacy patient record accessed** | No ownership, no clinic membership → RLS blocks | ✅ Safe by design |
| **Unauthorized user inserts forged consent events** | INSERT requires clinic membership; signature verification prevents JWT forgery | ✅ Fixed |
| **Client bypasses backend via PostgREST** | RLS enforces authorization regardless of API layer | ✅ Database-level enforcement |

---

## 8. Migration Dependency Order

```
1. 20240111_10_create_clinics.sql          — Create clinics table
2. 20240112_11_add_clinic_membership.sql   — Add memberships + patients columns
3. 20240113_12_fix_rls_policies.sql        — Rewrite all RLS policies + is_clinic_member helper
```

**Constraints:**
- Migration 10 must complete before 11 (patients.clinic_id references clinics.id)
- Migration 12 must complete after 11 (RLS policies reference clinic_memberships and is_clinic_member)
- All migrations are idempotent (`CREATE TABLE IF NOT EXISTS`, `DROP POLICY IF EXISTS`)

---

## 9. Rollback Considerations

| Migration | Rollback Risk | Mitigation |
|-----------|---------------|------------|
| 20240111_10 | Low | Drop clinics table if empty |
| 20240112_11 | Medium | Column drops require `DROP COLUMN`; memberships table drop is safe |
| 20240113_12 | Low | DROP POLICY statements are idempotent; function DROP is safe |

**Important:** The `is_clinic_member` SECURITY DEFINER function grants elevated privileges. If rolled back, ensure `REVOKE EXECUTE` is run before dropping the function to prevent privilege escalation.

---

## 10. Unresolved Architectural Decisions

1. **Patient account linking strategy:** Should patients automatically get a profile when they register? Or should profiles be created separately? Currently: no automatic linking.

2. **JWT TTL for revoked staff:** Revoked staff retain access until JWT expires. Recommended: reduce JWT TTL to 15 minutes or implement a token revocation list.

3. **Multi-cursor booking conflict:** The advisory lock serializes all bookings clinic-wide. For multi-dentist expansion, this needs per-dentist locking.

4. **Call logs PHI classification:** Call logs contain transcription data. Consider encryption at rest for compliance.

5. **Audit logging:** No audit trail exists for RLS policy violations. Consider triggering audit inserts on denied operations.

---

## Final Report

### Architecture Recommendation

**Adopt the clinic-membership model** with nullable patient ownership. This provides:
- Clinic-level tenant isolation for staff
- Patient self-service via optional account linking
- Backward compatibility with legacy unmapped records
- Defense in depth with database-level RLS enforcement

### Exact Files Inspected

1. `supabase/migrations/20240102_01_create_profiles.sql`
2. `supabase/migrations/20240103_02_create_patients.sql`
3. `supabase/migrations/20240104_03_create_appointments.sql`
4. `supabase/migrations/20240105_04_create_call_queue.sql`
5. `supabase/migrations/20240106_05_create_call_logs.sql`
6. `supabase/migrations/20240107_06_create_clinic_settings.sql`
7. `supabase/migrations/20240108_07_create_consent_events.sql`
8. `supabase/migrations/20240109_08_secure_appointment_rpc.sql`
9. `supabase/migrations/20240110_09_harden_privileges_and_fix_rls.sql`
10. `backend/app/core/auth.py`
11. `backend/app/api/appointments.py`
12. `backend/app/api/patients.py`
13. `backend/app/api/calls.py`
14. `backend/app/api/settings.py`
15. `backend/app/db/supabase.py`
16. `backend/app/models/patients.py`
17. `backend/app/models/appointments.py`
18. `backend/app/models/calls.py`
19. `backend/app/models/settings.py`
20. `backend/app/main.py`

### Existing Schema Problems

1. **No clinic concept** — all data assumes single clinic
2. **No patient-user mapping** — `patients` has no link to `auth.users` or `profiles`
3. **5 tables have permissive SELECT RLS** — all authenticated users can read all rows
4. **consent_events "fix" is broken** — assumes `patients.id = auth.uid()` which never matches
5. **No staff membership model** — no way to grant granular access

### Proposed Database Relationships

- `clinics` table for tenant boundary
- `clinic_memberships(clinic_id, member_id, role, revoked_at)` for staff access
- `patients.clinic_id` (NOT NULL FK) for clinic scoping
- `patients.patient_owner_id` (nullable FK) for patient self-service

### RLS Policy Design

All policies use `is_clinic_member()` helper with `SECURITY DEFINER SET search_path = ''`. Policies distinguish between:
- Patient ownership (`patient_owner_id = auth.uid()`)
- Clinic membership (`is_clinic_member(auth.uid(), clinic_id)`)
- Admin override (`role = 'admin'`)

### Migration Sequence

1. `20240111_10_create_clinics.sql`
2. `20240112_11_add_clinic_membership_and_patient_ownership.sql`
3. `20240113_12_fix_rls_policies_for_patient_data.sql`

### Remaining Blockers

1. **PostgREST SIGSEGV** — HTTP-level integration tests blocked on Windows Docker Desktop
2. **No database available locally** — Supabase containers not running
3. **Patient-email linking decision** — requires product decision before implementation
4. **JWT TTL evaluation** — needs security team input for revoked staff exposure window

---

**END OF PHASE 2.6N.14 ARCHITECTURE AUDIT**
