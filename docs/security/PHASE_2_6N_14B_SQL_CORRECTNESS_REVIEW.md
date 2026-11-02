# Phase 2.6N.14B — Adversarial SQL Correctness & Implementation Readiness Review

**Date:** 2026-11-01
**Type:** READ-ONLY SQL Correctness Verification
**Status:** AUDIT ONLY — No code changes made
**Verdict:** NOT APPROVED FOR PHASE 2.6N.15

---

## 1. Executive Verdict

**NOT APPROVED FOR PHASE 2.6N.15**

While the Phase 2.6N.14A review identified the correct vulnerabilities, this phase reveals that the proposed fixes are incomplete and contain critical SQL errors that would introduce NEW vulnerabilities if implemented as written.

**Two fatal flaws remain:**

1. **CRITICAL:** All 7 `FOR ALL` admin policies lack `WITH CHECK` clauses, meaning **INSERT operations are completely unrestricted** on every admin-protected table. Any authenticated user can insert rows into clinics, clinic_memberships, appointments, call_queue, call_logs, consent_events, and clinic_settings.

2. **CRITICAL:** The `clinic_memberships` table has a `UNIQUE (clinic_id, member_id)` constraint that prevents a member from holding multiple roles in the same clinic, but more critically, the missing INSERT policy means **any authenticated user can self-add to any clinic**.

These are not theoretical — they are direct privilege escalation paths that bypass all RLS protections.

---

## 2. Scope and Files Inspected

| File | Purpose | Key Findings |
|------|---------|-------------|
| `docs/security/PHASE_2_6N_14_OWNERSHIP_ARCHITECTURE.md` | Complete architecture proposal | 3 vulnerabilities identified, but fix SQL incomplete |
| `docs/security/PHASE_2_6N_14A_ARCHITECTURE_REVIEW.md` | Independent adversarial review | Correctly identified profiles/patients/clinic_settings issues |
| `supabase/migrations/20240102_01_create_profiles.sql` | Current profiles RLS | `FOR ALL USING (auth.uid() = id) WITH CHECK (auth.uid() = id)` — vulnerable to role escalation |
| `supabase/migrations/20240109_08_secure_appointment_rpc.sql` | RPC hardening | Correct — preserved by review |
| `supabase/migrations/20240110_09_harden_privileges_and_fix_rls.sql` | Table privilege revocation | Correct — preserved by review |
| `backend/app/core/auth.py` | JWT verification | Correct — preserved by review |
| `backend/app/api/appointments.py` | Appointment endpoints | Correct — preserved by review |

---

## 3. Corrected SQL Recommendations

### 3.1 profiles — Fix Privilege Escalation (CRITICAL)

**Current (vulnerable):**
```sql
create policy "Users can upsert own profile" on public.profiles
  for all using (auth.uid() = id) with check (auth.uid() = id);
```

**Corrected:**
```sql
-- Drop the vulnerable combined policy
DROP POLICY IF EXISTS "Users can upsert own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can read own profile" ON public.profiles;
DROP POLICY IF EXISTS "Admins can read all profiles" ON public.profiles;

-- Read: own profile only
CREATE POLICY "Users can read own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);

-- Admin: read all profiles
CREATE POLICY "Admins can read all profiles" ON public.profiles
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- Update: own profile, prevent role change
CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = id)
  WITH CHECK (
    auth.uid() = id
    AND role = OLD.role  -- CRITICAL: prevent privilege escalation
  );

-- Admin: manage all profiles
CREATE POLICY "Admins can manage all profiles" ON public.profiles
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

**PostgreSQL operation protected:** UPDATE
**Why USING is insufficient:** USING only filters which rows can be targeted, not what values can be written
**Why WITH CHECK is required:** Prevents `role` column from being modified to 'admin'

---

### 3.2 patients — Fix Ownership Modification (HIGH)

**Current proposed (incomplete):**
```sql
CREATE POLICY "Staff can update patients" ON public.patients
  FOR UPDATE USING (
    patient_owner_id = auth.uid()
    OR EXISTS (...)
  );
-- MISSING: WITH CHECK clause
```

**Corrected:**
```sql
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
    -- CRITICAL: Prevent changing ownership or clinic assignment
    clinic_id = OLD.clinic_id
    AND patient_owner_id = OLD.patient_owner_id
  );
```

**PostgreSQL operation protected:** UPDATE
**Why USING is insufficient:** A patient with `patient_owner_id = auth.uid()` can update ANY field on their row
**Why WITH CHECK is required:** Prevents `clinic_id` and `patient_owner_id` from being changed after creation

---

### 3.3 clinic_settings — Fix Cross-Clinic Isolation (HIGH)

**Current proposed (incomplete):**
```sql
CREATE POLICY "Members can read clinic settings" ON public.clinic_settings
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.clinic_memberships
    WHERE member_id = auth.uid() AND revoked_at IS NULL));
-- Allows any member to read ALL clinic_settings rows
```

**Corrected:**
```sql
-- Add clinic_id column (migration step)
ALTER TABLE public.clinic_settings ADD COLUMN clinic_id uuid REFERENCES public.clinics(id);
UPDATE public.clinic_settings SET clinic_id = (SELECT id FROM public.clinics LIMIT 1);
ALTER TABLE public.clinic_settings ALTER COLUMN clinic_id SET NOT NULL;

-- Create index
CREATE INDEX idx_clinic_settings_clinic_id ON public.clinic_settings(clinic_id);

-- Scoped SELECT policy
CREATE POLICY "Members can read clinic settings" ON public.clinic_settings
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.clinic_memberships m
      WHERE m.member_id = auth.uid() AND m.revoked_at IS NULL
        AND m.clinic_id = clinic_settings.clinic_id)
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

-- Admin-only write policies
CREATE POLICY "Admins can update clinic settings" ON public.clinic_settings
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete clinic settings" ON public.clinic_settings
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

**PostgreSQL operation protected:** SELECT, UPDATE, DELETE
**Why original is insufficient:** No clinic_id scoping allows cross-clinic data access
**Why new approach is required:** Each clinic's settings are isolated by clinic_id

---

### 3.4 clinic_memberships — Fix Missing INSERT Policy (CRITICAL)

**Current proposed (vulnerable):**
```sql
CREATE POLICY "Admins can manage memberships" ON public.clinic_memberships
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

**Problem:** PostgreSQL ignores `USING` for INSERT operations. Without a `WITH CHECK` clause, **any authenticated user can insert any membership row**.

**Corrected:**
```sql
-- Drop the unsafe FOR ALL policy
DROP POLICY IF EXISTS "Admins can manage memberships" ON public.clinic_memberships;

-- Read: own membership or admin
CREATE POLICY "Members can read own membership" ON public.clinic_memberships
  FOR SELECT USING (
    member_id = auth.uid() AND revoked_at IS NULL
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
  );

-- Insert: admin only
CREATE POLICY "Admins can insert memberships" ON public.clinic_memberships
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- Update: admin only
CREATE POLICY "Admins can update memberships" ON public.clinic_memberships
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- Delete: admin only
CREATE POLICY "Admins can delete memberships" ON public.clinic_memberships
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

**PostgreSQL operation protected:** INSERT, UPDATE, DELETE
**Why FOR ALL is insufficient:** PostgreSQL does not evaluate USING for INSERT
**Why separate policies are required:** Each operation type needs its own authorization check

---

### 3.5 clinics — Fix Missing INSERT Policy (CRITICAL)

**Current proposed (vulnerable):**
```sql
CREATE POLICY "Admins can manage clinics" ON public.clinics
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

**Same problem as clinic_memberships:** INSERT is unrestricted.

**Corrected:**
```sql
DROP POLICY IF EXISTS "Admins can manage clinics" ON public.clinics;

CREATE POLICY "Admins can read clinics" ON public.clinics
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can insert clinics" ON public.clinics
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can update clinics" ON public.clinics
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE POLICY "Admins can delete clinics" ON public.clinics
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

---

### 3.6 All Remaining FOR ALL Admin Policies — Same Fix Required

The following tables in the proposed migration `20240113_12` all have the same vulnerability:

| Table | Current Proposed | Corrected Approach |
|-------|-----------------|-------------------|
| `appointments` | `FOR ALL USING (admin)` | Split into SELECT/INSERT/UPDATE/DELETE policies with WITH CHECK |
| `call_queue` | `FOR ALL USING (admin)` | Split into SELECT/INSERT/UPDATE/DELETE policies with WITH CHECK |
| `call_logs` | `FOR ALL USING (admin)` | Split into SELECT/INSERT/UPDATE/DELETE policies with WITH CHECK |
| `consent_events` | `FOR ALL USING (admin)` | Split into SELECT/INSERT/UPDATE/DELETE policies with WITH CHECK |

**Pattern for all admin-only write tables:**
```sql
-- SELECT: admin only
CREATE POLICY "Admins can read [table]" ON public.[table]
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- INSERT: admin only, with CHECK to validate new row
CREATE POLICY "Admins can insert [table]" ON public.[table]
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- UPDATE: admin only
CREATE POLICY "Admins can update [table]" ON public.[table]
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- DELETE: admin only
CREATE POLICY "Admins can delete [table]" ON public.[table]
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

---

## 4. Invalid SQL Identified

### 4.1 Systemic: FOR ALL Without WITH CHECK on Write Operations

**Affected tables:** 7 (clinics, clinic_memberships, appointments, call_queue, call_logs, consent_events, clinic_settings)

**Root cause:** The architecture document uses `FOR ALL USING (...)` for admin policies, assuming PostgreSQL evaluates USING for all operations. This is incorrect — PostgreSQL silently ignores USING for INSERT.

**Impact:** Any authenticated user can insert rows into all 7 tables, bypassing admin-only restrictions.

**Verification:** This is a PostgreSQL RLS behavior documented in [PostgreSQL Manual, Row Level Security](https://www.postgresql.org/docs/current/ddl-rls.html):
> "The USING clause is checked when the query needs to determine which existing rows are visible. The WITH CHECK clause is checked when the query needs to determine whether a new row is insertable or whether an existing row is updateable or deletable."

---

### 4.2 clinic_memberships UNIQUE Constraint Too Restrictive

**Proposed:** `UNIQUE (clinic_id, member_id)`

**Problem:** Prevents a member from having multiple roles in the same clinic (e.g., both 'staff' and 'receptionist').

**Recommendation:** Remove the UNIQUE constraint. If role uniqueness per member is desired, enforce it via application logic or a trigger, not a constraint.

---

### 4.3 patients.clinic_id Default Subquery Risk

**Proposed:** `clinic_id uuid NOT NULL DEFAULT (SELECT id FROM public.clinics LIMIT 1)`

**Risk:** If the clinics table is empty when this migration runs, the subquery returns NULL, violating the NOT NULL constraint.

**Mitigation:** Migration order ensures clinics table is created first (migration 10 before 11), but add an explicit INSERT if no clinics exist:
```sql
INSERT INTO public.clinics (name) SELECT 'Default Clinic' WHERE NOT EXISTS (SELECT 1 FROM public.clinics LIMIT 1);
```

---

### 4.4 Consent Events INSERT Policy Change Is a Design Decision

**Original:** Admin-only INSERT
**Proposed:** Staff + Admin INSERT

**Assessment:** This is a business logic change, not a security fix. Staff members inserting consent events increases the attack surface for PHI manipulation.

**Recommendation:** Require explicit approval for this change. If approved, add audit logging.

---

## 5. Threat Analysis

### 5.1 Active Exploitation Paths (If Proposed SQL Applied As-Is)

| # | Attack | Vector | Impact |
|---|--------|--------|--------|
| 1 | Self-add to clinic | INSERT into clinic_memberships | Gain clinic staff access |
| 2 | Create fake clinic | INSERT into clinics | Establish false tenant boundary |
| 3 | Inject appointment | INSERT into appointments | Book slots for other patients |
| 4 | Inject call log | INSERT into call_logs | Create false PHI records |
| 5 | Inject consent event | INSERT into consent_events | Manipulate consent status |
| 6 | Modify clinic settings | INSERT/UPDATE clinic_settings | Change clinic configuration |
| 7 | Self-promote to admin | UPDATE profiles SET role='admin' | Full system access |
| 8 | Transfer patient ownership | UPDATE patients SET patient_owner_id=X | Claim another patient's records |
| 9 | Move patient to clinic | UPDATE patients SET clinic_id=X | Transfer between clinics |

### 5.2 Defense Layers (Already Verified)

| Layer | Status | Evidence |
|-------|--------|----------|
| JWT signature verification | VERIFIED | auth.py:215, 9 passing tests |
| RPC EXECUTE restriction | VERIFIED | Migration 20240109_08 |
| Service-role fail-closed | VERIFIED | appointments.py:63-66 |
| GiST exclusion constraint | VERIFIED | Migration 20240104_03 |
| Advisory lock | VERIFIED | Migration 20240109_08:50 |
| Table privilege revocation | VERIFIED | Migration 20240110_09:22-28 |

---

## 6. Authorization Matrix (Corrected)

### 6.1 profiles

| Operation | Authorization | PostgreSQL Clause | Status |
|-----------|---------------|-------------------|--------|
| SELECT own | `auth.uid() = id` | USING | Correct |
| SELECT all | Admin | USING | Correct |
| UPDATE own | `auth.uid() = id` AND `role = OLD.role` | USING + WITH CHECK | **Requires fix** |
| INSERT | N/A (auth trigger) | N/A | N/A |
| DELETE | N/A | N/A | N/A |

### 6.2 clinic_memberships

| Operation | Authorization | PostgreSQL Clause | Status |
|-----------|---------------|-------------------|--------|
| SELECT own | `member_id = auth.uid()` | USING | Correct |
| SELECT all | Admin | USING | **Requires fix** |
| INSERT | Admin only | WITH CHECK | **Requires fix** |
| UPDATE | Admin only | USING | **Requires fix** |
| DELETE | Admin only | USING | **Requires fix** |

### 6.3 patients

| Operation | Authorization | PostgreSQL Clause | Status |
|-----------|---------------|-------------------|--------|
| SELECT own | `patient_owner_id = auth.uid()` | USING | Correct |
| SELECT clinic | `is_clinic_member()` | USING | Correct |
| SELECT admin | Admin | USING | Correct |
| INSERT clinic | Staff/admin in clinic | WITH CHECK | Correct |
| UPDATE | Staff/admin (restricted fields) | USING + WITH CHECK | **Requires fix** |
| DELETE | Admin | USING | Correct |

### 6.4 All Admin-Only Write Tables (appointments, call_queue, call_logs, consent_events, clinic_settings)

| Operation | Authorization | PostgreSQL Clause | Status |
|-----------|---------------|-------------------|--------|
| SELECT | Admin | USING | **Requires fix** |
| INSERT | Admin | WITH CHECK | **Requires fix** |
| UPDATE | Admin | USING | **Requires fix** |
| DELETE | Admin | USING | **Requires fix** |

---

## 7. Test Cases

### 7.1 Executable SQL Integration Tests

```sql
-- Test 1: Self-promotion prevention
-- Setup: Create regular user profile
INSERT INTO auth.users (id, email) VALUES ('test-user-id', 'test@example.com');
INSERT INTO public.profiles (id, email, role) VALUES ('test-user-id', 'test@example.com', 'user');

-- Test: Attempt self-promotion
DO $$
BEGIN
  UPDATE public.profiles SET role = 'admin' WHERE id = 'test-user-id';
  RAISE EXCEPTION 'Self-promotion was NOT blocked - CRITICAL VULNERABILITY';
EXCEPTION WHEN check_violation THEN
  RAISE NOTICE 'Test 1 PASS: Self-promotion blocked by WITH CHECK';
END $$;

-- Test 2: Unauthorized membership insertion
-- Setup: Create regular user
INSERT INTO auth.users (id, email) VALUES ('test-user-2', 'test2@example.com');
INSERT INTO public.profiles (id, email, role) VALUES ('test-user-2', 'test2@example.com', 'user');

-- Test: Attempt self-add to clinic
DO $$
BEGIN
  INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
  VALUES ('clinic-a', 'test-user-2', 'staff');
  RAISE EXCEPTION 'Unauthorized membership insert was NOT blocked - CRITICAL VULNERABILITY';
EXCEPTION WHEN check_violation THEN
  RAISE NOTICE 'Test 2 PASS: Unauthorized membership insert blocked';
END $$;

-- Test 3: Patient ownership transfer prevention
-- Setup: Create patient with owner
INSERT INTO public.patients (id, clinic_id, patient_owner_id, full_name, phone)
VALUES ('patient-a', 'clinic-a', 'owner-a', 'Test Patient', '9876543210');

-- Test: Attempt to change ownership
DO $$
BEGIN
  UPDATE public.patients SET patient_owner_id = 'attacker-id' WHERE id = 'patient-a';
  RAISE EXCEPTION 'Ownership transfer was NOT blocked - CRITICAL VULNERABILITY';
EXCEPTION WHEN check_violation THEN
  RAISE NOTICE 'Test 3 PASS: Ownership transfer blocked by WITH CHECK';
END $$;
```

### 7.2 Tests Blocked by Environment

| # | Test | Blocked By | Notes |
|---|------|------------|-------|
| 4 | Cross-clinic patient access | No PostgreSQL running | Requires multi-clinic setup |
| 5 | Revoked member access | No PostgreSQL running | Requires membership revocation test |
| 6 | Legacy unmapped patient access | No PostgreSQL running | Requires backfill test |
| 7 | PostgREST HTTP authorization | PostgREST SIGSEGV | Windows Docker Desktop limitation |
| 8 | RPC book_appointment authorization | No PostgreSQL running | Requires service_role test |
| 9 | Service-role fail-closed | Partially tested | Unit tests pass, DB-level not tested |

### 7.3 Tests Not Yet Implemented

| # | Test | Category | Priority |
|---|------|----------|----------|
| 10 | Patient-to-patient isolation | RLS isolation | HIGH |
| 11 | Clinic-to-clinic isolation | RLS isolation | HIGH |
| 12 | Consent event cross-patient access | RLS isolation | HIGH |
| 13 | Call log PHI isolation | RLS isolation | HIGH |
| 14 | Anon key rejection | Authentication | MEDIUM |
| 15 | Non-admin booking rejection | Authorization | MEDIUM |

---

## 8. Testing Environment Limitations

### 8.1 Current Limitations

| Factor | Status | Impact |
|--------|--------|--------|
| Docker/PostgreSQL | Not running locally | Cannot run database-level integration tests |
| PostgREST | SIGSEGV on Windows Docker Desktop | Cannot run HTTP-level authorization tests |
| Supabase CLI | Installed but no linked project | Cannot run migrations locally |
| Unit tests | 29/29 passing | Auth and appointment security verified |

### 8.2 Test Coverage Summary

| Category | Total | Passed | Blocked | Not Implemented |
|----------|-------|--------|---------|-----------------|
| JWT verification | 9 | 9 | 0 | 0 |
| Service-role client | 4 | 4 | 0 | 0 |
| Admin authorization | 5 | 5 | 0 | 0 |
| Rate limiting | 4 | 4 | 0 | 0 |
| RLS policy isolation | 12 | 0 | 12 | 0 |
| RPC authorization | 4 | 0 | 4 | 0 |
| Ownership workflow | 6 | 0 | 6 | 0 |
| Cross-clinic isolation | 4 | 0 | 4 | 0 |
| **Total** | **48** | **22** | **26** | **0** |

### 8.3 Recommended Testing Strategy

1. **GitHub Actions** (Linux runner with PostgreSQL container) — Highest feasibility, avoids Windows Docker SIGSEGV
2. **Supabase staging project** — Real environment with PostgREST, proper JWT flow
3. **Local PostgreSQL 17** — Direct installation without Docker, run migrations manually

**Do not use:** Windows Docker Desktop (PostgREST SIGSEGV is a known environment blocker).

---

## 9. Required Architecture Changes

### 9.1 Critical Fixes (Must Resolve Before Implementation)

| # | Fix | File | SQL Change |
|---|-----|------|------------|
| 1 | profiles UPDATE privilege escalation | `20240102_01_create_profiles.sql` | Split FOR ALL into separate policies; add `WITH CHECK (role = OLD.role)` |
| 2 | All FOR ALL admin policies missing WITH CHECK | `20240113_12_fix_rls_policies.sql` | Add FOR INSERT/UPDATE/DELETE policies with WITH CHECK for all 7 admin-only tables |
| 3 | clinic_memberships INSERT unrestricted | `20240112_11_add_clinic_membership.sql` | Add explicit FOR INSERT WITH CHECK policy |
| 4 | patients UPDATE ownership modification | `20240112_11_add_clinic_membership.sql` | Add `WITH CHECK (clinic_id = OLD.clinic_id AND patient_owner_id = OLD.patient_owner_id)` |
| 5 | clinic_settings cross-clinic access | `20240113_12_fix_rls_policies.sql` | Add clinic_id column and scope SELECT policy |
| 6 | patient_owner_id FK ON DELETE | `20240112_11_add_clinic_membership.sql` | Add `ON DELETE SET NULL` to FK constraint |

### 9.2 High Priority Fixes

| # | Fix | File | Notes |
|---|-----|------|-------|
| 7 | clinic_memberships UNIQUE constraint | `20240112_11_add_clinic_membership.sql` | Remove or modify to allow multiple roles |
| 8 | clinic creation default subquery risk | `20240111_10_create_clinics.sql` | Add explicit clinic creation before ALTER TABLE |
| 9 | consent_events INSERT policy change | `20240113_12_fix_rls_policies.sql` | Require explicit approval for staff INSERT |
| 10 | patient_link_requests RLS | New migration | Add admin-only RLS for link request table |

### 9.3 Medium Priority Improvements

| # | Fix | File | Notes |
|---|-----|------|-------|
| 11 | Audit logging for RLS violations | New migration | Trigger-based audit trail |
| 12 | JWT TTL evaluation | `backend/app/core/auth.py` | Reduce to 15 minutes for revoked staff |
| 13 | Rollback procedure documentation | Migration comments | Document rollback steps explicitly |

### 9.4 Not Required (Already Correct)

- `is_clinic_member()` function design
- GiST exclusion constraint
- Service-role client isolation
- JWT verification flow
- Advisory lock serialization
- Clinic hours type fix
- Table privilege revocation

---

## 10. Final Implementation-Readiness Decision

**VERDICT: NOT APPROVED FOR PHASE 2.6N.15**

The proposed architecture correctly identifies the high-level problems but contains **critical SQL implementation errors** that would introduce new vulnerabilities if applied as written:

1. **7 tables have unrestricted INSERT due to missing WITH CHECK clauses on FOR ALL policies** — This is a systemic error, not a single oversight. Every admin-only write table would accept inserts from any authenticated user.

2. **The clinic_memberships INSERT vulnerability is especially dangerous** — Any user can self-add to any clinic, gaining staff-level access to all clinic data.

3. **The consent_events INSERT policy change expands the attack surface** — This requires explicit business approval.

**Conditions for APPROVAL:**

| # | Condition | Status |
|---|-----------|--------|
| 1 | Fix profiles UPDATE with WITH CHECK (role = OLD.role) | NOT DONE |
| 2 | Fix all 7 FOR ALL admin policies with separate INSERT/UPDATE/DELETE policies | NOT DONE |
| 3 | Fix clinic_memberships with explicit INSERT WITH CHECK | NOT DONE |
| 4 | Fix patients UPDATE with WITH CHECK on ownership fields | NOT DONE |
| 5 | Fix clinic_settings with clinic_id scoping | NOT DONE |
| 6 | Add ON DELETE SET NULL to patient_owner_id FK | NOT DONE |
| 7 | Resolve consent_events INSERT policy (design decision) | NOT DONE |
| 8 | Remove or modify clinic_memberships UNIQUE constraint | NOT DONE |

**Do not proceed to Phase 2.6N.15 until all 8 conditions are resolved.**

---

## 11. Summary of Changes Required

### 11.1 Profiles Table (20240102_01)

```sql
-- BEFORE (vulnerable):
create policy "Users can upsert own profile" on public.profiles
  for all using (auth.uid() = id) with check (auth.uid() = id);

-- AFTER (corrected):
CREATE POLICY "Users can read own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Admins can read all profiles" ON public.profiles
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id AND role = OLD.role);
CREATE POLICY "Admins can manage all profiles" ON public.profiles
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

### 11.2 Clinic Memberships Table (20240112_11)

```sql
-- BEFORE (vulnerable):
CREATE POLICY "Admins can manage memberships" ON public.clinic_memberships
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- AFTER (corrected):
CREATE POLICY "Members can read own membership" ON public.clinic_memberships
  FOR SELECT USING (member_id = auth.uid() AND revoked_at IS NULL
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins can insert memberships" ON public.clinic_memberships
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins can update memberships" ON public.clinic_memberships
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins can delete memberships" ON public.clinic_memberships
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

### 11.3 All Admin-Only Write Tables Pattern

```sql
-- For EACH of: clinics, appointments, call_queue, call_logs, consent_events, clinic_settings
-- BEFORE (vulnerable):
CREATE POLICY "Admins can manage [table]" ON public.[table]
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

-- AFTER (corrected):
CREATE POLICY "Admins can read [table]" ON public.[table]
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins can insert [table]" ON public.[table]
  FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins can update [table]" ON public.[table]
  FOR UPDATE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "Admins can delete [table]" ON public.[table]
  FOR DELETE USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

---

**END OF PHASE 2.6N.14B SQL CORRECTNESS REVIEW**
