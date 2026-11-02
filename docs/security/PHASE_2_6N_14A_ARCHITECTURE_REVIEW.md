# Phase 2.6N.14A — Independent Architecture Review

**Date:** 2026-11-01
**Type:** READ-ONLY Adversarial Review
**Status:** AUDIT ONLY — No code changes made
**Verdict:** APPROVED WITH CONDITIONS

---

## 1. Executive Verdict

**APPROVED WITH CONDITIONS**

The proposed clinic-membership architecture correctly addresses the critical findings from Phase 2.6N.13 (cross-patient data exposure, broken consent_events ownership, missing clinic isolation). The design introduces proper tenant boundaries and patient self-service through nullable ownership mapping.

However, three high-severity conditions must be resolved before Phase 2.6N.15 implementation:

1. **CRITICAL:** The `profiles` table UPDATE policy allows privilege escalation — any user can set `role = 'admin'` on their own profile.
2. **HIGH:** The `patients` UPDATE policy lacks a `WITH CHECK` clause, allowing patients to modify `clinic_id` or `patient_owner_id` fields.
3. **HIGH:** The `clinic_settings` SELECT policy is not scoped to clinic membership — any member can read settings from any clinic.

These three issues are fixable with minimal SQL changes and do not require architectural redesign.

---

## 2. Scope and Files Inspected

### Source Materials

| File | Lines Inspected | Key Findings |
|------|----------------|---------------|
| `docs/security/PHASE_2_6N_14_OWNERSHIP_ARCHITECTURE.md` | 1-596 | Complete architecture proposal |
| `supabase/migrations/20240102_01_create_profiles.sql` | 1-26 | profiles RLS: FOR ALL USING (auth.uid()=id) WITH CHECK (auth.uid()=id) |
| `supabase/migrations/20240103_02_create_patients.sql` | 1-40 | Permissive SELECT, admin-only writes |
| `supabase/migrations/20240104_03_create_appointments.sql` | 1-133 | GiST constraint + book_appointment RPC |
| `supabase/migrations/20240105_04_create_call_queue.sql` | 1-36 | Permissive SELECT, admin-only writes |
| `supabase/migrations/20240106_05_create_call_logs.sql` | 1-37 | Permissive SELECT, admin-only writes |
| `supabase/migrations/20240107_06_create_clinic_settings.sql` | 1-29 | Permissive SELECT, admin-only writes |
| `supabase/migrations/20240108_07_create_consent_events.sql` | 1-37 | Permissive SELECT (broken fix in 20240110_09) |
| `supabase/migrations/20240109_08_secure_appointment_rpc.sql` | 1-97 | RPC hardening: search_path='', EXECUTE revoked |
| `supabase/migrations/20240110_09_harden_privileges_and_fix_rls.sql` | 1-81 | Privilege revocation + broken consent fix |
| `backend/app/core/auth.py` | 1-266 | JWT verification: role from verified_claims only |
| `backend/app/api/patients.py` | 1-89 | Admin write endpoints, permissive read |
| `backend/app/api/appointments.py` | 1-99 | Service-role booking, admin updates |
| `backend/app/api/calls.py` | 1-198 | Admin write endpoints, permissive read |
| `backend/app/api/settings.py` | 1-58 | Admin settings management |
| `backend/app/db/supabase.py` | 1-62 | Service-role client isolation |
| `backend/tests/test_auth.py` | 1-265 | 9 tests: forged JWT, verified claims |
| `backend/tests/test_appointment_security.py` | 1-278 | 16 tests: service-role, admin auth, overlap |
| `backend/tests/test_rate_limit.py` | 1-64 | 4 tests: limiter config |

---

## 3. Confirmed Existing Security Controls

### 3.1 JWT Authorization (VERIFIED CORRECT)

- **File:** `backend/app/core/auth.py:215`
- **Control:** `role=verified_claims.get("role", "authenticated")` — role extracted only after JWKS signature verification
- **Evidence:** Grep across entire codebase confirms zero instances of `unverified.get("role")`
- **Verification:** 9 unit tests pass, including `TestForgedAdminJWT` and `TestJWTVerificationFlow`

### 3.2 RPC Authorization Closure (VERIFIED CORRECT)

- **File:** `supabase/migrations/20240109_08_secure_appointment_rpc.sql:90-96`
- **Control:** `REVOKE EXECUTE` from PUBLIC, anon, authenticated; `GRANT EXECUTE` to service_role only
- **Function hardened:** `SECURITY DEFINER SET search_path = ''`
- **Backend isolation:** `appointments.py:63-66` uses `get_supabase_service_role_client()` with fail-closed (500 if key missing)

### 3.3 Race Condition Protection (VERIFIED CORRECT)

- **Advisory lock:** `pg_advisory_xact_lock(hashtextextended('booking_lock', 0))` serializes bookings
- **GiST exclusion constraint:** `exclude using gist (tstzrange(starts_at, ends_at, '[)') with &&) WHERE (status in ('scheduled', 'rescheduled'))`
- **Defect detection:** Three-layer defense (lock + explicit check + constraint)

### 3.4 Clinic Hours Type Fix (VERIFIED CORRECT)

- **File:** `supabase/migrations/20240109_08_secure_appointment_rpc.sql:59,62`
- **Fix:** `v_starts_local::time < TIME '10:00'` (time vs time comparison, not timestamp vs time)

### 3.5 Write Endpoint Authorization (VERIFIED CORRECT)

All 8 write endpoints use `require_admin` dependency AND database RLS policies require admin:
- `POST /api/appointments`, `PATCH /api/appointments/{id}`
- `POST /api/patients`, `PATCH /api/patients/{id}`
- `PATCH /api/settings`
- `POST /api/calls/simulate`, `POST /api/calls/queue`, `POST /api/calls/start`

### 3.6 Table Privilege Revocation (VERIFIED CORRECT)

- **File:** `supabase/migrations/20240110_09_harden_privileges_and_fix_rls.sql:22-28`
- **Control:** `REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN` from anon/authenticated on all 7 tables
- **Default privileges:** Adjusted for future tables (service_role full, anon/auth CRUD only)

---

## 4. Architecture Weaknesses

### 4.1 CRITICAL: profiles UPDATE Policy Allows Privilege Escalation

**Location:** `supabase/migrations/20240102_01_create_profiles.sql:24-25`

```sql
create policy "Users can upsert own profile" on public.profiles
  for all using (auth.uid() = id) with check (auth.uid() = id);
```

**Problem:** The `FOR ALL` applies to SELECT, INSERT, UPDATE, and DELETE. The `WITH CHECK` only verifies that the user owns the row (`auth.uid() = id`), but does NOT restrict which fields can be modified. A regular user can execute:

```sql
UPDATE profiles SET role = 'admin' WHERE id = auth.uid();
```

**This is a direct privilege escalation path.** Any authenticated user can self-promote to admin by updating their own profile's `role` field.

**Required Fix:**
```sql
-- Separate UPDATE policy that restricts role modification
DROP POLICY IF EXISTS "Users can upsert own profile" ON public.profiles;

CREATE POLICY "Users can read own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = id)
  WITH CHECK (
    auth.uid() = id
    AND role = OLD.role  -- prevent role change
  );

CREATE POLICY "Admins can manage all profiles" ON public.profiles
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

### 4.2 HIGH: patients UPDATE Policy Lacks WITH CHECK Clause

**Location:** Proposed migration `20240112_11_add_clinic_membership_and_patient_ownership.sql`

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
  );
```

**Problem:** PostgreSQL RLS `USING` clause controls WHICH rows can be targeted but does NOT constrain WHAT values can be written. A patient with `patient_owner_id = auth.uid()` can update ANY field, including:

- `clinic_id` → transfer their record to another clinic
- `patient_owner_id` → claim another user's ownership
- `call_consent` → override consent status
- `do_not_call` → override DNC status

**Required Fix:**
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
    -- Prevent changing ownership or clinic assignment
    clinic_id = OLD.clinic_id
    AND patient_owner_id = OLD.patient_owner_id
  );
```

### 4.3 HIGH: clinic_settings Not Scoped to Clinic

**Location:** Proposed migration `20240113_12_fix_rls_policies_for_patient_data.sql`

```sql
CREATE POLICY "Members can read clinic settings" ON public.clinic_settings
  FOR SELECT USING (EXISTS (SELECT 1 FROM public.clinic_memberships
    WHERE member_id = auth.uid() AND revoked_at IS NULL));
```

**Problem:** This policy allows ANY clinic member to read ALL rows in `clinic_settings`, regardless of which clinic they belong to. If multiple clinics exist, Clinic A staff can read Clinic B's settings.

**Current state:** `clinic_settings` has no `clinic_id` column, so there is no scoping mechanism.

**Options:**
1. **Add `clinic_id` to `clinic_settings`** (recommended for multi-clinic):
   ```sql
   ALTER TABLE public.clinic_settings ADD COLUMN clinic_id uuid REFERENCES public.clinics(id);
   UPDATE public.clinic_settings SET clinic_id = (SELECT id FROM public.clinics LIMIT 1);
   CREATE POLICY "Members can read clinic settings" ON public.clinic_settings
     FOR SELECT USING (
       EXISTS (SELECT 1 FROM public.clinic_memberships m
         WHERE m.member_id = auth.uid() AND m.revoked_at IS NULL
           AND m.clinic_id = clinic_settings.clinic_id)
       OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
     );
   ```
2. **Keep single-clinic assumption** and document that clinic_settings is global (acceptable for current single-clinic deployment).

### 4.4 MEDIUM: No Mechanism for Secure Patient Account Linking

**Location:** Proposed architecture, Section 6.1

The architecture identifies that `patient_owner_id` should link patients to their accounts but provides no secure workflow for this linkage.

**Risks:**
- Automatic email-based linking could incorrectly associate accounts
- Manual linking requires a trusted admin action
- Patient-initiated linking requires proof of ownership (phone number?)

**Recommended Workflow:**
1. Patient creates account (profile inserted via Supabase Auth)
2. Patient requests account linking via authenticated API call
3. Backend verifies patient identity (phone number match)
4. Admin or automated process sets `patient_owner_id`
5. Audit log entry created for the linkage

**This workflow should be documented in the implementation plan (Phase 2.6N.15).**

### 4.5 MEDIUM: clinic_settings Write Policies Still Use FOR ALL

**Location:** Proposed migration, line for clinic_settings

```sql
CREATE POLICY "Admins can manage clinic settings" ON public.clinic_settings
  FOR ALL USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
```

**Problem:** `FOR ALL` covers INSERT, which doesn't make sense for settings (settings are key-value pairs, not created by users). This should be split:
- SELECT: any clinic member
- UPDATE/DELETE: admin only
- No INSERT policy needed (settings managed by admin or initial migration)

---

## 5. Patient Ownership Workflow Assessment

### 5.1 How is a patient account securely linked?

**Current proposal:** `patient_owner_id` column added to `patients` table, nullable FK to `profiles.id`.

**Gap:** No explicit workflow defined for establishing this linkage. The architecture says "optional" but doesn't specify:
- Who initiates the linkage (patient or admin)?
- What verification is required (phone match, email match, manual confirmation)?
- How is the linkage logged for audit purposes?

**Recommendation:** Add a dedicated `patient_link_requests` table and a backend endpoint for secure linking:

```sql
CREATE TABLE public.patient_link_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  patient_id uuid NOT NULL REFERENCES public.patients(id) ON DELETE CASCADE,
  profile_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  verified_phone text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz,
  approved_by uuid REFERENCES public.profiles(id)
);
```

### 5.2 Who is authorized to create/update/revoke the mapping?

**Proposed:** Admin-only via RLS (implicit, since patients UPDATE requires clinic membership or admin role).

**Assessment:** Correct. Only clinic staff (via clinic_memberships) or admins should be able to set `patient_owner_id`. The proposed RLS policies achieve this.

### 5.3 Can a patient claim another patient's record?

**With current proposed policies:** YES, partially.
- A patient can UPDATE their own `patients` row (if they have `patient_owner_id` set).
- But they CANNOT change `clinic_id` or `patient_owner_id` without the `WITH CHECK` fix.
- They CANNOT access another patient's record via SELECT because `patient_owner_id` won't match their `auth.uid()`.

**After fixes:** NO. The `WITH CHECK` clause prevents modification of ownership fields.

### 5.4 Can an authenticated user change `patient_owner_id` directly?

**With current proposed policies:** NO — because:
1. They cannot SELECT another patient's row (ownership check fails)
2. They cannot UPDATE `patient_owner_id` on their own row (but this doesn't matter since they already own it)

**After fixes:** Explicitly prevented by `WITH CHECK (patient_owner_id = OLD.patient_owner_id)`.

### 5.5 What happens when a patient account is deleted?

**Cascade behavior:**
- `profiles.id` references `auth.users.id` with `ON DELETE CASCADE`
- `patient_owner_id` FK to `profiles.id` has no `ON DELETE` clause (will fail on delete)
- `clinic_memberships.member_id` FK to `profiles.id` with `ON DELETE CASCADE`

**Issue:** Deleting a `profiles` row will fail if `patient_owner_id` references it without `ON DELETE CASCADE`.

**Fix:** Add `ON DELETE SET NULL` to `patient_owner_id`:
```sql
ALTER TABLE public.patients ADD COLUMN patient_owner_id uuid REFERENCES public.profiles(id) ON DELETE SET NULL;
```

This way, when a patient deletes their account, their `patient_owner_id` becomes NULL and they lose access to their own records (but records remain for clinic staff).

### 5.6 How are duplicate or conflicting ownership claims handled?

**Current proposal:** `patient_owner_id` is a single FK — one patient can only have one owner.

**Scenario:** What if two users claim the same patient?
- First linkage succeeds
- Second linkage attempt fails (FK constraint) or requires admin intervention
- No conflict resolution mechanism defined

**Recommendation:** The `patient_link_requests` table (see 5.1) provides the conflict resolution mechanism. Pending requests can be reviewed by admins.

### 5.7 Can a patient belong to multiple clinics?

**Current proposal:** `patients.clinic_id` is a single FK — one patient belongs to exactly one clinic.

**Assessment:** This is correct for the dental clinic use case. A patient has one primary clinic. If multi-clinic visits are needed in the future, a junction table can be added.

---

## 6. Clinic Isolation Matrix

### 6.1 Table-by-Table Ownership Analysis

| Table | Ownership Column | Scope | SELECT Authorization | INSERT | UPDATE | DELETE |
|-------|-----------------|-------|---------------------|--------|--------|--------|
| `profiles` | `id` = `auth.uid()` | Self-only | Own profile + admin sees all | N/A (auth trigger) | Admin only (after fix) | N/A |
| `patients` | `patient_owner_id` + `clinic_id` | Patient + clinic | Own + clinic staff + admin | Clinic staff + admin | Clinic staff + admin (after WITH CHECK fix) | Admin only |
| `appointments` | `patient_id` -> `clinic_id` | Clinic | Patient's appointments + clinic + admin | Admin only (RPC) | Admin only | Admin only |
| `call_queue` | `patient_id` -> `clinic_id` | Clinic | Clinic staff + admin | Admin only | Admin only | Admin only |
| `call_logs` | `patient_id` -> `clinic_id` | Clinic | Clinic staff + admin | Admin only | Admin only | Admin only |
| `clinic_settings` | N/A (no patient data) | Global/Clinic | Any member (after clinic_id fix) | Admin only | Admin only | Admin only |
| `consent_events` | `patient_id` -> `clinic_id` | Patient + clinic | Own consent + clinic + admin | Clinic staff + admin | Admin only | Admin only |
| `clinics` | N/A | System | Admin only | Admin only | Admin only | Admin only |
| `clinic_memberships` | `member_id` + `clinic_id` | Self + admin | Own membership + admin | Admin only | Admin only | Admin only |

### 6.2 Cross-Clinic Isolation Verification

**Appointments:**
- Patient A (Clinic 1) -> Appointments filtered by `patient_owner_id = auth.uid()` OR `is_clinic_member(auth.uid(), clinic_id)`
- Staff B (Clinic 2) -> `is_clinic_member` returns FALSE for Clinic 1 patients
- **Result:** Isolated

**Call Logs:**
- Same pattern as appointments via `patient_id` -> `clinic_id`
- **Result:** Isolated

**Consent Events:**
- Same pattern as appointments
- **Result:** Isolated

**Potential Bypass Vector:**
- If a staff member can INSERT a record with another clinic's `patient_id`, they could access cross-clinic data
- INSERT policies require `is_clinic_member(auth.uid(), clinic_id)` matching the NEW row's `clinic_id`
- **Result:** Safe — staff can only insert for their own clinic

---

## 7. Membership and Role Security Assessment

### 7.1 Multiple Clinic Memberships

**Supported:** A user can belong to multiple clinics (no UNIQUE constraint on `member_id` alone).

**Risk:** A user could gain access to multiple clinics' data. This is intentional for multi-clinic operations.

**Mitigation:** Each clinic's data is scoped by `clinic_id`, so cross-clinic access is controlled.

### 7.2 Membership Revocation

**Mechanism:** `revoked_at IS NOT NULL` indicates revoked membership.

**Immediate effect:** RLS policies check `revoked_at IS NULL`, so revoked members lose access immediately.

**Existing sessions:** JWT remains valid until expiry. Revoked member can continue accessing data until token expires.

**Recommended:** Reduce JWT TTL to 15 minutes or implement token revocation list.

### 7.3 Disabled or Deleted Users

**Behavior:**
- Delete `profiles` row -> `clinic_memberships` cascades (ON DELETE CASCADE)
- Delete `profiles` row -> `patient_owner_id` breaks FK (needs ON DELETE SET NULL)
- Revoked membership -> loses access immediately via RLS

**Fix needed:** Add `ON DELETE SET NULL` to `patients.patient_owner_id` FK (see 5.5).

### 7.4 Role Changes

**Current (before fix):** User can change their own `role` field via UPDATE. **VULNERABLE.**

**After fix:** `WITH CHECK (role = OLD.role)` prevents self-promotion.

**Admin role changes:** Admins can update any profile's role via admin policy.

### 7.5 Duplicate Memberships

**Constraint:** `UNIQUE (clinic_id, member_id)` prevents duplicate memberships for same clinic.

### 7.6 Unauthorized Self-Promotion

**Current (profiles):** **VULNERABLE** — user can UPDATE `role = 'admin'` on their own profile.

**After fix:** `WITH CHECK (role = OLD.role)` prevents this.

### 7.7 Clinic Administrator Boundaries

**Current design:** Single global admin (role = 'admin' in profiles).

**Multi-clinic consideration:** For future multi-clinic support, consider adding `clinic_admin` role or per-clinic admin scope. Not required for current single-clinic deployment.

### 7.8 Service-Role Access

**Controlled by:** `GRANT EXECUTE ON FUNCTION ... TO service_role` + backend `get_supabase_service_role_client()` fail-closed.

**Bypasses RLS:** Service role is a superuser-equivalent that bypasses RLS entirely.

**Safety:** Backend requires `require_admin` before using service-role client. Defense in depth.

---

## 8. SECURITY DEFINER Helper Review

### 8.1 Function Definition

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

### 8.2 Security Checks

| Check | Status | Notes |
|-------|--------|-------|
| `SET search_path = ''` | PASS | Prevents schema poisoning |
| Fully qualified references | PASS | `public.clinic_memberships` used |
| Minimal execution privileges | PASS | Only `service_role` granted EXECUTE |
| Explicit authorization checks | PASS | Checks revoked_at, member_id, clinic_id |
| No caller-controlled identity substitution | PASS | `auth.uid()` used in calling policies, not `p_user_id` |
| No recursive RLS dependency | PASS | Function bypasses RLS via SECURITY DEFINER; function only returns boolean |
| No information disclosure | PASS | Returns boolean only, no row data |

### 8.3 Should the helper accept both clinic ID and user ID?

**Yes.** The current signature `(p_user_id uuid, p_clinic_id uuid)` is correct.

- `p_user_id` comes from `auth.uid()` in the calling RLS policy (trusted)
- `p_clinic_id` comes from the row being accessed (data-driven, not user-controlled)

This prevents identity substitution attacks where a caller could pass their own UUID to check membership for another user.

### 8.4 Privilege Escalation Paths

**None identified.** The function:
- Only returns boolean
- Only reads from `clinic_memberships`
- Does not modify any data
- Requires `service_role` to execute directly (bypassed by RLS policies via SECURITY DEFINER)

---

## 9. Migration and Rollback Review

### 9.1 Migration 20240111_10: Create Clinics

| Aspect | Assessment |
|--------|------------|
| Tables added | `clinics` (id, name, address, created_at) |
| Constraints | PRIMARY KEY, RLS enabled, admin-only policy |
| Rollback | DROP TABLE — safe if empty or no dependencies |
| Downtime | None (CREATE TABLE IF NOT EXISTS) |
| Risk | Low |

### 9.2 Migration 20240112_11: Add Clinic Membership and Patient Ownership

| Aspect | Assessment |
|--------|------------|
| Tables added | `clinic_memberships` (id, clinic_id, member_id, role, joined_at, revoked_at) |
| Columns added | `patients.clinic_id` (NOT NULL, default from clinics), `patients.patient_owner_id` (nullable FK) |
| Indexes | `idx_patients_clinic_id`, `idx_patients_owner_id` |
| Rollback | DROP COLUMN requires no dependent objects; DROP TABLE for memberships |
| Downtime | ADD COLUMN with default is online-safe in PostgreSQL |
| Risk | Medium — ALTER TABLE on patients may lock briefly; backfill is safe |

**Backfill risk:** Legacy patients get `clinic_id = (default clinic)` and `patient_owner_id = NULL`. These records become inaccessible to ordinary users. Safe default.

### 9.3 Migration 20240113_12: Fix RLS Policies

| Aspect | Assessment |
|--------|------------|
| Functions added | `is_clinic_member(uuid, uuid)` SECURITY DEFINER |
| Policies dropped | 18 existing policies across 6 tables |
| Policies created | 14 new policies with ownership + clinic scoping |
| Grants changed | EXECUTE granted to service_role, revoked from PUBLIC/anon/authenticated |
| Rollback | DROP POLICY IF EXISTS is idempotent; DROP FUNCTION is safe |
| Risk | Low — all operations are idempotent |

**Rollback concern:** If rollback drops the `is_clinic_member` function without first revoking EXECUTE, the function definition is gone but the grant record remains (harmless). If rollback is done in wrong order, policies may reference non-existent function. **Mitigation:** Document rollback procedure explicitly.

---

## 10. Adversarial Test Matrix

### 10.1 Patient-to-Patient Isolation

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 1 | User A (profile_id='a', role='user'), Patient B (patient_owner_id='b', clinic_id='c1') | User A SELECT patients WHERE id='patient-b-id' | DENIED (403/RLS) | No cross-patient access |
| 2 | User A (profile_id='a', role='user'), Patient A (patient_owner_id='a', clinic_id='c1') | User A SELECT patients WHERE id='patient-a-id' | ALLOWED | Self-access works |
| 3 | Staff B (profile_id='b', clinic_memberships: clinic_id='c1') | Staff B SELECT patients WHERE clinic_id='c1' | ALLOWED | Clinic staff access |
| 4 | Staff B (clinic='c1'), Patient X (clinic='c2') | Staff B SELECT patients WHERE id='patient-x-id' | DENIED | Cross-clinic isolation |
| 5 | Anonymous (no JWT) | SELECT patients | DENIED (401) | No anonymous access |
| 6 | User A (role='user', no memberships) | SELECT patients WHERE id='any' | DENIED | No unaffiliated access |

### 10.2 Appointment Isolation

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 7 | Patient A (clinic='c1'), Appointment X (patient='patient-x', clinic='c2') | Patient A SELECT appointments | DENIED | Cross-clinic appointment isolation |
| 8 | Staff B (clinic='c1'), Appointment Y (patient='patient-y', clinic='c1') | Staff B SELECT appointments | ALLOWED | Clinic appointment access |
| 9 | Admin C | SELECT appointments WHERE any | ALLOWED | Admin universal access |
| 10 | User D (no clinic) | INSERT appointments | DENIED | No unauthorized inserts |

### 10.3 Consent Event Isolation

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 11 | Patient A | SELECT consent_events WHERE patient_id='patient-b-id' | DENIED | No cross-patient consent access |
| 12 | Staff B (clinic='c1') | SELECT consent_events WHERE patient in clinic='c1' | ALLOWED | Clinic consent access |
| 13 | Staff B | INSERT consent_events for patient in clinic='c2' | DENIED | No cross-clinic consent inserts |

### 10.4 Call Log Isolation

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 14 | Patient A | SELECT call_logs WHERE patient_id='patient-b-id' | DENIED | PHI isolation |
| 15 | Staff B (clinic='c1') | SELECT call_logs WHERE patient in clinic='c1' | ALLOWED | Clinic call log access |
| 16 | User C (no clinic) | SELECT call_logs | DENIED | Unaffiliated denial |

### 10.5 Revoked Member Access

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 17 | Staff B (membership revoked_at='2026-01-01') | SELECT patients WHERE clinic_id='c1' | DENIED | Revoked members blocked |
| 18 | Staff B (revoked) with valid JWT | INSERT appointments | DENIED | Revoked = no writes |
| 19 | Staff B (revoked) with valid JWT | SELECT call_logs | DENIED | Revoked = no PHI access |

### 10.6 Ownership Manipulation Attempts

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 20 | Patient A (owns patient-record-A) | UPDATE patients SET patient_owner_id='user-b-id' WHERE id='patient-a-id' | DENIED (WITH CHECK fails) | Cannot transfer ownership |
| 21 | Patient A | UPDATE patients SET clinic_id='clinic-b-id' WHERE id='patient-a-id' | DENIED (WITH CHECK fails) | Cannot change clinic |
| 22 | User X (no account) | UPDATE profiles SET role='admin' WHERE id='user-x-id' | DENIED (RLS) | No self-promotion |
| 23 | User A (role='user') | UPDATE profiles SET role='admin' WHERE id='user-a-id' | DENIED (WITH CHECK role=OLD.role) | No privilege escalation |

### 10.7 Cross-Clinic Attack Vectors

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 24 | Staff B (clinic='c1') | INSERT patients WITH clinic_id='c2' | DENIED (WITH CHECK fails clinic membership) | Cannot create in other clinic |
| 25 | Staff B (clinic='c1') | INSERT appointments WITH patient from clinic='c2' | DENIED (is_clinic_member returns false) | Cannot book other clinic |
| 26 | Staff B (clinic='c1') | SELECT clinic_settings WHERE clinic_id='c2' | DENIED (after fix) | No cross-clinic settings |

### 10.8 Anonymous and Authenticated Bypass

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 27 | No JWT | POST /api/appointments | 401 Missing token | No anonymous booking |
| 28 | User JWT (non-admin) | POST /api/appointments | 403 Admin access required | No non-admin booking |
| 29 | Anon key (no JWT) | RPC book_appointment | DENIED (EXECUTE revoked) | No direct RPC access |
| 30 | Service-role key | RPC book_appointment | ALLOWED (if admin JWT present) | Service-role works for booking |

### 10.9 Direct PostgREST Access

| # | Setup | Test | Expected Result | Invariant |
|---|-------|------|-----------------|-----------|
| 31 | Anon key | GET /patients | DENIED (RLS blocks all) | Anon cannot read patients |
| 32 | User JWT | GET /patients | Only own rows returned | RLS enforces ownership |
| 33 | Staff JWT | GET /patients | All clinic rows returned | Clinic scope works |
| 34 | Admin JWT | GET /patients | All rows returned | Admin universal access |
| 35 | User JWT | POST /patients | 403 (RLS INSERT requires admin) | No self-registration |
| 36 | User JWT | PATCH /patients/id | 403 (RLS UPDATE requires admin/staff) | No unauthorized updates |

---

## 11. Testing Environment Limitations

### 11.1 Current Limitations

| Factor | Status | Impact |
|--------|--------|--------|
| Docker/PostgreSQL | Not running locally | Cannot run database-level tests |
| PostgREST | SIGSEGV on Windows Docker Desktop | Cannot run HTTP-level integration tests |
| Supabase CLI | Installed but no linked project | Cannot run migrations locally |
| Unit tests | 29/29 passing | Auth and appointment security verified |

### 11.2 Tests by Category

| Category | Count | Status | Notes |
|----------|-------|--------|-------|
| JWT signature verification | 9 | PASSED | Unit tests with mocks |
| Service-role client config | 4 | PASSED | Unit tests |
| Admin authorization | 5 | PASSED | Unit tests |
| Rate limiting | 4 | PASSED | Unit tests |
| RLS policy isolation | 0 | NOT RUN | Requires database |
| RPC authorization | 0 | NOT RUN | Requires database + PostgREST |
| Patient ownership workflow | 0 | NOT RUN | Requires database |
| Cross-clinic isolation | 0 | NOT RUN | Requires multi-clinic setup |
| Revoked member access | 0 | NOT RUN | Requires database |

### 11.3 Potential Testing Environments

| Option | Feasibility | Notes |
|--------|-------------|-------|
| GitHub Actions (Linux runner) | HIGH | Can spin up PostgreSQL container, run migrations, execute SQL tests |
| Supabase staging project | HIGH | Real Supabase project with PostgREST, proper JWT flow |
| WSL2 with Docker | MEDIUM | May work if Docker Desktop not installed, use podman |
| Local PostgreSQL (no Docker) | MEDIUM | Install PostgreSQL 17 directly, run migrations |
| CI/CD pipeline | HIGH | Recommended for production validation |

**Recommendation:** Use GitHub Actions with a PostgreSQL container for automated RLS testing. This avoids the Windows Docker Desktop SIGSEGV issue entirely.

---

## 12. Required Architecture Changes

### 12.1 Critical Fixes (Must Resolve Before Implementation)

1. **profiles UPDATE policy** — Add `WITH CHECK (role = OLD.role)` to prevent privilege escalation
2. **patients UPDATE policy** — Add `WITH CHECK (clinic_id = OLD.clinic_id AND patient_owner_id = OLD.patient_owner_id)`
3. **patients.patient_owner_id FK** — Add `ON DELETE SET NULL` for graceful account deletion

### 12.2 High Priority Fixes (Should Resolve Before Implementation)

4. **clinic_settings** — Add `clinic_id` column and scope SELECT policy to clinic membership
5. **Patient account linking workflow** — Define secure linking process (patient_link_requests table or API endpoint)
6. **JWT TTL evaluation** — Set appropriate TTL for revoked staff mitigation (recommend 15 minutes)

### 12.3 Medium Priority Improvements

7. **clinic_settings FOR ALL** — Split into separate SELECT/UPDATE/DELETE policies
8. **Audit logging** — Add trigger-based audit trail for RLS policy violations
9. **Documentation** — Add rollback procedure to migration comments

### 12.4 Not Required (Current Design is Sufficient)

- `is_clinic_member()` function design — Correct as proposed
- GiST exclusion constraint — Already correct
- Service-role client isolation — Already correct
- JWT verification flow — Already correct
- Advisory lock serialization — Already correct

---

## 13. Implementation-Readiness Decision

**VERDICT: APPROVED WITH CONDITIONS**

The architecture is **directionally correct** and addresses all critical findings from Phase 2.6N.13. The clinic-membership model with nullable patient ownership provides proper tenant isolation and patient self-service.

**Conditions for Phase 2.6N.15:**

| # | Condition | Severity | Resolution |
|---|-----------|----------|------------|
| 1 | Fix profiles UPDATE to prevent privilege escalation | CRITICAL | Add `WITH CHECK (role = OLD.role)` |
| 2 | Fix patients UPDATE to prevent ownership modification | HIGH | Add `WITH CHECK` for clinic_id and patient_owner_id |
| 3 | Add ON DELETE SET NULL to patient_owner_id FK | HIGH | Prevents FK violation on account deletion |
| 4 | Scope clinic_settings to clinic membership | HIGH | Add clinic_id column or document single-clinic assumption |
| 5 | Define patient account linking workflow | MEDIUM | Document in implementation plan |
| 6 | Evaluate JWT TTL for revoked staff | MEDIUM | Security team decision needed |

**Do not proceed to Phase 2.6N.15 until conditions 1-4 are resolved.** Conditions 5-6 can be addressed during implementation.

---

## Summary of Confirmed Security Controls

| Control | Status | Evidence |
|---------|--------|----------|
| JWT role from verified_claims | CONFIRMED | auth.py:215, 9 passing tests |
| RPC EXECUTE restricted to service_role | CONFIRMED | Migration 20240109_08, grep verified |
| Service-role fail-closed | CONFIRMED | appointments.py:63-66, 4 passing tests |
| GiST exclusion constraint | CONFIRMED | Migration 20240104_03 |
| Advisory lock serialization | CONFIRMED | Migration 20240109_08:50 |
| Clinic hours type fix | CONFIRMED | Migration 20240109_08:59,62 |
| Table privilege revocation | CONFIRMED | Migration 20240110_09:22-28 |
| Admin-only write endpoints | CONFIRMED | 8 endpoints, all use require_admin |
| profiles privilege escalation | VULNERABLE | FOR ALL with only row ownership check |
| patients ownership modification | VULNERABLE | FOR UPDATE missing WITH CHECK |
| clinic_settings cross-clinic | VULNERABLE | No clinic_id scoping |
| RLS policy isolation (proposed) | UNTESTED | Requires database |
| Patient ownership workflow | UNDEFINED | Needs implementation plan |

---

**END OF PHASE 2.6N.14A ARCHITECTURE REVIEW**
