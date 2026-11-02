-- Phase 2.6N.15 — PostgreSQL RLS Security Integration Tests
-- Run against PostgreSQL 17 after all migrations applied
-- Requires: supabase/migrations/*.sql already applied

-- =============================================================================
-- SETUP: Test utilities
-- =============================================================================

-- Create test user with profile
CREATE OR REPLACE FUNCTION public.create_test_user(p_email text, p_role text DEFAULT 'user')
RETURNS uuid AS $$
DECLARE
  v_user_id uuid;
BEGIN
  INSERT INTO auth.users (id, email, email_confirmed_at)
  VALUES (gen_random_uuid(), p_email, now())
  RETURNING id INTO v_user_id;

  INSERT INTO public.profiles (id, email, role)
  VALUES (v_user_id, p_email, p_role);

  RETURN v_user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = '';

GRANT EXECUTE ON FUNCTION public.create_test_user(text, text) TO service_role;
REVOKE EXECUTE ON FUNCTION public.create_test_user(text, text) FROM PUBLIC;

-- Set JWT claims for RLS testing
CREATE OR REPLACE FUNCTION public.set_jwt_claims(p_sub uuid, p_role text, p_email text)
RETURNS void AS $$
BEGIN
  PERFORM set_config('request.jwt.claims',
    '{"sub":"' || p_sub::text || '","role":"' || p_role || '","email":"' || p_email || '"}'::jsonb,
    true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = '';

GRANT EXECUTE ON FUNCTION public.set_jwt_claims(uuid, text, text) TO service_role;
REVOKE EXECUTE ON FUNCTION public.set_jwt_claims(uuid, text, text) FROM PUBLIC;

-- =============================================================================
-- TEST 1: Self-promotion prevention (CRITICAL)
-- =============================================================================

DO $$
DECLARE
  test_user_id uuid;
BEGIN
  test_user_id := public.create_test_user('test_self_promo@example.com', 'user');
  PERFORM public.set_jwt_claims(test_user_id, 'user', 'test_self_promo@example.com');

  BEGIN
    UPDATE public.profiles SET role = 'admin' WHERE id = test_user_id;
    RAISE EXCEPTION 'FAIL: Self-promotion was NOT blocked';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS: Self-promotion blocked by WITH CHECK (role = OLD.role)';
  END;
END $$;

-- =============================================================================
-- TEST 2: Unauthorized clinic membership insertion
-- =============================================================================

DO $$
DECLARE
  test_user_id uuid;
  test_clinic_id uuid;
BEGIN
  test_user_id := public.create_test_user('test_membership@example.com', 'user');

  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO test_clinic_id;

  -- Insert membership as admin (superuser bypasses RLS for test setup)
  INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
  VALUES (test_clinic_id, test_user_id, 'staff');

  -- Switch to regular user and attempt self-add
  PERFORM public.set_jwt_claims(test_user_id, 'user', 'test_membership@example.com');

  BEGIN
    INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
    VALUES (test_clinic_id, test_user_id, 'staff');
    RAISE EXCEPTION 'FAIL: Unauthorized membership insert was NOT blocked';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS: Unauthorized membership insert blocked by WITH CHECK';
  END;
END $$;

-- =============================================================================
-- TEST 3: Patient ownership transfer prevention
-- =============================================================================

DO $$
DECLARE
  owner_id uuid;
  attacker_id uuid;
  patient_id uuid;
  clinic_id uuid;
BEGIN
  owner_id := public.create_test_user('owner@example.com', 'user');
  attacker_id := public.create_test_user('attacker@example.com', 'user');

  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO clinic_id;

  INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
  VALUES (clinic_id, owner_id, 'staff');

  INSERT INTO public.patients (id, clinic_id, patient_owner_id, full_name, phone)
  VALUES (gen_random_uuid(), clinic_id, owner_id, 'Test Patient', '9876543210')
  RETURNING id INTO patient_id;

  PERFORM public.set_jwt_claims(owner_id, 'user', 'owner@example.com');

  BEGIN
    UPDATE public.patients SET patient_owner_id = attacker_id WHERE id = patient_id;
    RAISE EXCEPTION 'FAIL: Ownership transfer was NOT blocked';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS: Ownership transfer blocked by WITH CHECK';
  END;
END $$;

-- =============================================================================
-- TEST 4: Cross-clinic isolation
-- =============================================================================

DO $$
DECLARE
  clinic_a uuid;
  clinic_b uuid;
  staff_a uuid;
  patient_b uuid;
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Clinic A') RETURNING id INTO clinic_a;
  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Clinic B') RETURNING id INTO clinic_b;

  staff_a := public.create_test_user('staffa@example.com', 'user');
  INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
  VALUES (clinic_a, staff_a, 'staff');

  INSERT INTO public.patients (id, clinic_id, full_name, phone)
  VALUES (gen_random_uuid(), clinic_b, 'Clinic B Patient', '1111111111')
  RETURNING id INTO patient_b;

  PERFORM public.set_jwt_claims(staff_a, 'user', 'staffa@example.com');

  IF EXISTS (SELECT 1 FROM public.patients WHERE id = patient_b) THEN
    RAISE EXCEPTION 'FAIL: Cross-clinic isolation NOT enforced';
  ELSE
    RAISE NOTICE 'PASS: Cross-clinic isolation enforced';
  END IF;
END $$;

-- =============================================================================
-- TEST 5: Revoked member access
-- =============================================================================

DO $$
DECLARE
  clinic_id uuid;
  staff_id uuid;
  patient_id uuid;
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO clinic_id;

  staff_id := public.create_test_user('revoked@example.com', 'user');
  INSERT INTO public.clinic_memberships (clinic_id, member_id, role, revoked_at)
  VALUES (clinic_id, staff_id, 'staff', now());

  INSERT INTO public.patients (id, clinic_id, full_name, phone)
  VALUES (gen_random_uuid(), clinic_id, 'Revoked Staff Patient', '2222222222')
  RETURNING id INTO patient_id;

  PERFORM public.set_jwt_claims(staff_id, 'user', 'revoked@example.com');

  IF EXISTS (SELECT 1 FROM public.patients WHERE id = patient_id) THEN
    RAISE EXCEPTION 'FAIL: Revoked member still has access';
  ELSE
    RAISE NOTICE 'PASS: Revoked member access blocked';
  END IF;
END $$;

-- =============================================================================
-- TEST 6: Service-role bypasses RLS
-- =============================================================================

DO $$
DECLARE
  regular_user_id uuid;
BEGIN
  regular_user_id := public.create_test_user('regular@example.com', 'user');

  PERFORM set_config('role', 'service_role', true);

  IF EXISTS (SELECT 1 FROM public.profiles WHERE id = regular_user_id) THEN
    RAISE NOTICE 'PASS: service_role bypasses RLS (expected behavior)';
  ELSE
    RAISE EXCEPTION 'FAIL: service_role cannot read profiles';
  END IF;

  PERFORM set_config('role', 'authenticated', true);
END $$;

-- =============================================================================
-- TEST 7: Consent INSERT restricted to admin
-- =============================================================================

DO $$
DECLARE
  regular_user_id uuid;
  clinic_id uuid;
  patient_id uuid;
BEGIN
  regular_user_id := public.create_test_user('regular2@example.com', 'user');

  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO clinic_id;

  INSERT INTO public.patients (id, clinic_id, full_name, phone)
  VALUES (gen_random_uuid(), clinic_id, 'Consent Test Patient', '3333333333')
  RETURNING id INTO patient_id;

  PERFORM public.set_jwt_claims(regular_user_id, 'user', 'regular2@example.com');

  BEGIN
    INSERT INTO public.consent_events (patient_id, consent_type, consent_given, source)
    VALUES (patient_id, 'verbal', true, 'front_desk');
    RAISE EXCEPTION 'FAIL: Regular user could insert consent event';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS: Consent event INSERT blocked for non-admin';
  END;
END $$;

-- =============================================================================
-- TEST 8: Admin privilege escalation test
-- =============================================================================

DO $$
DECLARE
  admin_user_id uuid;
BEGIN
  admin_user_id := public.create_test_user('escalation_test@example.com', 'admin');

  BEGIN
    EXECUTE 'DROP POLICY "Admins can read all profiles" ON public.profiles';
    RAISE EXCEPTION 'FAIL: Non-superuser could drop RLS policy';
  EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'PASS: Non-superuser cannot drop RLS policies';
  END;
END $$;

-- =============================================================================
-- TEST 9: Legacy unmapped record access
-- =============================================================================

DO $$
DECLARE
  regular_user_id uuid;
  clinic_id uuid;
  legacy_patient_id uuid;
BEGIN
  regular_user_id := public.create_test_user('legacy_test@example.com', 'user');

  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO clinic_id;

  INSERT INTO public.patients (id, clinic_id, full_name, phone)
  VALUES (gen_random_uuid(), clinic_id, 'Legacy Patient', '4444444444')
  RETURNING id INTO legacy_patient_id;

  INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
  VALUES (clinic_id, regular_user_id, 'staff');

  PERFORM public.set_jwt_claims(regular_user_id, 'user', 'legacy_test@example.com');

  IF EXISTS (SELECT 1 FROM public.patients WHERE id = legacy_patient_id) THEN
    RAISE NOTICE 'PASS: Clinic staff can access legacy patients via clinic membership';
  ELSE
    RAISE EXCEPTION 'FAIL: Clinic staff cannot access legacy patients';
  END IF;
END $$;

-- =============================================================================
-- TEST 10: Anon key cannot access any data
-- =============================================================================

DO $$
DECLARE
  clinic_id uuid;
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO clinic_id;

  PERFORM set_config('role', 'anon', true);

  IF EXISTS (SELECT 1 FROM public.patients) THEN
    RAISE EXCEPTION 'FAIL: Anon can read patients';
  ELSE
    RAISE NOTICE 'PASS: Anon cannot read patients';
  END IF;

  IF EXISTS (SELECT 1 FROM public.profiles) THEN
    RAISE EXCEPTION 'FAIL: Anon can read profiles';
  ELSE
    RAISE NOTICE 'PASS: Anon cannot read profiles';
  END IF;

  PERFORM set_config('role', 'authenticated', true);
END $$;

-- =============================================================================
-- TEST 11: RPC book_appointment requires service_role
-- =============================================================================

DO $$
DECLARE
  test_patient_id uuid;
  test_clinic_id uuid;
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO test_clinic_id;

  INSERT INTO public.patients (id, clinic_id, full_name, phone)
  VALUES (gen_random_uuid(), test_clinic_id, 'RPC Test Patient', '5555555555')
  RETURNING id INTO test_patient_id;

  -- Verify function still exists
  IF EXISTS (
    SELECT 1 FROM information_schema.routines
    WHERE routine_schema = 'public' AND routine_name = 'book_appointment'
  ) THEN
    RAISE NOTICE 'PASS: book_appointment function exists';
  ELSE
    RAISE EXCEPTION 'FAIL: book_appointment function missing';
  END IF;

  -- Verify EXECUTE is restricted
  IF EXISTS (
    SELECT 1 FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.proname = 'book_appointment'
      AND EXISTS (
        SELECT 1 FROM pg_authid a
        WHERE a.rolname = 'anon'
        AND has_function_privilege(a.oid, p.oid, 'EXECUTE')
      )
  ) THEN
    RAISE EXCEPTION 'FAIL: Anon can execute book_appointment';
  ELSE
    RAISE NOTICE 'PASS: Anon cannot execute book_appointment';
  END IF;
END $$;

-- =============================================================================
-- TEST 12: Clinic settings scoped to clinic
-- =============================================================================

DO $$
DECLARE
  clinic_a uuid;
  clinic_b uuid;
  staff_a uuid;
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Clinic A') RETURNING id INTO clinic_a;
  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Clinic B') RETURNING id INTO clinic_b;

  staff_a := public.create_test_user('staffscope@example.com', 'user');
  INSERT INTO public.clinic_memberships (clinic_id, member_id, role)
  VALUES (clinic_a, staff_a, 'staff');

  INSERT INTO public.clinic_settings (key, value, description, clinic_id)
  VALUES ('secret_setting', 'should_be_hidden', 'Test setting', clinic_b);

  PERFORM public.set_jwt_claims(staff_a, 'user', 'staffscope@example.com');

  IF EXISTS (SELECT 1 FROM public.clinic_settings WHERE clinic_id = clinic_b) THEN
    RAISE EXCEPTION 'FAIL: Cross-clinic settings access NOT blocked';
  ELSE
    RAISE NOTICE 'PASS: Cross-clinic settings access blocked';
  END IF;
END $$;

-- =============================================================================
-- TEST 13: Ownership reassignment prevention (full)
-- =============================================================================

DO $$
DECLARE
  owner_id uuid;
  attacker_id uuid;
  patient_id uuid;
  clinic_id uuid;
BEGIN
  owner_id := public.create_test_user('owner2@example.com', 'user');
  attacker_id := public.create_test_user('attacker2@example.com', 'user');

  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO clinic_id;

  INSERT INTO public.patients (id, clinic_id, patient_owner_id, full_name, phone)
  VALUES (gen_random_uuid(), clinic_id, owner_id, 'Ownership Test Patient', '6666666666')
  RETURNING id INTO patient_id;

  PERFORM public.set_jwt_claims(owner_id, 'user', 'owner2@example.com');

  BEGIN
    UPDATE public.patients SET clinic_id = clinic_id, patient_owner_id = attacker_id WHERE id = patient_id;
    RAISE EXCEPTION 'FAIL: Ownership reassignment was NOT blocked';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'PASS: Ownership reassignment blocked by WITH CHECK';
  END;
END $$;

-- =============================================================================
-- TEST 14: Patient cannot access another patient's appointments
-- =============================================================================

DO $$
DECLARE
  patient_a uuid;
  patient_b uuid;
  clinic_id uuid;
  appointment_id uuid;
BEGIN
  INSERT INTO public.clinics (id, name) VALUES (gen_random_uuid(), 'Test Clinic')
  RETURNING id INTO clinic_id;

  patient_a := public.create_test_user('patienta@example.com', 'user');
  patient_b := public.create_test_user('patientb@example.com', 'user');

  INSERT INTO public.patients (id, clinic_id, patient_owner_id, full_name, phone)
  VALUES (gen_random_uuid(), clinic_id, patient_a, 'Patient A', '7777777777')
  RETURNING id INTO patient_a;

  INSERT INTO public.patients (id, clinic_id, patient_owner_id, full_name, phone)
  VALUES (gen_random_uuid(), clinic_id, patient_b, 'Patient B', '8888888888')
  RETURNING id INTO patient_b;

  INSERT INTO public.appointments (id, patient_id, starts_at, ends_at, status)
  VALUES (gen_random_uuid(), patient_b, now() + interval '1 day', now() + interval '1 day 30 min', 'scheduled')
  RETURNING id INTO appointment_id;

  PERFORM public.set_jwt_claims(patient_a, 'user', 'patienta@example.com');

  IF EXISTS (SELECT 1 FROM public.appointments WHERE id = appointment_id) THEN
    RAISE EXCEPTION 'FAIL: Patient A can see Patient B appointments';
  ELSE
    RAISE NOTICE 'PASS: Patient A cannot see Patient B appointments';
  END IF;
END $$;

-- =============================================================================
-- TEST 15: Table privileges are correctly revoked
-- =============================================================================

DO $$
DECLARE
  v_has_priv boolean;
BEGIN
  SELECT has_table_privilege('anon', 'public.patients', 'TRUNCATE') INTO v_has_priv;
  IF v_has_priv THEN
    RAISE EXCEPTION 'FAIL: Anon has TRUNCATE on patients';
  ELSE
    RAISE NOTICE 'PASS: Anon does not have TRUNCATE on patients';
  END IF;

  SELECT has_table_privilege('authenticated', 'public.call_logs', 'REFERENCES') INTO v_has_priv;
  IF v_has_priv THEN
    RAISE EXCEPTION 'FAIL: Authenticated has REFERENCES on call_logs';
  ELSE
    RAISE NOTICE 'PASS: Authenticated does not have REFERENCES on call_logs';
  END IF;
END $$;

RAISE NOTICE '=== ALL 15 RLS SECURITY TESTS COMPLETE ===';
