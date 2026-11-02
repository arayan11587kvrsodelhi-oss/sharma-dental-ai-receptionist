-- Phase 2.6N.8: Authorization verification tests
-- Tests that anon/authenticated cannot EXECUTE book_appointment()
-- but service_role can.

DO $$
BEGIN
  IF has_function_privilege('anon', 'book_appointment(uuid, timestamptz, timestamptz, text, text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'SECURITY FAILURE: anon still has EXECUTE privilege';
  END IF;

  IF has_function_privilege('authenticated', 'book_appointment(uuid, timestamptz, timestamptz, text, text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'SECURITY FAILURE: authenticated still has EXECUTE privilege';
  END IF;

  IF NOT has_function_privilege('service_role', 'book_appointment(uuid, timestamptz, timestamptz, text, text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'SECURITY FAILURE: service_role lost EXECUTE privilege';
  END IF;

  RAISE NOTICE 'All privilege checks passed: anon=no, authenticated=no, service_role=yes';
END $$;
