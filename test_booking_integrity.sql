-- Phase 2.6N.8: Booking integrity tests
-- Tests all booking constraints using disposable test data
-- All test records are cleaned up at the end

-- Create test patient
INSERT INTO public.patients (full_name, phone) VALUES ('Integrity Test User', '+919999999999');
SELECT 'TEST PATIENT CREATED' AS status;

-- Test 1: Successful booking during clinic hours (11:00-11:30)
SELECT 'TEST 1: Success during clinic hours' AS test;
SELECT public.book_appointment(
  (SELECT id FROM public.patients WHERE full_name = 'Integrity Test User' LIMIT 1),
  '2026-11-20 11:00:00+05:30',
  '2026-11-20 11:30:00+05:30',
  'Test - success',
  NULL
);

-- Test 2: Adjacent appointment (11:30-12:00, immediately after)
SELECT 'TEST 2: Adjacent appointment' AS test;
SELECT public.book_appointment(
  (SELECT id FROM public.patients WHERE full_name = 'Integrity Test User' LIMIT 1),
  '2026-11-20 11:30:00+05:30',
  '2026-11-20 12:00:00+05:30',
  'Test - adjacent',
  NULL
);

-- Test 3: Overlapping appointment (11:15-11:45 - should fail)
SELECT 'TEST 3: Overlapping appointment (expect error)' AS test;
SELECT public.book_appointment(
  (SELECT id FROM public.patients WHERE full_name = 'Integrity Test User' LIMIT 1),
  '2026-11-20 11:15:00+05:30',
  '2026-11-20 11:45:00+05:30',
  'Test - should fail overlap',
  NULL
);

-- Test 4: Before clinic hours (09:00-09:30 - should fail)
SELECT 'TEST 4: Before clinic hours (expect error)' AS test;
SELECT public.book_appointment(
  (SELECT id FROM public.patients WHERE full_name = 'Integrity Test User' LIMIT 1),
  '2026-11-20 09:00:00+05:30',
  '2026-11-20 09:30:00+05:30',
  'Test - should fail early',
  NULL
);

-- Test 5: Past appointment (should fail)
SELECT 'TEST 5: Past appointment (expect error)' AS test;
SELECT public.book_appointment(
  (SELECT id FROM public.patients WHERE full_name = 'Integrity Test User' LIMIT 1),
  '2020-01-01 14:00:00+05:30',
  '2020-01-01 14:30:00+05:30',
  'Test - should fail past',
  NULL
);

-- Test 6: Invalid patient ID (should fail)
SELECT 'TEST 6: Invalid patient (expect error)' AS test;
SELECT public.book_appointment(
  '00000000-0000-0000-0000-000000000000',
  '2026-11-20 14:00:00+05:30',
  '2026-11-20 14:30:00+05:30',
  'Test - should fail invalid patient',
  NULL
);

-- Cleanup test data only
DELETE FROM public.appointments WHERE reason LIKE 'Test - %';
DELETE FROM public.patients WHERE full_name = 'Integrity Test User';

SELECT 'ALL TESTS COMPLETE - CLEANUP DONE' AS status;
