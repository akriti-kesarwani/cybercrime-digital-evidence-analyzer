-- Phase 1 security and reliability hardening.

-- Role checks must bypass profiles RLS without recursively querying profiles policies.

CREATE OR REPLACE FUNCTION public.has_role(required_roles text[])
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.profiles
    WHERE id = auth.uid()
      AND role = ANY(required_roles)
  );
$$;

REVOKE ALL ON FUNCTION public.has_role(text[]) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.has_role(text[]) TO authenticated;

-- A profile owner may edit identity fields, but never their authorization role.

CREATE OR REPLACE FUNCTION public.prevent_profile_role_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NEW.role IS DISTINCT FROM OLD.role
     AND auth.role() <> 'service_role' THEN
    RAISE EXCEPTION 'Profile roles can only be changed by a trusted administrator';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS prevent_profile_role_change ON public.profiles;

CREATE TRIGGER prevent_profile_role_change
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_profile_role_change();

DROP POLICY IF EXISTS "admin_select_all_profiles" ON public.profiles;

CREATE POLICY "admin_select_all_profiles"
ON public.profiles
FOR SELECT
TO authenticated
USING (public.has_role(ARRAY['ADMIN']));

-- Never accept a role from signup metadata.

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, name, role)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'name', ''),
    'INVESTIGATOR'
  );

  RETURN NEW;
END;
$$;

-- Replace role checks with the non-recursive helper.

DROP POLICY IF EXISTS "insert_cases" ON public.cases;

CREATE POLICY "insert_cases"
ON public.cases
FOR INSERT
TO authenticated
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
  AND created_by = auth.uid()
);

DROP POLICY IF EXISTS "update_cases" ON public.cases;

CREATE POLICY "update_cases"
ON public.cases
FOR UPDATE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
)
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "delete_cases" ON public.cases;

CREATE POLICY "delete_cases"
ON public.cases
FOR DELETE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN'])
);

DROP POLICY IF EXISTS "insert_evidence" ON public.evidence;

CREATE POLICY "insert_evidence"
ON public.evidence
FOR INSERT
TO authenticated
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
  AND uploaded_by = auth.uid()
);

DROP POLICY IF EXISTS "update_evidence" ON public.evidence;

CREATE POLICY "update_evidence"
ON public.evidence
FOR UPDATE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
)
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "delete_evidence" ON public.evidence;

CREATE POLICY "delete_evidence"
ON public.evidence
FOR DELETE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN'])
);

DROP POLICY IF EXISTS "insert_events" ON public.events;

CREATE POLICY "insert_events"
ON public.events
FOR INSERT
TO authenticated
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "update_events" ON public.events;

CREATE POLICY "update_events"
ON public.events
FOR UPDATE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
)
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "delete_events" ON public.events;

CREATE POLICY "delete_events"
ON public.events
FOR DELETE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN'])
);

DROP POLICY IF EXISTS "insert_alerts" ON public.alerts;

CREATE POLICY "insert_alerts"
ON public.alerts
FOR INSERT
TO authenticated
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "update_alerts" ON public.alerts;

CREATE POLICY "update_alerts"
ON public.alerts
FOR UPDATE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
)
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "delete_alerts" ON public.alerts;

CREATE POLICY "delete_alerts"
ON public.alerts
FOR DELETE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN'])
);

DROP POLICY IF EXISTS "insert_indicators" ON public.indicators;

CREATE POLICY "insert_indicators"
ON public.indicators
FOR INSERT
TO authenticated
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "update_indicators" ON public.indicators;

CREATE POLICY "update_indicators"
ON public.indicators
FOR UPDATE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
)
WITH CHECK (
  public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "delete_indicators" ON public.indicators;

CREATE POLICY "delete_indicators"
ON public.indicators
FOR DELETE
TO authenticated
USING (
  public.has_role(ARRAY['ADMIN'])
);

-- Analysis state and server-verified integrity metadata.

ALTER TABLE public.evidence
  ADD COLUMN IF NOT EXISTS analysis_status text NOT NULL DEFAULT 'PENDING'
    CHECK (
      analysis_status IN (
        'PENDING',
        'PROCESSING',
        'COMPLETED',
        'FAILED'
      )
    ),
  ADD COLUMN IF NOT EXISTS analysis_error text,
  ADD COLUMN IF NOT EXISTS analysis_started_at timestamptz,
  ADD COLUMN IF NOT EXISTS analysis_completed_at timestamptz,
  ADD COLUMN IF NOT EXISTS verified_sha256_hash text;

UPDATE public.evidence
SET analysis_status =
  CASE
    WHEN parsed THEN 'COMPLETED'
    ELSE 'PENDING'
  END
WHERE analysis_status = 'PENDING';

-- Preserve duplicate historical events.
-- This lookup index is safe on dirty data;
-- the trigger below prevents new duplicate analysis events.

CREATE INDEX IF NOT EXISTS idx_events_evidence_fingerprint
ON public.events (
  evidence_id,
  timestamp,
  event_type,
  (COALESCE(username, '')),
  (COALESCE(source_ip::text, '')),
  (COALESCE(description, ''))
)
WHERE evidence_id IS NOT NULL;

-- Preserve duplicate historical alerts while preventing new duplicates.

CREATE INDEX IF NOT EXISTS idx_alerts_evidence_rule
ON public.alerts (
  case_id,
  detection_rule,
  related_event_ids
);

CREATE OR REPLACE FUNCTION public.prevent_duplicate_evidence_event()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NEW.evidence_id IS NOT NULL
     AND EXISTS (
       SELECT 1
       FROM public.events e
       WHERE e.evidence_id = NEW.evidence_id
         AND e.timestamp = NEW.timestamp
         AND e.event_type = NEW.event_type
         AND COALESCE(e.username, '') = COALESCE(NEW.username, '')
         AND COALESCE(e.source_ip::text, '') = COALESCE(NEW.source_ip::text, '')
         AND COALESCE(e.description, '') = COALESCE(NEW.description, '')
     )
  THEN
    RAISE EXCEPTION 'Duplicate event for evidence %', NEW.evidence_id
      USING ERRCODE = '23505';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS prevent_duplicate_evidence_event ON public.events;

CREATE TRIGGER prevent_duplicate_evidence_event
  BEFORE INSERT ON public.events
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_duplicate_evidence_event();

CREATE OR REPLACE FUNCTION public.prevent_duplicate_evidence_alert()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.alerts a
    WHERE a.case_id = NEW.case_id
      AND a.detection_rule = NEW.detection_rule
      AND a.related_event_ids = NEW.related_event_ids
  )
  THEN
    RAISE EXCEPTION 'Duplicate alert for case % and rule %',
      NEW.case_id,
      NEW.detection_rule
      USING ERRCODE = '23505';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS prevent_duplicate_evidence_alert ON public.alerts;

CREATE TRIGGER prevent_duplicate_evidence_alert
  BEFORE INSERT ON public.alerts
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_duplicate_evidence_alert();

-- Atomic, database-generated case numbers;
-- callers must omit case_number.

CREATE SEQUENCE IF NOT EXISTS public.case_number_seq;

SELECT setval(
  'public.case_number_seq',
  GREATEST(
    COALESCE(
      (
        SELECT max(
          CASE
            WHEN case_number ~ '[0-9]{1,18}$'
            THEN substring(case_number from '[0-9]{1,18}$')::bigint
            ELSE 0
          END
        )
        FROM public.cases
      ),
      0
    ),
    1
  ),
  true
);

ALTER TABLE public.cases
ALTER COLUMN case_number SET DEFAULT
  (
    'CASE-' ||
    to_char(current_date, 'YYYY') ||
    '-' ||
    lpad(nextval('public.case_number_seq')::text, 6, '0')
  );

-- Storage access is tied to an evidence row and the case's authorization.

INSERT INTO storage.buckets (id, name, public)
VALUES ('evidence', 'evidence', false)
ON CONFLICT (id)
DO UPDATE SET public = false;

DROP POLICY IF EXISTS "evidence_bucket_read" ON storage.objects;

CREATE POLICY "evidence_bucket_read"
ON storage.objects
FOR SELECT
TO authenticated
USING (
  bucket_id = 'evidence'
  AND EXISTS (
    SELECT 1
    FROM public.evidence e
    WHERE e.storage_path = name
      AND public.has_role(
        ARRAY['ADMIN', 'INVESTIGATOR', 'VIEWER']
      )
  )
);

DROP POLICY IF EXISTS "evidence_bucket_upload" ON storage.objects;

CREATE POLICY "evidence_bucket_upload"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'evidence'
  AND public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
  AND name ~ '^[0-9a-fA-F-]{36}/'
  AND EXISTS (
    SELECT 1
    FROM public.cases c
    WHERE c.id::text = split_part(name, '/', 1)
  )
);

DROP POLICY IF EXISTS "evidence_bucket_update" ON storage.objects;

CREATE POLICY "evidence_bucket_update"
ON storage.objects
FOR UPDATE
TO authenticated
USING (
  bucket_id = 'evidence'
  AND public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
)
WITH CHECK (
  bucket_id = 'evidence'
  AND public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
);

DROP POLICY IF EXISTS "evidence_bucket_delete" ON storage.objects;

CREATE POLICY "evidence_bucket_delete"
ON storage.objects
FOR DELETE
TO authenticated
USING (
  bucket_id = 'evidence'
  AND public.has_role(ARRAY['ADMIN'])
);

DROP POLICY IF EXISTS "insert_audit_logs" ON public.audit_logs;

CREATE POLICY "insert_audit_logs"
ON public.audit_logs
FOR INSERT
TO authenticated
WITH CHECK (
  user_id = auth.uid()
);