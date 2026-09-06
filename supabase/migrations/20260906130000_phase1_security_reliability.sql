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
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role = ANY(required_roles)
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
  IF NEW.role IS DISTINCT FROM OLD.role AND auth.role() <> 'service_role' THEN
    RAISE EXCEPTION 'Profile roles can only be changed by a trusted administrator';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS prevent_profile_role_change ON public.profiles;
CREATE TRIGGER prevent_profile_role_change
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.prevent_profile_role_change();

DROP POLICY IF EXISTS "admin_select_all_profiles" ON public.profiles;
CREATE POLICY "admin_select_all_profiles" ON public.profiles FOR SELECT
  TO authenticated USING (public.has_role(ARRAY['ADMIN']));

-- Never accept a role from signup metadata.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, name, role)
  VALUES (NEW.id, NEW.email, COALESCE(NEW.raw_user_meta_data->>'name', ''), 'INVESTIGATOR');
  RETURN NEW;
END;
$$;

-- Replace role checks with the non-recursive helper.
DROP POLICY IF EXISTS "insert_cases" ON public.cases;
CREATE POLICY "insert_cases" ON public.cases FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']) AND created_by = auth.uid());
DROP POLICY IF EXISTS "update_cases" ON public.cases;
CREATE POLICY "update_cases" ON public.cases FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']))
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));
DROP POLICY IF EXISTS "delete_cases" ON public.cases;
CREATE POLICY "delete_cases" ON public.cases FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['ADMIN']));

DROP POLICY IF EXISTS "insert_evidence" ON public.evidence;
CREATE POLICY "insert_evidence" ON public.evidence FOR INSERT TO authenticated
  WITH CHECK (
    public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
    AND uploaded_by = auth.uid()
    AND storage_path ~ ('^' || case_id::text || '/' || id::text || '_')
  );
DROP POLICY IF EXISTS "update_evidence" ON public.evidence;
CREATE POLICY "update_evidence" ON public.evidence FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']))
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));
DROP POLICY IF EXISTS "delete_evidence" ON public.evidence;
CREATE POLICY "delete_evidence" ON public.evidence FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['ADMIN']));

DROP POLICY IF EXISTS "insert_events" ON public.events;
CREATE POLICY "insert_events" ON public.events FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));
DROP POLICY IF EXISTS "update_events" ON public.events;
CREATE POLICY "update_events" ON public.events FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']))
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));
DROP POLICY IF EXISTS "delete_events" ON public.events;
CREATE POLICY "delete_events" ON public.events FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['ADMIN']));

DROP POLICY IF EXISTS "insert_alerts" ON public.alerts;
CREATE POLICY "insert_alerts" ON public.alerts FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));
DROP POLICY IF EXISTS "update_alerts" ON public.alerts;
CREATE POLICY "update_alerts" ON public.alerts FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']))
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));
DROP POLICY IF EXISTS "delete_alerts" ON public.alerts;
CREATE POLICY "delete_alerts" ON public.alerts FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['ADMIN']));

DROP POLICY IF EXISTS "insert_indicators" ON public.indicators;
CREATE POLICY "insert_indicators" ON public.indicators FOR INSERT TO authenticated
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));
DROP POLICY IF EXISTS "update_indicators" ON public.indicators;
CREATE POLICY "update_indicators" ON public.indicators FOR UPDATE TO authenticated
  USING (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']))
  WITH CHECK (public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));
DROP POLICY IF EXISTS "delete_indicators" ON public.indicators;
CREATE POLICY "delete_indicators" ON public.indicators FOR DELETE TO authenticated
  USING (public.has_role(ARRAY['ADMIN']));

-- Analysis state and server-verified integrity metadata.
ALTER TABLE public.evidence
  ADD COLUMN IF NOT EXISTS analysis_status text NOT NULL DEFAULT 'PENDING'
    CHECK (analysis_status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
  ADD COLUMN IF NOT EXISTS analysis_error text,
  ADD COLUMN IF NOT EXISTS analysis_started_at timestamptz,
  ADD COLUMN IF NOT EXISTS analysis_completed_at timestamptz,
  ADD COLUMN IF NOT EXISTS verified_sha256_hash text;

-- Fingerprints are supplied by the server-side analyzer. They identify the
-- parsed occurrence, rather than treating matching forensic field values as
-- duplicates.
ALTER TABLE public.events
  ADD COLUMN IF NOT EXISTS analysis_fingerprint text;
ALTER TABLE public.alerts
  ADD COLUMN IF NOT EXISTS analysis_fingerprint text;

UPDATE public.evidence
SET analysis_status = CASE WHEN parsed THEN 'COMPLETED' ELSE 'PENDING' END
WHERE analysis_status = 'PENDING';

-- Preserve duplicate historical events. Only server-generated fingerprints
-- participate in idempotency, so legitimate same-valued forensic events remain
-- separate while repeated analysis of the same occurrence is rejected.
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_evidence_analysis_fingerprint
  ON public.events (evidence_id, analysis_fingerprint)
  WHERE evidence_id IS NOT NULL AND analysis_fingerprint IS NOT NULL;

-- Preserve duplicate historical alerts. NULL fingerprints and legacy rows are
-- untouched; new analyzer output is deduplicated by its deterministic key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_case_analysis_fingerprint
  ON public.alerts (case_id, analysis_fingerprint)
  WHERE analysis_fingerprint IS NOT NULL;

-- Atomic, database-generated case numbers; callers must omit case_number.
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
    0
  ),
  true
);
ALTER TABLE public.cases ALTER COLUMN case_number SET DEFAULT
  ('CASE-' || to_char(current_date, 'YYYY') || '-' || lpad(nextval('public.case_number_seq')::text, 6, '0'));

-- Storage access is tied to an evidence row and the case's authorization.
INSERT INTO storage.buckets (id, name, public)
VALUES ('evidence', 'evidence', false)
ON CONFLICT (id) DO UPDATE SET public = false;

DROP POLICY IF EXISTS "evidence_bucket_read" ON storage.objects;
CREATE POLICY "evidence_bucket_read" ON storage.objects FOR SELECT TO authenticated
  USING (
    bucket_id = 'evidence'
    AND EXISTS (
      SELECT 1 FROM public.evidence e
      WHERE e.storage_path = name
        AND public.has_role(ARRAY['ADMIN', 'INVESTIGATOR', 'VIEWER'])
    )
  );

DROP POLICY IF EXISTS "evidence_bucket_upload" ON storage.objects;
CREATE POLICY "evidence_bucket_upload" ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'evidence'
    AND public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
    AND EXISTS (
      SELECT 1
      FROM public.evidence e
      WHERE e.storage_path = name
        AND e.uploaded_by = auth.uid()
    )
  );

DROP POLICY IF EXISTS "evidence_bucket_update" ON storage.objects;
CREATE POLICY "evidence_bucket_update" ON storage.objects FOR UPDATE TO authenticated
  USING (bucket_id = 'evidence' AND public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']))
  WITH CHECK (bucket_id = 'evidence' AND public.has_role(ARRAY['ADMIN', 'INVESTIGATOR']));

DROP POLICY IF EXISTS "evidence_bucket_delete" ON storage.objects;
CREATE POLICY "evidence_bucket_delete" ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'evidence' AND public.has_role(ARRAY['ADMIN']));

-- Investigators may update analysis results through the trusted analyzer, but
-- cannot rewrite chain-of-custody or integrity ownership fields. Admins and
-- service-role operations retain broader management access.
CREATE OR REPLACE FUNCTION public.prevent_evidence_integrity_field_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF auth.role() <> 'service_role' AND NOT public.has_role(ARRAY['ADMIN']) AND (
    NEW.case_id IS DISTINCT FROM OLD.case_id OR
    NEW.uploaded_by IS DISTINCT FROM OLD.uploaded_by OR
    NEW.storage_path IS DISTINCT FROM OLD.storage_path OR
    NEW.sha256_hash IS DISTINCT FROM OLD.sha256_hash OR
    NEW.verified_sha256_hash IS DISTINCT FROM OLD.verified_sha256_hash OR
    NEW.analysis_status IS DISTINCT FROM OLD.analysis_status OR
    NEW.analysis_started_at IS DISTINCT FROM OLD.analysis_started_at OR
    NEW.analysis_completed_at IS DISTINCT FROM OLD.analysis_completed_at
  ) THEN
    RAISE EXCEPTION 'Investigators cannot modify evidence integrity or ownership fields';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS prevent_evidence_integrity_field_change ON public.evidence;
CREATE TRIGGER prevent_evidence_integrity_field_change
  BEFORE UPDATE ON public.evidence
  FOR EACH ROW EXECUTE FUNCTION public.prevent_evidence_integrity_field_change();

DROP POLICY IF EXISTS "insert_audit_logs" ON public.audit_logs;
CREATE POLICY "insert_audit_logs" ON public.audit_logs FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid());
