-- Secure the evidence upload predicate without weakening Storage RLS.
-- The SECURITY DEFINER helper avoids evaluating public.cases through the
-- caller's table policies and rejects malformed UUID path segments safely.

CREATE OR REPLACE FUNCTION public.can_upload_evidence_object(object_name text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  object_case_id uuid;
BEGIN
  IF auth.uid() IS NULL
     OR NOT public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
     OR object_name IS NULL
     OR object_name !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89ab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}/'
  THEN
    RETURN false;
  END IF;

  BEGIN
    object_case_id := split_part(object_name, '/', 1)::uuid;
  EXCEPTION
    WHEN invalid_text_representation THEN
      RETURN false;
  END;

  RETURN EXISTS (
    SELECT 1
    FROM public.cases c
    WHERE c.id = object_case_id
      AND (
        c.created_by = auth.uid()
        OR public.has_role(ARRAY['ADMIN', 'INVESTIGATOR'])
      )
  );
END;
$$;

REVOKE ALL ON FUNCTION public.can_upload_evidence_object(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.can_upload_evidence_object(text) TO authenticated;

DROP POLICY IF EXISTS "evidence_bucket_upload" ON storage.objects;

CREATE POLICY "evidence_bucket_upload"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'evidence'
  AND public.can_upload_evidence_object(name)
);
