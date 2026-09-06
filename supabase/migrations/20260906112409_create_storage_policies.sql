/*
# Create Storage Policies for Evidence Bucket

## Overview
Creates RLS policies on the storage.objects table to control access to
the 'evidence' storage bucket. Only authenticated admins and investigators
can upload, read, and delete evidence files. Viewers can read but not upload.

## Security
- SELECT: all authenticated users can read evidence files
- INSERT: only admins and investigators can upload
- UPDATE: only admins and investigators can modify
- DELETE: only admins can delete evidence files
*/

-- Allow authenticated users to read evidence files
DROP POLICY IF EXISTS "evidence_bucket_read" ON storage.objects;
CREATE POLICY "evidence_bucket_read" ON storage.objects FOR SELECT
  TO authenticated
  USING (bucket_id = 'evidence');

-- Allow admins and investigators to upload evidence files
DROP POLICY IF EXISTS "evidence_bucket_upload" ON storage.objects;
CREATE POLICY "evidence_bucket_upload" ON storage.objects FOR INSERT
  TO authenticated
  WITH CHECK (
    bucket_id = 'evidence'
    AND EXISTS (
      SELECT 1 FROM public.profiles p
      WHERE p.id = auth.uid()
      AND p.role IN ('ADMIN', 'INVESTIGATOR')
    )
  );

-- Allow admins and investigators to update evidence files
DROP POLICY IF EXISTS "evidence_bucket_update" ON storage.objects;
CREATE POLICY "evidence_bucket_update" ON storage.objects FOR UPDATE
  TO authenticated
  USING (
    bucket_id = 'evidence'
    AND EXISTS (
      SELECT 1 FROM public.profiles p
      WHERE p.id = auth.uid()
      AND p.role IN ('ADMIN', 'INVESTIGATOR')
    )
  )
  WITH CHECK (
    bucket_id = 'evidence'
    AND EXISTS (
      SELECT 1 FROM public.profiles p
      WHERE p.id = auth.uid()
      AND p.role IN ('ADMIN', 'INVESTIGATOR')
    )
  );

-- Allow only admins to delete evidence files
DROP POLICY IF EXISTS "evidence_bucket_delete" ON storage.objects;
CREATE POLICY "evidence_bucket_delete" ON storage.objects FOR DELETE
  TO authenticated
  USING (
    bucket_id = 'evidence'
    AND EXISTS (
      SELECT 1 FROM public.profiles p
      WHERE p.id = auth.uid()
      AND p.role = 'ADMIN'
    )
  );
