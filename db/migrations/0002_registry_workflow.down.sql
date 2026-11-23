-- Rollback of 0002 (development only: it drops the proposed definitions and the override requester).
DELETE FROM approvals WHERE subject_type = 'tool';
ALTER TABLE overrides DROP CONSTRAINT overrides_requested_by_fk, DROP COLUMN requested_by;
DROP INDEX findings_by_tool;
ALTER TABLE findings DROP CONSTRAINT findings_tool_fk, DROP COLUMN tool_id;
DROP INDEX approvals_by_subject;
ALTER TABLE approvals DROP CONSTRAINT approvals_tool_has_definition;
ALTER TABLE approvals DROP COLUMN proposed_definition, DROP COLUMN proposed_sha256, DROP COLUMN decided_action_class,
  DROP COLUMN decision_key, DROP COLUMN decision_reason;
ALTER TABLE approvals DROP CONSTRAINT approvals_subject_type_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_subject_type_check
  CHECK (subject_type IN ('tool_version', 'agent', 'grant', 'call'));
CREATE OR REPLACE FUNCTION override_approver_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM overrides o JOIN approvals a ON a.tenant_id = o.tenant_id AND a.id = o.approval_id
             WHERE o.tenant_id = NEW.tenant_id AND o.id = NEW.override_id AND a.requested_by = NEW.approver_user_id) THEN
    RAISE EXCEPTION 'override approver must differ from the requester (SoD-2)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
