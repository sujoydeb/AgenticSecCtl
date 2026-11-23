-- WP-1.6: what the registry workflow needs that the baseline did not have (expand-only, nothing dropped).
--  * a pending tool definition must live somewhere before it is approved (tool_versions is immutable and
--    only holds approved versions), so an approval of subject 'tool' carries the proposed canonical JSON
--    and its hash;
--  * findings about a tool that has no version yet need a link to the tool;
--  * overrides record who asked, so the requester cannot also be one of the two approvers (SoD-2);
--  * decisions are idempotent per key (API specification, Section 1).

ALTER TABLE approvals DROP CONSTRAINT approvals_subject_type_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_subject_type_check
  CHECK (subject_type IN ('tool_version', 'tool', 'agent', 'grant', 'call'));
ALTER TABLE approvals
  ADD COLUMN proposed_definition jsonb,
  ADD COLUMN proposed_sha256 bytea CHECK (proposed_sha256 IS NULL OR octet_length(proposed_sha256) = 32),
  ADD COLUMN decided_action_class text CHECK (decided_action_class IN ('read', 'write', 'execute', 'delete')),
  ADD COLUMN decision_key text,
  ADD COLUMN decision_reason text;
ALTER TABLE approvals ADD CONSTRAINT approvals_tool_has_definition
  CHECK (subject_type <> 'tool' OR (proposed_definition IS NOT NULL AND proposed_sha256 IS NOT NULL));
CREATE INDEX approvals_by_subject ON approvals (tenant_id, subject_type, subject_id);

ALTER TABLE findings ADD COLUMN tool_id uuid;
ALTER TABLE findings ADD CONSTRAINT findings_tool_fk
  FOREIGN KEY (tenant_id, tool_id) REFERENCES tools (tenant_id, id);
CREATE INDEX findings_by_tool ON findings (tenant_id, tool_id, severity, status);

ALTER TABLE overrides ADD COLUMN requested_by uuid;
ALTER TABLE overrides ADD CONSTRAINT overrides_requested_by_fk
  FOREIGN KEY (tenant_id, requested_by) REFERENCES users (tenant_id, id);

CREATE OR REPLACE FUNCTION override_approver_check() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM overrides o JOIN approvals a ON a.tenant_id = o.tenant_id AND a.id = o.approval_id
             WHERE o.tenant_id = NEW.tenant_id AND o.id = NEW.override_id
               AND (a.requested_by = NEW.approver_user_id OR o.requested_by = NEW.approver_user_id)) THEN
    RAISE EXCEPTION 'override approver must differ from the requesters (SoD-2)' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$;
