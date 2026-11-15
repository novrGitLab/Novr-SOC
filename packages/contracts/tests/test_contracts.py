"""Cross-cutting contract rules. Run: apps/api/.venv/Scripts/python -m pytest packages/contracts/tests"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import BaseModel, ValidationError

from novrsoc_contracts import v1
from novrsoc_contracts.v1 import collector, common, governance, soar, vms
from novrsoc_contracts.v1.common import Direction

NOW = datetime.now(timezone.utc)
ORG_FIELD_NAMES = {"org_id", "organization_id", "organisation_id", "tenant_id", "org", "org_slug", "tenant"}
ABSTRACT = {common.Contract, common.MachineInbound, common.MachineOutbound, common.Internal, common.Page}


def all_models():
    for mod in v1.MODULES.values():
        for v in vars(mod).values():
            if isinstance(v, type) and issubclass(v, BaseModel) and v.__module__ == mod.__name__ and v not in ABSTRACT:
                yield v


def _fields_deep(model, seen=None):
    seen = seen or set()
    if model in seen:
        return set()
    seen.add(model)
    names = set(model.model_fields)
    for f in model.model_fields.values():
        for t in getattr(f.annotation, "__args__", ()) + (f.annotation,):
            if isinstance(t, type) and issubclass(t, BaseModel):
                names |= _fields_deep(t, seen)
    return names


def test_every_contract_forbids_unknown_fields():
    for m in all_models():
        assert m.model_config.get("extra") == "forbid", m.__name__


def test_machine_inbound_contracts_never_carry_an_organisation():
    inbound = [m for m in all_models() if m.direction == Direction.MACHINE_INBOUND]
    assert len(inbound) >= 7
    for m in inbound:
        assert not (_fields_deep(m) & ORG_FIELD_NAMES), f"{m.__name__} must not accept an organisation"


def test_org_in_a_collector_payload_is_rejected_not_ignored():
    with pytest.raises(ValidationError):
        collector.CollectorHeartbeat(sent_at=NOW, collector_version="1.0.0", config_version=1, health="ok",
                                     queue_depth=0, org_id=str(uuid.uuid4()))


def test_state_changing_machine_and_soar_requests_need_idempotency_keys():
    for m in (collector.TelemetryBatch, collector.DiscoveryReport, collector.CredentialRotationRequest,
              vms.ScanResultBatch, vms.ScanJobRequest, soar.PlaybookExecutionRequest, soar.ApprovalRequest,
              governance.ReportRequest, governance.RestoreDrillRequest):
        key = next(n for n in m.model_fields if n in ("idempotency_key", "batch_id", "report_id", "request_id"))
        assert m.model_fields[key].is_required(), m.__name__


def test_site_scoped_addresses_distinguish_overlapping_private_ips():
    a = common.SiteScopedAddress(site_id=uuid.uuid4(), ip="10.0.0.5")
    b = common.SiteScopedAddress(site_id=uuid.uuid4(), ip="10.0.0.5")
    assert a.is_private and a != b
    with pytest.raises(ValidationError):
        common.SiteScopedAddress(site_id=uuid.uuid4(), ip="10.0.0.999")


def test_scan_assignment_is_single_site_and_windowed():
    site = uuid.uuid4()
    t = [common.SiteScopedAddress(site_id=site, ip="192.168.0.1")]
    ok = dict(assignment_id=uuid.uuid4(), scan_job_id=uuid.uuid4(), targets=t, window_start=NOW,
              window_end=NOW + timedelta(hours=1), scope_approval_id=uuid.uuid4())
    collector.ScanConnectivityAssignment(**ok)
    with pytest.raises(ValidationError):
        collector.ScanConnectivityAssignment(**{**ok, "window_end": NOW - timedelta(hours=1)})
    with pytest.raises(ValidationError):
        collector.ScanConnectivityAssignment(**{**ok, "targets": t + [common.SiteScopedAddress(site_id=uuid.uuid4(), ip="192.168.0.1")]})


def test_self_approval_and_non_human_approval_are_refused():
    u = uuid.uuid4()
    base = dict(approval_id=uuid.uuid4(), decision="approve", reason="looks right",
                requested_by=common.ActorRef(type="user", id=u))
    with pytest.raises(ValidationError, match="self-approval"):
        soar.ApprovalDecision(**base, decided_by=common.ActorRef(type="user", id=u))
    with pytest.raises(ValidationError, match="human"):
        soar.ApprovalDecision(**base, decided_by=common.ActorRef(type="service", id=uuid.uuid4()))
    soar.ApprovalDecision(**base, decided_by=common.ActorRef(type="user", id=uuid.uuid4()))


def test_only_consequential_actions_are_approval_gated_and_default_mode_is_dry_run():
    assert {a.value for a in soar.ActionType if a.consequential} == {"block_ip", "isolate_agent", "disable_account"}
    with pytest.raises(ValidationError):
        soar.ApprovalRequest(idempotency_key="k" * 20, run_id=uuid.uuid4(), step_key="notify", action="notify_email",
                             target="soc", justification="this is long enough", requested_by=common.ActorRef(type="user"))
    req = soar.PlaybookExecutionRequest(idempotency_key="run-0000000000000001", playbook_id=uuid.uuid4(),
                                        playbook_version=1, case_id=uuid.uuid4())
    assert req.mode == soar.ExecutionMode.DRY_RUN


def test_dry_run_never_reports_success_and_retry_needs_a_time():
    base = dict(run_id=uuid.uuid4(), step_key="block", attempt=1, mode="dry_run", message="m",
                finished_at=NOW, ownership_rechecked=True)
    with pytest.raises(ValidationError):
        soar.ExecutionOutcome(**base, status="succeeded")
    soar.ExecutionOutcome(**base, status="dry_run")
    with pytest.raises(ValidationError):
        soar.ExecutionOutcome(**{**base, "mode": "live"}, status="failed", retryable=True)


def test_run_state_machine_terminal_states_are_final():
    for s in (soar.RunState.SUCCEEDED, soar.RunState.FAILED, soar.RunState.CANCELLED):
        assert soar.ALLOWED_TRANSITIONS[s] == frozenset()


def test_findings_are_verified_only_by_evidence():
    with pytest.raises(ValidationError):
        vms.FindingTransition(finding_id=uuid.uuid4(), to_status="verified", reason="I fixed it")
    assert vms.MANUAL_TRANSITIONS[vms.FindingStatus.FIXED_PENDING_VERIFICATION] == frozenset()


def test_sca_score_must_match_counts():
    base = dict(asset_id=uuid.uuid4(), agent_id="003", policy_id="cis_ubuntu22", policy_name="CIS Ubuntu 22.04",
                scanned_at=NOW, passed=75, failed=25, not_applicable=3)
    vms.ScaPolicyResult(**base, score_percent=75)
    with pytest.raises(ValidationError):
        vms.ScaPolicyResult(**base, score_percent=90)


def test_cnii_designation_always_expires_after_grant_and_names_real_sectors():
    with pytest.raises(ValidationError):
        governance.CniiDesignation(id=uuid.uuid4(), user_id=uuid.uuid4(), sectors=["power"], scope_org_ids=None,
                                   granted_by=uuid.uuid4(), granted_at=NOW, expires_at=NOW - timedelta(days=1))
    with pytest.raises(ValidationError):
        governance.CniiDesignationGrant(user_id=uuid.uuid4(), sectors=["oil_and_gas"], reason="x" * 5, expires_at=NOW)


def test_restore_never_targets_live_data():
    with pytest.raises(ValidationError):
        governance.RestoreDrillRequest(idempotency_key="r" * 20, backup_job_id=uuid.uuid4(), target="production")


def test_api_contract_version_is_semver():
    import re
    assert re.match(r"^\d+\.\d+\.\d+$", v1.CONTRACT_VERSION)
