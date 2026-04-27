from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AnalysisSnapshot, TrackedDomain
from app.db.session import SessionLocal
from app.schemas.analysis import AnalysisResponse
from app.schemas.history import (
    AnalysisDiffSummary,
    DomainHistoryResponse,
    HistoryItem,
    SnapshotChangeItem,
)
from app.utils.input_parser import normalize_target


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


class AnalysisHistoryService:
    """Persists snapshots and computes diffs between analyses."""

    def __init__(self, session_factory: Callable[[], Session] | None = None) -> None:
        self.session_factory = session_factory or SessionLocal

    def record_analysis(
        self, result: AnalysisResponse, *, input_target: str
    ) -> AnalysisResponse:
        with self.session_factory() as db:
            tracked_domain = self.get_or_create_tracked_domain(
                db, result.normalized.analysis_domain
            )
            previous_snapshot = self.get_latest_snapshot(db, tracked_domain.id)
            diff = self.compare_with_previous(result, previous_snapshot)
            final_result = result.model_copy(update={"changes": diff})
            self.save_snapshot(
                db,
                tracked_domain=tracked_domain,
                result=final_result,
                input_target=input_target,
            )
            db.commit()
        return final_result

    def list_history(self, domain: str, *, limit: int = 20) -> DomainHistoryResponse:
        normalized_domain = normalize_target(domain).analysis_domain
        with self.session_factory() as db:
            tracked_domain = self._get_tracked_domain(db, normalized_domain)
            if tracked_domain is None:
                return DomainHistoryResponse(domain=normalized_domain, items=[])

            stmt = (
                select(AnalysisSnapshot)
                .where(AnalysisSnapshot.tracked_domain_id == tracked_domain.id)
                .order_by(
                    AnalysisSnapshot.created_at.desc(), AnalysisSnapshot.id.desc()
                )
                .limit(limit)
            )
            items = [
                self._to_history_item(snapshot) for snapshot in db.scalars(stmt).all()
            ]
            return DomainHistoryResponse(domain=normalized_domain, items=items)

    def get_latest_snapshot_for_domain(self, domain: str) -> AnalysisSnapshot | None:
        normalized_domain = normalize_target(domain).analysis_domain
        with self.session_factory() as db:
            tracked_domain = self._get_tracked_domain(db, normalized_domain)
            if tracked_domain is None:
                return None
            return self.get_latest_snapshot(db, tracked_domain.id)

    def get_latest_result_for_domain(self, domain: str) -> AnalysisResponse | None:
        snapshot = self.get_latest_snapshot_for_domain(domain)
        if snapshot is None or not snapshot.snapshot_data:
            return None
        return AnalysisResponse.model_validate(snapshot.snapshot_data)

    def get_or_create_tracked_domain(
        self, db: Session, normalized_domain: str
    ) -> TrackedDomain:
        tracked_domain = self._get_tracked_domain(db, normalized_domain)
        current_time = utcnow()
        if tracked_domain is not None:
            tracked_domain.last_seen_at = current_time
            tracked_domain.updated_at = current_time
            db.flush()
            return tracked_domain

        tracked_domain = TrackedDomain(
            normalized_domain=normalized_domain,
            first_seen_at=current_time,
            last_seen_at=current_time,
            created_at=current_time,
            updated_at=current_time,
        )
        db.add(tracked_domain)
        db.flush()
        return tracked_domain

    def save_snapshot(
        self,
        db: Session,
        *,
        tracked_domain: TrackedDomain,
        result: AnalysisResponse,
        input_target: str,
    ) -> AnalysisSnapshot:
        tracked_domain.last_seen_at = utcnow()
        snapshot = AnalysisSnapshot(
            tracked_domain_id=tracked_domain.id,
            input_target=input_target,
            analysis_domain=result.normalized.analysis_domain,
            score=result.score,
            severity=result.severity,
            summary=result.summary,
            snapshot_data=result.model_dump(mode="json"),
            created_at=utcnow(),
        )
        db.add(snapshot)
        db.flush()
        return snapshot

    def get_latest_snapshot(
        self, db: Session, tracked_domain_id: int
    ) -> AnalysisSnapshot | None:
        stmt = (
            select(AnalysisSnapshot)
            .where(AnalysisSnapshot.tracked_domain_id == tracked_domain_id)
            .order_by(AnalysisSnapshot.created_at.desc(), AnalysisSnapshot.id.desc())
            .limit(1)
        )
        return db.scalar(stmt)

    def compare_with_previous(
        self,
        current_result: AnalysisResponse,
        previous_snapshot: AnalysisSnapshot | None,
    ) -> AnalysisDiffSummary:
        if previous_snapshot is None:
            return AnalysisDiffSummary(
                has_previous_snapshot=False,
                message="Esta e a primeira analise salva para este dominio.",
                current_score=current_result.score,
                current_severity=current_result.severity,
            )

        previous_data = previous_snapshot.snapshot_data or {}
        current_data = current_result.model_dump(mode="json")

        changed_checks = self._build_changed_checks(previous_data, current_data)
        added_findings, removed_findings = self._diff_findings(
            previous_data, current_data
        )
        previous_score = self._coerce_int(previous_data.get("score"))
        current_score = current_result.score
        previous_severity = previous_data.get("severity")
        current_severity = current_result.severity

        return AnalysisDiffSummary(
            has_previous_snapshot=True,
            message=self._build_diff_message(
                changed_checks,
                added_findings,
                removed_findings,
                previous_score,
                current_score,
            ),
            previous_snapshot_created_at=previous_snapshot.created_at,
            previous_score=previous_score,
            current_score=current_score,
            score_delta=None
            if previous_score is None
            else current_score - previous_score,
            previous_severity=previous_severity,
            current_severity=current_severity,
            severity_changed=previous_severity != current_severity,
            changed_checks=changed_checks,
            added_findings=added_findings,
            removed_findings=removed_findings,
        )

    def _get_tracked_domain(
        self, db: Session, normalized_domain: str
    ) -> TrackedDomain | None:
        stmt = select(TrackedDomain).where(
            TrackedDomain.normalized_domain == normalized_domain
        )
        return db.scalar(stmt)

    def _to_history_item(self, snapshot: AnalysisSnapshot) -> HistoryItem:
        return HistoryItem(
            id=snapshot.id,
            created_at=snapshot.created_at,
            input_target=snapshot.input_target,
            analysis_domain=snapshot.analysis_domain,
            score=snapshot.score,
            severity=snapshot.severity,
            summary=snapshot.summary,
        )

    def _build_changed_checks(
        self, previous_data: dict, current_data: dict
    ) -> list[SnapshotChangeItem]:
        fields = [
            ("checks.spf.posture", "Postura SPF"),
            ("checks.dkim.status", "Status DKIM"),
            ("checks.dmarc.policy", "Politica DMARC"),
            ("checks.dmarc.policy_strength", "Forca DMARC"),
            ("website_tls.ssl_active", "TLS do website"),
            ("email_tls.has_email_tls_data", "Dados uteis de TLS de e-mail"),
            ("domain_registration.expiry_status", "Status de expiracao do dominio"),
            ("domain_registration.days_to_expire", "Dias para expirar o dominio"),
        ]
        changes: list[SnapshotChangeItem] = []
        for path, label in fields:
            previous_value = self._get_nested_value(previous_data, path)
            current_value = self._get_nested_value(current_data, path)
            if previous_value == current_value:
                continue
            changes.append(
                SnapshotChangeItem(
                    field=path,
                    label=label,
                    previous=self._format_change_value(previous_value),
                    current=self._format_change_value(current_value),
                )
            )
        return changes

    def _diff_findings(
        self, previous_data: dict, current_data: dict
    ) -> tuple[list[str], list[str]]:
        previous_findings = {
            self._finding_signature(item) for item in previous_data.get("findings", [])
        }
        current_findings = {
            self._finding_signature(item) for item in current_data.get("findings", [])
        }
        added = sorted(item for item in current_findings - previous_findings if item)
        removed = sorted(item for item in previous_findings - current_findings if item)
        return added, removed

    @staticmethod
    def _finding_signature(item: dict) -> str | None:
        title = item.get("title")
        detail = item.get("detail")
        if not title:
            return None
        return str(title) if not detail else f"{title}: {detail}"

    @staticmethod
    def _get_nested_value(data: dict, path: str):
        current = data
        for part in path.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    @staticmethod
    def _format_change_value(value):
        if isinstance(value, bool):
            return "sim" if value else "nao"
        return value

    @staticmethod
    def _coerce_int(value) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _build_diff_message(
        changed_checks: list[SnapshotChangeItem],
        added_findings: list[str],
        removed_findings: list[str],
        previous_score: int | None,
        current_score: int,
    ) -> str:
        if (
            previous_score is None
            and not changed_checks
            and not added_findings
            and not removed_findings
        ):
            return "Nao foi possivel comparar a nova analise com o snapshot anterior."
        if (
            not changed_checks
            and not added_findings
            and not removed_findings
            and previous_score == current_score
        ):
            return (
                "Nenhuma mudanca relevante foi detectada desde a ultima analise salva."
            )
        if previous_score is None:
            return "Mudancas relevantes foram detectadas desde a ultima analise salva."

        score_delta = current_score - previous_score
        if score_delta > 0:
            return f"A postura melhorou {score_delta} ponto(s) desde a ultima analise salva."
        if score_delta < 0:
            return f"A postura caiu {abs(score_delta)} ponto(s) desde a ultima analise salva."
        return "Mudancas relevantes foram detectadas desde a ultima analise salva."
