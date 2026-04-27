import pytest

from app.db.base import Base
from app.db.session import engine
from app.services.asset_discovery_service import AssetDiscoveryService
from app.services.auth_service import AuthenticationService
from app.services.providers.amass_runner import (
    AssetDiscoveryResult,
    DiscoveredAssetRecord,
)


class StubAmassRunner:
    provider_name = "amass"

    def __init__(self, results: list[AssetDiscoveryResult]) -> None:
        self.results = list(results)
        self.calls: list[str] = []

    def discover(self, domain: str) -> AssetDiscoveryResult:
        self.calls.append(domain)
        return self.results.pop(0)


@pytest.fixture(autouse=True)
def reset_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_asset_discovery_service_persists_results_and_marks_new_assets():
    auth_service = AuthenticationService()
    user = auth_service.register_user("discovery@example.com", "supersecret")
    runner = StubAmassRunner(
        [
            AssetDiscoveryResult(
                provider="amass",
                status="completed",
                assets=[
                    DiscoveredAssetRecord(fqdn="api.example.com", source="amass"),
                    DiscoveredAssetRecord(fqdn="mail.example.com", source="amass"),
                ],
            ),
            AssetDiscoveryResult(
                provider="amass",
                status="completed",
                assets=[
                    DiscoveredAssetRecord(fqdn="api.example.com", source="amass"),
                    DiscoveredAssetRecord(fqdn="new.example.com", source="amass"),
                ],
            ),
        ]
    )
    service = AssetDiscoveryService(runner=runner)

    first = service.create_run(user_id=user.id, domain="example.com")
    second = service.create_run(user_id=user.id, domain="example.com")

    assert runner.calls == ["example.com", "example.com"]
    assert first.run.asset_count == 2
    assert first.run.new_asset_count == 2
    assert second.run.asset_count == 2
    assert second.run.new_asset_count == 1
    assert [item.fqdn for item in second.subdomains] == [
        "api.example.com",
        "new.example.com",
    ]
    assert [item.is_new for item in second.subdomains] == [False, True]


def test_asset_discovery_service_handles_unavailable_runner():
    auth_service = AuthenticationService()
    user = auth_service.register_user(
        "discovery-unavailable@example.com", "supersecret"
    )
    runner = StubAmassRunner(
        [
            AssetDiscoveryResult(
                provider="amass",
                status="unavailable",
                error_message="Amass nao encontrado.",
            )
        ]
    )
    service = AssetDiscoveryService(runner=runner)

    detail = service.create_run(user_id=user.id, domain="example.com")

    assert detail.run.status == "unavailable"
    assert detail.run.asset_count == 0
    assert detail.run.error_message == "Amass nao encontrado."
