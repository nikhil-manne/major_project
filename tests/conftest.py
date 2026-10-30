"""
Shared pytest configuration for the Cyber Range test suite.

Provides a module-scoped DB cleanup fixture that removes session and lab rows
created by previous (possibly aborted) test runs. This prevents UNIQUE constraint
violations when the same test uploads the same Dockerfile content more than once.
"""
import os
import pytest

# Ensure test-mode auth bypass is active before any module is imported
os.environ.setdefault("DEV_AUTH_ENABLED", "true")
os.environ.setdefault("ATTACK_EXECUTION_MODE", "simulation")
os.environ.setdefault("ALLOW_SIMULATED_SANDBOX", "true")


@pytest.fixture(scope="session", autouse=True)
def clean_test_db():
    """
    Runs once per pytest session, before any tests.
    Deletes rows that were created by previous test runs (identified by the
    tenant used in tests) so each run starts from a predictable state.
    This does NOT drop tables or touch production data — only the test tenant.
    """
    from shared.db import init_db, db_context, Lab, SessionModel

    init_db()

    TEST_TENANT = "00000000-0000-0000-0000-000000000123"
    OTHER_TEST_TENANT = "00000000-0000-0000-0000-000000000999"

    with db_context() as db:
        # Delete sessions belonging to test tenants
        db.query(SessionModel).filter(
            SessionModel.tenant_id.in_([TEST_TENANT, OTHER_TEST_TENANT])
        ).delete(synchronize_session=False)
        # Delete labs belonging to test tenant
        db.query(Lab).filter(
            Lab.tenant_id.in_([TEST_TENANT, OTHER_TEST_TENANT])
        ).delete(synchronize_session=False)
        db.commit()

    yield
    # No teardown needed — next run's setup fixture will clean up.

