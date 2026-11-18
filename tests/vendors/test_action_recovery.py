import pytest
from psycopg import errors

from vendors.common.actions import ActionStore


@pytest.mark.integration
def test_action_is_not_dispatched_again_after_a_failed_completion_write(db_pool, clock):
    calls = []
    store = ActionStore(db_pool.schema, db_pool, lambda *args: calls.append(args), clock=clock.now)
    store.ensure_table()
    action = store.submit("control", "test", "fixture", {})

    with db_pool.connection() as connection:
        connection.execute(f"ALTER TABLE {store.table} ADD CONSTRAINT no_success CHECK (status <> 'succeeded')")
    with pytest.raises(errors.CheckViolation):
        store.advance(clock(4))
    with db_pool.connection() as connection:
        connection.execute(f"ALTER TABLE {store.table} DROP CONSTRAINT no_success")

    restarted = ActionStore(db_pool.schema, db_pool, lambda *args: calls.append(args), clock=clock.now)
    restarted.advance(clock(5))

    assert len(calls) == 1
    record = restarted.get(action.action_id)
    assert record.status == "failed"
    assert "outcome unknown" in record.failure_reason
