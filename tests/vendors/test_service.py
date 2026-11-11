import asyncio

from vendors.common.service import advance_safely


def test_advance_safely_swallows_and_reports_errors():
    class Broken:
        def advance(self):
            raise RuntimeError("database restarted")

    assert advance_safely(Broken()) is False


def test_advance_loop_keeps_running_after_an_error():
    from vendors.common import service

    calls = []

    class Flaky:
        def advance(self):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("transient")

    async def main():
        task = asyncio.create_task(service._advance_loop(Flaky(), interval=0.01))
        await asyncio.sleep(0.1)
        task.cancel()

    asyncio.run(main())
    assert len(calls) >= 3
