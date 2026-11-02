import asyncio
import pytest
from services.common import RequestSlots


def test_requests_wait_before_body_read_and_health_bypasses_queue():
    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()
        seen = []

        async def app(scope, receive, send):
            seen.append(scope['path'])
            if scope['path'] == '/first':
                entered.set()
                await release.wait()

        gate = RequestSlots(app, limit=1)
        first = asyncio.create_task(gate({'type': 'http', 'path': '/first'}, None, None))
        await entered.wait()
        second = asyncio.create_task(gate({'type': 'http', 'path': '/second'}, None, None))
        await asyncio.sleep(0)
        await gate({'type': 'http', 'path': '/health'}, None, None)
        assert seen == ['/first', '/health']
        release.set()
        await asyncio.gather(first, second)
        assert seen == ['/first', '/health', '/second']
    asyncio.run(scenario())


def test_failed_request_releases_slot():
    async def scenario():
        async def app(scope, receive, send):
            if scope['path'] == '/error':
                raise ValueError('test')
        gate = RequestSlots(app, limit=1)
        with pytest.raises(ValueError):
            await gate({'type': 'http', 'path': '/error'}, None, None)
        await asyncio.wait_for(gate({'type': 'http', 'path': '/ok'}, None, None), 1)
    asyncio.run(scenario())
