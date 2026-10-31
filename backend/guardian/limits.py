"""Bound the entire request before multipart parsing can spool it to disk."""
from starlette.responses import JSONResponse

class RequestSizeLimit:
    def __init__(self, app, limit=11 * 1024 * 1024):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] not in {'POST', 'PUT', 'PATCH'}:
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            size += len(message.get('body', b''))
            if size > self.limit:
                return await JSONResponse({'detail':'Request exceeds the 11 MB transport limit.'}, status_code=413)(scope, receive, send)
            chunks.append(message)
            if not message.get('more_body', False):
                break
        iterator = iter(chunks)
        async def replay():
            return next(iterator, {'type':'http.request', 'body':b'', 'more_body':False})
        await self.app(scope, replay, send)
