# Using Custom Debug Browser

It might be desirable to run your own debug browser for running the tests in
environments such as WSL which might have no browser installed.

`aws-cli-auth` will look for an environment variable named `ROD_BROWSER_WS_URL`
and will use this Web Socket URL as the browser to use for communications.

## Example (MSEdge)

For example, to run a debug browser using MSEdge:
```bash
msedge \
	--remote-debugging-port=9222 \
	--user-data-dir='C:\temp\test'
```

> NOTE: The `--user-data-dir` parameter isn't strictly necessary, but if MSEdge
> is open for whatever reason then it'll re-use that window and you won't get a
> debug instance. Sometimes Windows suspends a closed window and this results in
> it thinking the window is still open.

### WSL Usage

When exposing debug browsers like MSEdge the `--remote-debugging-address` is
ignored. This means it binds to 127.0.0.1 explicitly which WSL (by default)
can't.

To mitiagte this please add to your `~/.wslconfig`:
```ini
[wsl2]
networkingMode=mirrored
```

This will allow WSL to access ports bound to 127.0.0.1 on the Windows host as if
they were bound through WSL.

### VSCode Tests

By adding a `ROD_BROWSER_WS_URL` to the `./vscode/settings.json` the tests can
then use the debug browser added above. E.g.:
```json
"ROD_BROWSER_WS_URL": "ws://127.0.0.1:9222/devtools/browser/b28bdd90-8c1d-478b-8294-1e3fd3170f4d",
```
