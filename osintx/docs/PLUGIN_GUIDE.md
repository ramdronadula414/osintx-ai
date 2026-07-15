# Plugin Development Guide

OSINT-X AI's plugin system lets you add a new data source or Linux tool
without modifying core files. Plugins are auto-discovered from
`plugins/installed/*.py` on every run.

## Minimal plugin

```python
from core.schema import Entity, EntityType, ToolResult
from plugins.base import OsintxPlugin, PluginMetadata


class MyPlugin(OsintxPlugin):
    metadata = PluginMetadata(
        name="My Data Source",
        version="1.0.0",
        author="Your Name",
        description="What this plugin does",
        supported_targets=["domain"],   # one or more of: person, username,
                                        # email, domain, ip, company, image
        requires_binary=None,           # or "some-cli-tool" if it shells out
    )

    def is_available(self) -> bool:
        # Return True only if dependencies (binary on PATH, API reachable,
        # API key set, etc.) are satisfied.
        return True

    def run(self, target: str, target_type: str, **kwargs) -> ToolResult:
        entities = [
            Entity(type=EntityType.SUBDOMAIN, value="found.example.com",
                   source="my_plugin", confidence=0.7)
        ]
        return ToolResult(tool="my_plugin", target=target, success=True,
                           entities=entities, raw_output="")
```

Save this as `plugins/installed/my_plugin.py`. It will be picked up
automatically by any module that calls `discover_plugins()` and checks
`target_type in plugin.metadata.supported_targets`.

## Rules for plugins

- **Public data only.** Never call an endpoint that requires bypassing
  authentication, scraping a logged-in session, or violating a site's
  terms of service.
- **No shell strings.** If your plugin shells out to a binary, use
  `utils.shell.run_command(argv_list, timeout=...)` — never build a shell
  string or use `shell=True`.
- **Never raise from `run()`.** Catch your own exceptions and return a
  `ToolResult(success=False, error=str(exc))` instead; the orchestrator
  will still record a warning, but a plugin exception should never crash
  an investigation for the whole target.
- **Respect rate limits.** Add your own delay/backoff if querying a public
  API repeatedly.

## Wiring a subprocess-based plugin

If your plugin wraps a CLI tool instead of an HTTP API, follow the same
pattern as `integrations/*_tool.py`: build a safe argv list, run it via
`utils.shell.run_command`, and parse stdout into `Entity` objects.

```python
from utils.shell import run_command

class MyCliPlugin(OsintxPlugin):
    ...
    def run(self, target, target_type, **kwargs):
        result = run_command(["my-tool", "--target", target], timeout=30)
        # ... parse result.stdout into entities ...
```
