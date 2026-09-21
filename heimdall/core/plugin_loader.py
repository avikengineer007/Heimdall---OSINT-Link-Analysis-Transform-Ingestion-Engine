"""
Plugin Loader — Discovers and hot-loads community transforms from transforms/plugins/.

Scans a directory for *.py files, imports each as a module, and catches any
PluginDefinitionError or import error without crashing the server.

Supports:
  - Cold discovery on server startup
  - Hot-reload via POST /api/v1/plugins/reload
  - Optional filesystem watching via `watchfiles` (soft dependency)
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

logger = logging.getLogger("heimdall.core.plugin_loader")


class PluginReport(NamedTuple):
    loaded: List[str]           # Successfully registered plugin names/files
    failed: Dict[str, str]      # filename → error message


class PluginLoader:
    """
    Discovers, imports, and optionally watches a plugins directory.

    Plugins are plain Python modules that use the ``@heimdall_plugin``
    decorator — no class registration boilerplate needed.
    """

    def __init__(self, plugin_dir: Optional[Path] = None):
        self.plugin_dir = plugin_dir or Path("transforms/plugins")
        self._watching: bool = False
        self._watch_task = None

    def discover(self, plugin_dir: Optional[Path] = None) -> PluginReport:
        """
        Scans ``plugin_dir`` for *.py files and imports each one.

        Each import triggers the @heimdall_plugin decorator which auto-registers
        the transform. Import errors are caught and returned in the failed dict.

        Returns:
            PluginReport(loaded, failed)
        """
        target = plugin_dir or self.plugin_dir
        loaded: List[str] = []
        failed: Dict[str, str] = {}

        if not target.exists():
            logger.debug(f"Plugin directory '{target}' does not exist — skipping discovery")
            return PluginReport(loaded=[], failed={})

        plugin_files = sorted(target.glob("*.py"))
        plugin_files = [f for f in plugin_files if not f.name.startswith("_")]

        if not plugin_files:
            logger.debug(f"No plugins found in '{target}'")
            return PluginReport(loaded=[], failed={})

        logger.info(f"[PluginLoader] Discovering {len(plugin_files)} plugin(s) from '{target}'")

        for py_file in plugin_files:
            module_name = f"heimdall_plugin_{py_file.stem}"
            try:
                # Skip already-loaded modules (avoid double-registration on hot-reload)
                if module_name in sys.modules:
                    logger.debug(f"[PluginLoader] Already loaded: {py_file.name} — skipping")
                    loaded.append(py_file.name)
                    continue

                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Could not create module spec for '{py_file}'")

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)  # type: ignore[attr-defined]

                loaded.append(py_file.name)
                logger.info(f"[PluginLoader] ✓ Loaded: {py_file.name}")

            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}"
                failed[py_file.name] = err_msg
                # Remove from sys.modules if partially loaded
                sys.modules.pop(module_name, None)
                logger.warning(f"[PluginLoader] ✗ Failed to load '{py_file.name}': {err_msg}")

        logger.info(
            f"[PluginLoader] Discovery complete: {len(loaded)} loaded, {len(failed)} failed"
        )
        return PluginReport(loaded=loaded, failed=failed)

    def reload(self, plugin_dir: Optional[Path] = None) -> PluginReport:
        """
        Hot-reload: evicts cached plugin modules then re-discovers.

        Useful when plugins are updated at runtime without restarting the server.
        Note: transforms already in the registry from the previous load persist —
        hot-reload adds new transforms but does not deregister stale ones to
        avoid invalidating in-flight pipeline references.
        """
        target = plugin_dir or self.plugin_dir
        # Evict cached modules from this plugin dir
        prefixed = "heimdall_plugin_"
        stale = [k for k in sys.modules if k.startswith(prefixed)]
        for key in stale:
            del sys.modules[key]
        logger.info(f"[PluginLoader] Evicted {len(stale)} cached plugin module(s) for hot-reload")
        return self.discover(target)

    async def watch(self, plugin_dir: Optional[Path] = None):
        """
        Optional file-system watcher using ``watchfiles`` (soft dependency).

        Automatically triggers hot-reload when any .py file in the plugins dir
        is created or modified. Safe to call even if watchfiles is not installed.
        """
        target = plugin_dir or self.plugin_dir
        try:
            from watchfiles import awatch  # type: ignore
        except ImportError:
            logger.info(
                "[PluginLoader] 'watchfiles' not installed — file-system watching disabled. "
                "Install it with: pip install watchfiles"
            )
            return

        logger.info(f"[PluginLoader] Watching '{target}' for plugin changes...")
        self._watching = True
        async for changes in awatch(target):
            py_changes = [c for c in changes if str(c[1]).endswith(".py")]
            if py_changes:
                logger.info(f"[PluginLoader] File change detected: {[c[1] for c in py_changes]}")
                self.reload(target)


# Module-level singleton
plugin_loader = PluginLoader()
