"""
Heimdall Plugin SDK — @heimdall_plugin Decorator.

Allows community contributors to define OSINT transforms as plain async functions
and have them auto-registered into the Heimdall pipeline without touching core code.

Usage (drop into transforms/plugins/my_transform.py):
    from heimdall.transforms.sdk import heimdall_plugin
    from heimdall.core.models import EntityType, GraphEdge

    @heimdall_plugin(
        name="custom_leak_db",
        display_name="LeakDB Email Lookup",
        inputs=[EntityType.EMAIL],
        outputs=[EntityType.URL],
    )
    async def custom_leak_db(urn, value, transport, **kwargs):
        data = await transport.get_json(f"https://leakdb.example.com/check/{value}")
        if data and data.get("found"):
            return [GraphEdge(source=urn, target=f"URL:{data['breach_url']}",
                              target_type="URL", rel="FOUND_IN_BREACH")]
        return []
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Callable, List, Union

from heimdall.core.models import EntityType, GraphEdge, TransformResult
from heimdall.core.transport import ResilientAsyncTransport
from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import TransformRegistry

logger = logging.getLogger("heimdall.transforms.sdk")


class PluginDefinitionError(Exception):
    """Raised when a @heimdall_plugin decorated function has an invalid definition."""
    pass


def _normalise_types(types: List[Union[EntityType, str]]) -> set:
    """Accepts both EntityType enum members and raw strings."""
    result = set()
    for t in types:
        result.add(t.value if isinstance(t, EntityType) else str(t))
    return result


def _make_execute_method(user_fn: Callable) -> Callable:
    """
    Manufactures an ``execute`` method that wraps the user's plain async function
    while conforming to BaseTransform's exact method signature.
    """
    async def execute(
        self: BaseTransform,
        node_urn: str,
        value: str,
        transport: ResilientAsyncTransport,
        **kwargs: Any,
    ) -> List[GraphEdge]:
        result = await user_fn(urn=node_urn, value=value, transport=transport, **kwargs)
        if result is None:
            return []
        if not isinstance(result, list):
            logger.warning(
                f"Plugin '{self.name}' returned non-list type {type(result).__name__}; "
                "wrapping in empty list."
            )
            return []
        return result

    return execute


def heimdall_plugin(
    name: str,
    display_name: str,
    inputs: List[Union[EntityType, str]],
    outputs: List[Union[EntityType, str]] = None,
    requires_api_key: bool = False,
    description: str = "",
) -> Callable:
    """
    Decorator that converts an async function into a fully registered Heimdall transform.

    Parameters
    ----------
    name:            Unique machine identifier (e.g. "custom_leak_db").
    display_name:    Human-readable label shown in the UI and API transform list.
    inputs:          List of EntityType values this transform consumes.
    outputs:         List of EntityType values this transform may emit.
    requires_api_key: When True the transform will be skipped if its key is absent.
    description:     Optional docstring override.

    Raises
    ------
    PluginDefinitionError  if inputs is empty or the function is not async.
    """
    def decorator(fn: Callable) -> Callable:
        # ── Validation ────────────────────────────────────────────────────────
        if not inputs:
            raise PluginDefinitionError(
                f"Plugin '{name}' must declare at least one input EntityType."
            )
        if not inspect.iscoroutinefunction(fn):
            raise PluginDefinitionError(
                f"Plugin function '{fn.__name__}' must be an async coroutine (async def)."
            )

        # ── Dynamic class manufacture ─────────────────────────────────────────
        # Class-level attributes satisfy BaseTransform's attribute contract
        plugin_class = type(
            f"Plugin_{name.replace('-', '_').replace('.', '_')}",
            (BaseTransform,),
            {
                "name": name,
                "display_name": display_name,
                "description": description or (fn.__doc__ or display_name).strip(),
                "input_types": _normalise_types(inputs),
                "output_types": _normalise_types(outputs or []),
                "requires_api_key": requires_api_key,
                # Plug the user function in as execute()
                "execute": _make_execute_method(fn),
                # Mark as a dynamic plugin for introspection
                "__is_heimdall_plugin__": True,
                "__plugin_source__": inspect.getfile(fn),
            },
        )

        # ── Auto-register ──────────────────────────────────────────────────────
        instance = plugin_class()
        TransformRegistry.register(instance)
        logger.info(
            f"[Plugin SDK] Registered '{name}' ← {inspect.getfile(fn)}"
        )

        # Return the original function unchanged (it can still be called directly)
        return fn

    return decorator
