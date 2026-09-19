"""
Transform Registry for Dynamic Discovery and Execution.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Type
from heimdall.transforms.base import BaseTransform

logger = logging.getLogger("heimdall.registry")


class TransformRegistry:
    """Registry maintaining active OSINT transform plugins."""

    _registry: Dict[str, BaseTransform] = {}

    @classmethod
    def register(cls, transform_inst: BaseTransform) -> BaseTransform:
        cls._registry[transform_inst.name] = transform_inst
        logger.debug(f"Registered transform: {transform_inst.name}")
        return transform_inst

    @classmethod
    def get(cls, name: str) -> Optional[BaseTransform]:
        return cls._registry.get(name)

    @classmethod
    def list_transforms(cls) -> List[Dict[str, any]]:
        return [
            {
                "name": t.name,
                "display_name": t.display_name,
                "description": t.description,
                "input_types": list(t.input_types),
                "output_types": list(t.output_types),
                "requires_api_key": t.requires_api_key,
            }
            for t in cls._registry.values()
        ]

    @classmethod
    def find_for_type(cls, entity_type: str) -> List[BaseTransform]:
        """Returns all transforms that can process the specified entity type."""
        return [t for t in cls._registry.values() if t.can_process(entity_type)]

    @classmethod
    def clear(cls) -> None:
        cls._registry.clear()


def register_transform(cls: Type[BaseTransform]) -> Type[BaseTransform]:
    """Decorator to auto-instantiate and register a transform."""
    instance = cls()
    TransformRegistry.register(instance)
    return cls
