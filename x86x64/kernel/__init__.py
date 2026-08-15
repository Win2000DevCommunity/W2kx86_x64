"""Ring-0 surface: the service descriptor table a translated ntdll targets."""

from .ssdt import (
    ARGUMENT_TABLE_SYMBOL,
    DEFAULT_SERVICE_LIMIT,
    DESCRIPTOR_SYMBOL,
    SERVICE_TABLE_SYMBOL,
    ServiceEntry,
    ServiceTable,
)

__all__ = [
    'ARGUMENT_TABLE_SYMBOL', 'DEFAULT_SERVICE_LIMIT', 'DESCRIPTOR_SYMBOL',
    'SERVICE_TABLE_SYMBOL', 'ServiceEntry', 'ServiceTable',
]
