"""
Anonymization strategy helpers.

``OperatorConfig`` is kept as part of the public API for external callers
who build custom anonymization pipelines.  Internal modes (anonymize, tag,
i_tag) are implemented directly in GuardEngine and no longer use this module.
"""
from zorgdeid.types import OperatorConfig

__all__ = ["OperatorConfig"]
