# SPDX-License-Identifier: Apache-2.0

"""Smoke tests for files/netbox/extractors/base_extractor.py.

Analogous to the exceptions.py inheritance smoke tests: ``BaseExtractor`` is an
abstract base class, and every tier-3 extractor must subclass it and provide a
concrete ``extract`` (so instances are creatable).
"""

import pytest

from extractors.base_extractor import BaseExtractor
from extractors.config_context_extractor import ConfigContextExtractor
from extractors.custom_field_extractor import CustomFieldExtractor
from extractors.gnmic_extractor import GnmicExtractor
from extractors.primary_ip_extractor import PrimaryIPExtractor
from extractors.secrets_extractor import SecretsExtractor

TIER3_EXTRACTORS = [
    ConfigContextExtractor,
    CustomFieldExtractor,
    GnmicExtractor,
    PrimaryIPExtractor,
    SecretsExtractor,
]


def test_base_extractor_cannot_be_instantiated():
    # The abstractmethod on extract prevents direct instantiation.
    with pytest.raises(TypeError):
        BaseExtractor()


@pytest.mark.parametrize("extractor_cls", TIER3_EXTRACTORS)
def test_tier3_extractor_is_concrete_subclass(extractor_cls):
    assert issubclass(extractor_cls, BaseExtractor)
    # A concrete extract overrides the abstractmethod, so instances are creatable.
    assert isinstance(extractor_cls(), BaseExtractor)


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    pytest.main([__file__, "-v"])
