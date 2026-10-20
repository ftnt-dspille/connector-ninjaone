"""Off-box test fixtures.

The connector imports ``connectors.core.connector`` -- a module that only exists
on a FortiSOAR appliance. We stub a minimal version into ``sys.modules`` so the
operations module can be imported and exercised anywhere (CI, a laptop).

conftest is imported before the test modules, so the stub is in place by the time
``tests/test_ninjaone.py`` does its module-level ``from ninjaone import ...``.
"""

import sys
import types


class ConnectorError(Exception):
    pass


class Connector:  # the real base class; unused off-box but imported by connector.py
    pass


def get_logger(_name):
    import logging

    return logging.getLogger(_name)


_core = types.ModuleType("connectors.core.connector")
_core.ConnectorError = ConnectorError
_core.Connector = Connector
_core.get_logger = get_logger
# Deliberately NOT stubbed: update_connnector_config and
# integrations.crudhub.trigger_ingest_playbook. operations.py guards both with a
# try/ImportError, and leaving them absent is what exercises that off-box path.

sys.modules.setdefault("connectors", types.ModuleType("connectors"))
sys.modules.setdefault("connectors.core", types.ModuleType("connectors.core"))
sys.modules["connectors.core.connector"] = _core
