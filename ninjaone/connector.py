"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, get_logger, ConnectorError

from .constants import CONNECTOR_NAME
from .operations import operations, _check_health

logger = get_logger(CONNECTOR_NAME)


class NinjaOne(Connector):
    def _connector_info(self):
        """Name and version, read from info.json at runtime.

        The version is what update_connnector_config() targets when the connector
        caches a freshly minted access token. Taking it from the manifest rather
        than from a constant keeps the two from drifting on a version bump.
        """
        return {
            'connector_name': self._info_json.get('name'),
            'connector_version': self._info_json.get('version'),
        }

    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation: {}'.format(operation))
        action = operations.get(operation)
        if not action:
            raise ConnectorError('Unsupported operation: {}'.format(operation))
        # FCP/TIP passes this through; the operation signatures do not take it.
        kwargs.pop('connector_name', None)
        kwargs['connector_info'] = self._connector_info()
        try:
            return action(config, params, **kwargs)
        except ConnectorError:
            raise
        except Exception as err:
            logger.exception('Operation {} failed'.format(operation))
            raise ConnectorError('{}'.format(err))

    def check_health(self, config):
        return _check_health(config, connector_info=self._connector_info())
