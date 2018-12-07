import pytest
from logging import getLogger, DEBUG, INFO

from corautil.device_settings import DeviceSettings


@pytest.mark.parametrize(('setting', 'setting_id'),
                         [
                             ('callbackEnabled', 36),
                             ('currentProgramName', 89),
                         ]
                         )
def test_device_settings(setting, setting_id):
    logger = getLogger('test_device_settings')
    logger.setLevel(DEBUG)

    set_id = DeviceSettings(setting).value

    logger.debug('{}: {}'.format(setting, set_id))

    assert set_id == setting_id
