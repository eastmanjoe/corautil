import pytest
from logging import getLogger, DEBUG, INFO

from corautil.utils import extract_data, remove_quotes


@pytest.mark.parametrize(('command', 'cora_output', 'response'),
                         [
                             (
                                    'get-device-setting',
                                    '*get-device-setting,active\n'
                                    '{\n'
                                    '0 {19900101 00:00:00.000} 300000 120000 3 86400000\n'
                                    '}\n'
                                    '+get-device-setting\n',
                                    ['0 {19900101 00:00:00.000} 300000 120000 3 86400000']
                              ),
                             (
                                    'list-stations',
                                    '*list-stations\n'
                                    '{\n'
                                    '{{s0000_draker_engineering_das-4} 3}\n'
                                    '{{LAB-CR200X} 8}\n'
                                    '{{LAB-CR6} 10}\n'
                                    '{{draker_dealer-dot-com} 12}\n'
                                    '{{s0000_draker_engineering_das-1} 14}\n'
                                    '{{Apps_Test_CR1000} 18}\n'
                                    '{{s0000_draker_engineering_das-3} 20}\n'
                                    '{{s0000_draker_engineering_das-2} 22}\n'
                                    '{{s0000_draker_engineering_das-5} 28}\n'
                                    '{{PV2001_CR1000} 30}\n'
                                    '{{CR200Series} 32}\n'
                                    '{{CR300Series} 34}\n'
                                    '{{s0000_draker_engineering_das-6} 36}\n'
                                    '{{__Statistics__} 37}\n'
                                    '}\n'
                                    '+list-stations\n',
                                    [
                                        '{{s0000_draker_engineering_das-4} 3}',
                                        '{{LAB-CR200X} 8}',
                                        '{{LAB-CR6} 10}',
                                        '{{draker_dealer-dot-com} 12}',
                                        '{{s0000_draker_engineering_das-1} 14}',
                                        '{{Apps_Test_CR1000} 18}',
                                        '{{s0000_draker_engineering_das-3} 20}',
                                        '{{s0000_draker_engineering_das-2} 22}',
                                        '{{s0000_draker_engineering_das-5} 28}',
                                        '{{PV2001_CR1000} 30}',
                                        '{{CR200Series} 32}',
                                        '{{CR300Series} 34}',
                                        '{{s0000_draker_engineering_das-6} 36}',
                                        '{{__Statistics__} 37}'
                                    ]
                             ),
                             (
                                 'clock-check',
                                 '*clock-check\n'
                                 '{\n'
                                 '"2017-06-13 16:32:17.330",-2332\n'
                                 '}\n'
                                 '+clock-check,clock checked\n',
                                 [
                                    '"2017-06-13 16:32:17.330",-2332'
                                 ]
                             ),
                             (
                                 'get-device-setting',
                                 'CoraScript 1, 17, 02\n'
                                 '+connect,"coralib3.dll version 1, 11, 05"\n'
                                 '+lock-network\n'
                                 '*get-device-setting,active\n'
                                 '{\n'
                                 '\n'
                                 '}\n'
                                 '+get-device-setting\n'
                                 '+unlock-network\n',
                                 ['']
                             ),
                             (
                                'list-tables',
                                'CoraScript 1, 19, 01\n'
                                '+connect,"coralib3.dll version 1, 11, 05"\n'
                                '+lock-network\n'
                                '*list-tables,p3088_01-chikunishi_mega_solar_nihondensetu-chikusei\n'
                                '{\n'
                                '"fifteenMin"\n'
                                '"panelStatus"\n'
                                '"Public"\n'
                                '"Status"\n'
                                '}\n'
                                '+list-tables\n'
                                '+unlock-network\n',
                                [
                                    '"fifteenMin"',
                                    '"panelStatus"',
                                    '"Public"',
                                    '"Status"'
                                ]
                             )
                         ]
                         )
def test_extract_data(command, cora_output, response):
    logger = getLogger('test_device_settings')
    logger.setLevel(DEBUG)

    extracted_response = extract_data(cora_output, command)
    logger.debug('{}'.format(extracted_response))

    assert extracted_response == response


# @pytest.mark.parametrize(('cora_output', 'string'),
#                          [
#                              'CoraScript 1, 19, 01\n'
#                              '+connect,"coralib3.dll version 1, 11, 05"\n'
#                              '+lock-network\n'
#                              '*get-value\n'
#                              '{\n'
#                              '4,194,304\n'
#                              '}\n'
#                              '+get-value\n'
#                              '+unlock-network\n'
#                          ]
#                          )
# def test_remove_quotes():
#     logger = getLogger('test_device_settings')
#     logger.setLevel(DEBUG)
