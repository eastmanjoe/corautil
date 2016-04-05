#!/usr/bin/env python

"""
Run Cora commands
"""

# ---------------------------------------------------------------------------#
from argparse import ArgumentParser
import subprocess
from logging.config import fileConfig

import os
import sys
import signal
import logging
import time
import re

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------#
# noinspection PyUnusedLocal,PyUnusedLocal,PyShadowingNames
def signal_handler(signal, frame):
    print ('You pressed Ctrl+C')
    logger.info('Script Stopped on: %s' % time.asctime(
        time.localtime(time.time())))
    sys.exit(0)


# ---------------------------------------------------------------------------#
class CoraError(Exception):
    FAILURES = {
        'unsupported message': 'command not supported by LoggerNet server',
        'invalid security': 'Server security prevented this command/transaction from executing.',
        'orphaned session': 'The connection to the server was lost while this command was executing.',
        'connection lost': 'The connection to the server was lost while this command was executing.',
        'Expected the device name': 'The name of the device is expected as the first argument.',
        'unknown': 'The server sent a response code that corascript is unable to recognise',
        'session failure': 'The server connection was lost while the transaction was executing.',
        'invalid device name': "The device name specified does not exist in the server's network map.",
        'blocked by server': 'Server security prevented the command from executing.',
        'unsupported': 'The server or the specified device does not support the command/transaction.',
        'blocked by logger': 'The security code setting for the specified device is not valid.',
        'communication disabled': 'Communication with the datalogger is disabled.',
        'communication failed': 'Communication with the datalogger failed.',
        'Expected the account name': 'The name of the account was expected in the first argument.',
        'Expected the account password': 'The password for the account was expected in the second argument.',
        'Expected the access level': 'The access level for the account was expected in the third argument.',
        'Invalid access level specified': 'An invalid access level was speciifed.',
        'unknown failure': 'The server sent a failure code that was not recognised by corascript.',
        'insufficient access to add accounts': 'Server security blocked this command from executing.',
        'connection failed': 'The server connection was lost while this command was executing.',
        'security interface is locked': 'Another client has locked the security interface.',
        'invalid account name': 'An invalid (or already existing) account name was specified.',
        'account is in use ': 'The command referred to an account that is currently being used.',
        'insufficient access to delete accounts': 'The command failed because of server security.',
        'Broker name expected first': 'The name of the data broker was expected as the first argument.',
        'invalid broker specified': 'There is no data broker that has the specified name.',
        'unsupported message type': 'The server does not support this command.',
        'exception': 'The server sent a response code that corascript was unable to recognise.',
        'Expected the column identifier': 'The column identifier was expected as the first argument.',
        'server_security_blocked': 'Server security prevented the command from executing.',
        'invalid_table_name': 'The table name specified does not exist.',
        'invalid_column_name': 'The column name specified does not exist.',
        'invalid_subscript': 'The array subscript specified does not exist.',
        'communication_failed': 'Communication with the datalogger failed.',
        'communication_disabled': 'Communication with the datalogger is disabled.',
        'logger_security_blocked':
            'The security code setting for the logger device is not set to an appropriate value.',
        'invalid_table_definitions': "The server's table definitions are not valid.",
        'invalid_device_name': 'The name of the device specified is invalid.',
        'unsupported by the server': 'The transaction is not supported by the server or by the device specified.'
    }

    def __init__(self, value):
        self.value = CoraError.FAILURES[value]

    def __str__(self):
        return self.value


# ---------------------------------------------------------------------------#
class CoraUtil:
    """
    Utility to execute cora commands for use in Python scripts
    """
    ACCESS_LEVEL = {
        'read-only': '1000',
        'Read-Only': '1000',
        'operator': '2000',
        'Operator': '2000',
        'manager': '3000',
        'Station Manager': '3000',
        'administrator': '4000',
        'Network Administrator': '4000',
        'root': '5000',
        'Full Administrator': '5000'
    }

    def __init__(self, server_ip, username, password, server_port=6789):
        """
        :param server_ip: IP Address or DNS Name of the LoggerNet server to connect to
        :type server_ip: str
        :param username: username for the account being used to access the LoggerNet server
        :type username: str
        :param password: the password for the account being used to access the LoggerNet server
        :type password: str
        :param server_port:
        :type server_port: int
        :return:
        """

        self.server_ip = server_ip
        self.username = username
        self.password = password
        self.server_port = server_port

    def write_cora_file(self, command_str):
        """
        write the list of commands to a temp file to be executed

        :param command_str: the cora command(s) to write to the temp file
        :type command_str: str
        """

        cora_connect = 'connect '
        cora_connect += self.server_ip + ' '
        cora_connect += '--name={' + self.username + '} '
        cora_connect += '--password={' + self.password + '} '
        cora_connect += '--server-port=' + str(self.server_port) + ';\n'
        cora_connect += 'lock-network;'

        with open('tmp.cora', 'w') as fid:
            fid.write(cora_connect + '\n')
            fid.write(command_str + '\n')
            fid.write('unlock-network;\nexit;\n')

    def execute_cora(self, command_str):
        """
        execute a list of cora commands

        :param command_str: the list of cora commands
        :type command_str: str
        """
        cora = ['cora', '--echo=on', '--input-file=tmp.cora']

        command = command_str.partition(' ')

        error = re.compile("-" + command[0].strip(';') + ",(?P<error_message>.+)")
        response = re.compile("\*" + command[0].strip(';') + "\n{\n(?P<response>.+)\n}\n")

        # write the cora commands to a file to make executing them easier
        self.write_cora_file(command_str)

        # execute the cora command
        logger.debug('executing cora command')
        cora_output = subprocess.check_output(cora)

        # cora_output = re.sub(r'\r', '\n', cora_output)
        logger.debug('output of cora is: {}'.format(cora_output))

        # os.remove('tmp.cora')

        for line in cora_output.split('\n'):

            # search for the indicator of an error
            error_str = error.search(line)

            # logger.debug('cora line: {}'.format(line))
            # logger.debug('error found: {}'.format(error_str))

            if error_str:
                error_message = error_str.group('error_message').strip()

                return error_message

        return cora_output

    def list_stations(self):
        """
        issues the cora command to list the station on the LoggerNet server and return as a list

        :return:
        """
        station_list = []
        station_name = re.compile(r'\{\{(?P<station_name>.*)\}\s+\d+\}')

        logger.debug('getting station list via cora')

        cora_output = self.execute_cora('list-stations;')

        if cora_output not in dict.keys(CoraError.FAILURES):
            for line in cora_output.split('\n'):
                sn_match = station_name.match(line.strip())
                if sn_match:
                    if sn_match.group('station_name') != '__Statistics__':
                        station_list.append(sn_match.group('station_name'))

            return station_list

        else:
            # raise CoraError(cora_output)
            return cora_output

    def list_files(self, station_name):
        re_file = re.compile(
            r'\{CPU:(?P<filename>.+)\}\srn=(?P<rn>false|true)\spu=(?P<pu>false|true)' +
            r'\sro=(?P<ro>false|true)\ssize=(?P<size>\d+)\slast-changed=\{(?P<last_changed>.+)\}'
        )

        file_list = []

        cora_output = self.execute_cora('list-files ' + station_name + ';')

        if cora_output not in dict.keys(CoraError.FAILURES):
            cora_output_split = cora_output.split('\n')
            cora_output_split = filter(None, cora_output_split)

            # logger.debug('cora_output list is: {}'.format(cora_output_split))

            for line in cora_output_split:
                # clear dictionary
                file_info = {}

                # remove newline characters
                line = line.strip()

                # logger.debug('cora_output line is: {}'.format(line))

                # if CPU is in string
                if 'CPU' in line:

                    parameter = re_file.search(line)
                    # logger.debug('cora_output regex is: {}'.format(parameter))

                    if parameter:
                        # logger.debug('file parameters are: {}'.format(parameter.groups()))

                        file_info['filename'] = parameter.group('filename')
                        file_info['filename'] = file_info['filename'].strip('{CPU:')
                        file_info['filename'] = file_info['filename'].strip('}')

                        file_info['rn'] = parameter.group('rn')
                        file_info['pu'] = parameter.group('pu')
                        file_info['ro'] = parameter.group('ro')
                        file_info['size'] = parameter.group('size')
                        file_info['last-changed'] = parameter.group('last_changed')

                        logger.debug('filename is: {}'.format(file_info['filename']))
                        logger.debug('file_info is: {}'.format(file_info))

                        if file_info['filename'] != '':
                            file_list.append(file_info)

            logger.debug('the complete list is: {}'.format(file_list))
            return file_list

        else:
            logger.debug('cora error is: {}'.format(CoraError))
            # raise CoraError(cora_output)
            return cora_output

    def list_devices(self):
        """
        get a list of the devices on the loggernet server
        """

        device_list = []

        reg_device = re.compile(
            r'\{\{(?P<device_name>.+)\}\s(?P<device_id>\d)+\s(?P<device_type_code>.+)\s(?P<device_indent>\d+)\}'
        )

        cora_output = self.execute_cora('list-devices;')

        if cora_output not in dict.keys(CoraError.FAILURES):
            cora_output = re.sub(r'\r', '\n', cora_output)

            for line in cora_output.split('\n'):
                line = line.strip()

                device = reg_device.search(line)

                if device:
                    # append the device to list of devices
                    device_list.append(
                        {
                            'device_name': device.group('device_name').strip(),
                            'device_id': device.group('device_id').strip(),
                            'device_type_code': device.group('device_type_code').strip(),
                            'device_indent': device.group('device_indent').strip()
                        }
                    )

            return device_list

        else:
            # logger.debug('cora error is: {}'.format(CoraError))
            # raise CoraError(cora_output)
            return cora_output

    def get_network_map(self, export_format='xml'):
        # execute the cora command
        cora_output = self.execute_cora('make-xml-network-map --format=' + export_format + ';')
        logger.info('{}'.format(cora_output))

    def list_tables(self, station_name):
        cora_output = self.execute_cora('list-tables {' + station_name + '};')

        logger.debug('cora_output is: {}'.format(cora_output))

        if cora_output not in dict.keys(CoraError.FAILURES):
            cora_output = re.sub(r'\r', '', cora_output)
            cora_output = re.sub(r'\n', '', cora_output)
            cora_output = re.sub(r'""', ',', cora_output)

            # extract the cora response
            str_start = cora_output.index('*list-tables')
            str_end = cora_output.index('+list-tables')

            table_str = cora_output[str_start:str_end]

            # extract the list of tables
            str_start = table_str.index('{') + 1
            str_end = table_str.index('}')
            table_str = table_str[str_start:str_end]

            table_str = re.sub('"', '', table_str)

            logger.debug('{}'.format(cora_output))
            logger.debug('{}'.format(str_start))
            logger.debug('{}'.format(str_end))
            logger.debug('{}'.format(table_str))

            table_list = table_str.split(',')

            return table_list
        else:
            # raise CoraError(cora_output)
            return cora_output


    def clock_check(self, station_name):
        cora_output = self.execute_cora('clock-check {' + station_name + '};')

        if cora_output not in dict.keys(CoraError.FAILURES):
            str_start = cora_output.index('*clock-check')
            str_end = cora_output.index('+clock-check')

            returned_str = cora_output[str_start:str_end]

            # extract the time returned
            str_start = returned_str.index('{') + 1
            str_end = returned_str.index('}')
            station_time = returned_str[str_start:str_end]

            if '2016' in station_time:
                return True
            else:
                return False
        else:
            return False


    def get_value(self, station_name, value):
        cora_output = self.execute_cora('get-value {' + station_name + value + '};')

        if cora_output not in dict.keys(CoraError.FAILURES):
            cora_output = re.sub(r'\r', '', cora_output)
            cora_output = re.sub(r'\n', '', cora_output)

            logger.debug('cora_output is: {}'.format(cora_output))

            value_index_start = cora_output.index('*get-value{') + 11
            value_index_end = cora_output.index('}+get-value')

            value_str = cora_output[value_index_start:value_index_end]

            return value_str
        else:
            # logger.error('{}'.format(CoraError(cora_output)))
            # raise CoraError(cora_output)
            return cora_output

    def get_program_stats(self, station_name):
        # list of cora command to execute
        cora_output = self.execute_cora('get-program-stats {' + station_name + '};')
        logger.info('{}'.format(cora_output))

    def change_account(self, account_name, password, security_level, device_addition=''):
        options = [account_name, password, security_level, '{' + device_addition + '};']
        cora_output = self.execute_cora('change-account ' + ' '.join(options))
        logger.info('{}'.format(cora_output))

    def add_account(self, account_name, password, security_level, device_addition=''):
        options = [account_name, password, security_level, '{' + device_addition + '};']
        cora_output = self.execute_cora('add-account ' + ' '.join(options))
        logger.info('{}'.format(cora_output))

    def delete_account(self, account_name):
        cora_output = self.execute_cora('delete-account ' + account_name + ';')
        logger.info('{}'.format(cora_output))

    def list_accounts(self):
        cora_output = self.execute_cora('list-accounts;')
        logger.info('{}'.format(cora_output))

    def add_device(self, device_type, device_name, anchor_code, anchor_device_name):
        # cora_output = self.execute_cora(';')
        pass

    def set_device_setting(self):
        # list of cora command to execute
        # "set-device-setting" device-name setting-id formatted-setting.
        # cora_output = self.execute_cora(';')
        pass

    def enable_collection(self, station):
        cora_output = self.execute_cora('set-device-setting {} defaultScheduleEnabled true;'.format(station))
        print(cora_output)

# ---------------------------------------------------------------------------#
if __name__ == '__main__':
    fileConfig(os.path.join(os.path.dirname(__file__), 'cora.ini'))
    logger = logging.getLogger('cora')
    # logger.setLevel('DEBUG')

    station = {}

    parser = ArgumentParser()
    parser.add_argument(
        '--server_ip', help='ip address of the LoggerNet server', default=''
    )
    parser.add_argument(
        '--username', help='username for LoggerNet server', default=''
    )
    parser.add_argument(
        '--password', help='password for LoggerNet server', default=''
    )
    args = parser.parse_args()

    # register Ctrl-C signal handler
    signal.signal(signal.SIGINT, signal_handler)

    if args.username == '':
        args.username = raw_input('Please enter your LoggerNet username')

    if args.password == '':
        args.password = raw_input('Please enter your LoggerNet password')

    # tests for
    # for name, server in dict.items(loggernet_servers):
    #     if name not in ['localhost', 'all']:
    #         logger.info('Performing Operations on {}'.format(name))
    #         loggernet = Cora(server, args.username, args.password)
    #         # loggernet.changeAccount('Joe', 'Schmo', Cora.ACCESS_LEVEL['Full Administrator'])
    #         loggernet.deleteAccount('Joe')

    loggernet = CoraUtil(args.server_ip, args.username, args.password)
    # station_list = loggernet.listStations()
    # logger.info('{}'.format(station_list))

    # for station_name in station_list:
    #     station[station_name] = {}
    #     station[station_name]['list-files'] = loggernet.listFiles(station_name)

    # test for listFiles
    # station_name = 'LAB-CR1000'
    # station[station_name] = {}
    # station[station_name]['list-files'] = loggernet.listFiles(station_name)

    # logger.info('{}'.format(station))

    # test for listDevices
    devices = loggernet.list_devices()
    logger.info('{}'.format(devices))

    # test for listTables
    # table_list = loggernet.listTables(station_name)
    # logger.info('{}'.format(table_list))
    # try:
    #     table_list.remove('Public')
    # except ValueError:
    #     raise
    # finally:
    #     logger.info('{}'.format(table_list))

    # # test for getValue
    # logger.info('{}'.format(loggernet.getValue(station_name, '.Status.DataTableName(' + str(1) + ')')))
    # logger.info('{}'.format(loggernet.getValue(station_name, '.Status.DataFillDays(' + str(1) + ')')))
