#!/usr/bin/env python

"""
Run Cora commands
"""

# ---------------------------------------------------------------------------#
from argparse import ArgumentParser
# import subprocess
from subprocess import check_output, Popen, PIPE
from logging.config import fileConfig

import os
import sys
import signal
from logging import getLogger, INFO, DEBUG
import time
import re
from datetime import datetime
import time

from errors import CoraError
from utils import format_cora_backup_scripts, remove_quotes


# ---------------------------------------------------------------------------#
# noinspection PyUnusedLocal,PyUnusedLocal,PyShadowingNames
def signal_handler(signal, frame):
    print ('You pressed Ctrl+C')
    logger.info('Script Stopped on: %s' % time.asctime(
        time.localtime(time.time())))
    sys.exit(0)


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
        self.logger = getLogger('coraUtil')

    def set_logger_level(self, logger_level):
        self.logger.setLevel(logger_level)

    def execute_cora(self, command_str):
        """
        execute a list of cora commands

        :param command_str: the list of cora commands
        :type command_str: str
        """

        if os.name == 'nt':
            cora = ["C:\Program Files (x86)\Campbellsci\LoggerNet\cora_cmd.exe"]
        elif os.name == 'posix':
            cora = ['/opt/CampbellSci/Loggernet/cora_cmd']
        else:
            cora = []

        # spawn an instance of cora
        cora_proc = Popen(cora, stdin=PIPE, stdout=PIPE, stderr=PIPE)

        #generate the connect command and lock the network
        cora_cmd = 'connect '
        cora_cmd += self.server_ip + ' '
        cora_cmd += '--name={' + self.username + '} '
        cora_cmd += '--password={' + self.password + '} '
        cora_cmd += '--server-port=' + str(self.server_port) + '; '
        cora_cmd += 'lock-network;'
        cora_cmd += command_str
        cora_cmd += 'unlock-network; exit;'

        # run the cora command and terminate the instance
        self.logger.debug('sending cora command: {}'.format(command_str))
        output, output_err = cora_proc.communicate(
            input=cora_cmd
        )

        if cora_proc.returncode != 0:
            self.logger.debug('cora returncode is {}'.format(cora_proc.returncode))
            self.logger.debug('cora error is {}'.format(output_err))
            exit(cora_proc.returncode)

        # terminate the cora subprocess
        cora_proc.kill()

        # create regex to find if cmd error
        command = command_str.partition(' ')
        error = re.compile("-" + command[0].strip(';') + ",(?P<error_message>.+)")
        # response = re.compile("\*" + command[0].strip(';') + "\n{\n(?P<response>.+)\n}\n")

        output = re.sub(r'\r\n', '\n', output)
        self.logger.debug('output of cora is: {}'.format(output))

        if error.search(output) is not None:
            raise CoraError(error.search(output).group('error_message').strip())
        else:
            output_list = output.split('\n')
            output_list = filter(None, output_list)

            for index, value in enumerate(output_list):
                if '*' + command[0].strip(';') in value:
                    str_start = index
                elif '+' + command[0].strip(';') in value:
                    str_end = index + 1

            return output_list[str_start:str_end]

    def list_stations(self):
        """
        issues the cora command to list the station on the LoggerNet server and return as a list

        :return:
        """
        station_list = []
        station_name = re.compile(r'\{\{(?P<station_name>.*)\}\s+(?P<broker_id>\d+)\}')

        self.logger.debug('getting station list via cora')

        cora_output = self.execute_cora('list-stations;')

        try:
            for line in cora_output:
                sn_match = station_name.match(line.strip())
                if sn_match is not None:
                    if sn_match.group('station_name') != '__Statistics__':
                        station_list.append(sn_match.group('station_name'))

            return station_list

        except CoraError:
            raise

    def list_files(self, station_name):
        re_file = re.compile(
            r'\{CPU:(?P<filename>.+)\}\srn=(?P<rn>false|true)\spu=(?P<pu>false|true)' +
            r'\sro=(?P<ro>false|true)\ssize=(?P<size>\d+)\slast-changed=\{(?P<last_changed>.+)\}'
        )

        file_list = []

        try:
            cora_output = self.execute_cora('list-files ' + station_name + ';')

            logger.debug('cora_output list is: {}'.format(cora_output))

            for line in cora_output:
                # clear dictionary
                file_info = {}

                # remove newline characters
                line = line.strip()

                logger.debug('cora_output line is: {}'.format(line))

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

                        self.logger.debug('filename is: {}'.format(file_info['filename']))
                        self.logger.debug('file_info is: {}'.format(file_info))

                        if file_info['filename'] != '':
                            file_list.append(file_info)

                        self.logger.debug('the complete list is: {}'.format(file_list))
            return file_list

        except CoraError:
            raise

    def list_devices(self):
        """
        get a list of the devices on the loggernet server
        """

        device_list = []

        reg_device = re.compile(
            r'\{\{(?P<device_name>.+)\}\s(?P<device_id>\d)+\s(?P<device_type_code>.+)\s(?P<device_indent>\d+)\}'
        )

        try:
            cora_output = self.execute_cora('list-devices;')

            for line in cora_output:
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

        except CoraError:
            raise

    def get_network_map(self, export_format='xml'):
        # execute the cora command
        cora_output = self.execute_cora('make-xml-network-map --format=' + export_format + ';')
        self.logger.info('{}'.format(cora_output))

    def list_tables(self, station_name):
        try:
            cora_output = self.execute_cora('list-tables {' + station_name + '};')

            self.logger.debug('cora_output is: {}'.format(cora_output))

            # extract the list of tables
            str_start = cora_output.index('{') + 1
            str_end = cora_output.index('}')

            return cora_output[str_start:str_end]

        except CoraError:
            raise

    def clock_check(self, station_name):
        """
         Returns the current time of the station and the difference between the station and the server.
         The time difference is in milliseconds.  A negative value indicates the station is ahead of the server.

        :param station_name:
        :return:
        """
        station_time = {}

        try:
            cora_output = self.execute_cora('clock-check {' + station_name + '};')

            # extract the time returned
            resp_index = cora_output.index('{') + 1

            self.logger.debug(str(cora_output[resp_index]))

            clock_response = re.search(
                '"(?P<station_time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3})",(?P<differences_msec>[|-]\d+)',
                str(cora_output[resp_index])
            )

            if clock_response is not None:
                station_time['Station Time'] = clock_response.group('station_time')
                station_time['Time Difference'] = clock_response.group('differences_msec')

                return station_time

        except CoraError:
            raise

    def data_query(self, station_name, table_name, begin_date, end_date):
        try:
            cmd = 'data-query {%s} {%s} "%s" "%s";' % (station_name, table_name, begin_date, end_date)
            self.logger.debug('cora command: {}'.format(cmd))

            cora_output = self.execute_cora(cmd)

            self.logger.debug('cora_output is: {}'.format(cora_output))

            index_start = cora_output.index('{') + 1
            index_end = cora_output.index('}')

            return cora_output[index_start:index_end]

        except CoraError:
            raise

    def get_value(self, station_name, value, swath=1):
        try:
            cora_output = self.execute_cora('get-value {' + station_name + '.'+ value + '} --swath=' + str(swath) + ';')

            self.logger.debug('cora_output is: {}'.format(cora_output))

            cora_output = remove_quotes(cora_output)

            index_start = cora_output.index('{') + 1
            index_end = cora_output.index('}')

            value_str = cora_output[index_start:index_end]
            return value_str

        except CoraError:
            raise

    def get_program_stats(self, station_name):
        # list of cora command to execute
        cora_output = self.execute_cora('get-program-stats {' + station_name + '};')
        self.logger.info('{}'.format(cora_output))

    def change_account(self, account_name, password, security_level, device_addition=''):
        options = [account_name, password, security_level, '{' + device_addition + '};']
        cora_output = self.execute_cora('change-account ' + ' '.join(options))
        self.logger.info('{}'.format(cora_output))

    def add_account(self, account_name, password, security_level, device_addition=''):
        options = [account_name, password, security_level, '{' + device_addition + '};']
        cora_output = self.execute_cora('add-account ' + ' '.join(options))
        self.logger.info('{}'.format(cora_output))

    def delete_account(self, account_name):
        cora_output = self.execute_cora('delete-account ' + account_name + ';')
        self.logger.info('{}'.format(cora_output))

    def list_accounts(self):
        cora_output = self.execute_cora('list-accounts;')
        self.logger.info('{}'.format(cora_output))

    def add_device(self, device_type, device_name, anchor_code, anchor_device_name):
        # cora_output = self.execute_cora(';')
        pass

    def set_device_setting(self):
        # list of cora command to execute
        # "set-device-setting" device-name setting-id formatted-setting.
        # cora_output = self.execute_cora(';')
        pass

    def enable_collection(self, station):
        cora_output = self.execute_cora(
            'set-device-setting %s 5 {true {19900101 00:00:30.000} 900000 120000 5 900000};' % station
        )
        return cora_output

    def disable_collection(self, station):
        cora_output = self.execute_cora(
            'set-device-setting %s 5 {false {19900101 00:00:30.000} 900000 120000 5 900000};' % station
        )
        return cora_output

    def get_table_defs(self, station):
        try:
            cora_output = self.execute_cora('get-table-defs %s;' % station)

            if '+get-table-defs' in cora_output:
                return True

        except CoraError:
            raise

    def collect_table(self, station, table):
        cora_output = self.execute_cora('set-collect-area-setting %s %s 2 true;' % (station, table))
        if cora_output not in dict.keys(CoraError.FAILURES):
            return True
        else:
            return False

    def get_table_settings(self, station, table):
        cora_output = self.execute_cora('list-collect-area-settings %s %s;' % (station, table))
        if cora_output not in dict.keys(CoraError.FAILURES):
            str_start = cora_output.index('*list-collect-area-settings')
            str_end = cora_output.index('+list-collect-area-settings')
            description_str = cora_output[str_start:str_end]
            description_str = re.sub('\n', '', description_str)
            self.logger.debug('{}'.format(cora_output))
            self.logger.debug('{}'.format(str_start))
            self.logger.debug('{}'.format(str_end))
            self.logger.debug('{}'.format(description_str))

            return description_str

        else:
            return cora_output

    def create_backup_scripts(self):
        # create backup
        cora_output = self.execute_cora('create-backup-script ' + self.server_ip + '-backup.cora;')
        parsed_backup = format_cora_backup_scripts(self.server_ip + '-backup.cora')
        return parsed_backup

    def read_note(self, station):
        #use this to read a station note in loggernet
        cora_output = self.execute_cora('get-device-setting {' + station + '} 90;')

        self.logger.debug('cora_output is: {}'.format(cora_output))

        if cora_output not in dict.keys(CoraError.FAILURES):

            # extract the cora response
            str_start = cora_output.index('*get-device-setting,active')
            str_end = cora_output.index('+get-device-setting')

            description_str = cora_output[str_start:str_end]

            # extract the list of tables
            str_start = description_str.index('{') + 1
            str_end = description_str.index('}')
            description_str = description_str[str_start:str_end]

            description_str = re.sub('"', '', description_str)

            self.logger.debug('{}'.format(cora_output))
            self.logger.debug('{}'.format(str_start))
            self.logger.debug('{}'.format(str_end))
            self.logger.debug('{}'.format(description_str))

            # description_list = description_str.split(',')

            return description_str
        else:
            # raise CoraError(cora_output)
            return cora_output

    def write_note(self, station, note, overwrite=False):
        #use this to write a note to a station in loggernet

        if not overwrite:
            current_note = self.read_note(station)
            new_note = current_note + note
        else:
            new_note = note

        cora_output = self.execute_cora(str('set-device-setting {' + station + '} 90 {' + new_note + '};'))

        self.logger.debug('cora_output is: {}'.format(cora_output))

    def delete_device(self, device):
        cora_output = self.execute_cora('delete-device ' + device + ';')
        self.logger.info('{}'.format(cora_output))

        return cora_output



# ---------------------------------------------------------------------------#
if __name__ == '__main__':
    fileConfig(os.path.join(os.path.dirname(__file__), 'cora.ini'))
    logger = getLogger('cora')
    logger.setLevel(DEBUG)

    logger.debug(os.getcwd())

    station = {}

    parser = ArgumentParser()
    parser.add_argument(
        '--server_ip', help='ip address of the LoggerNet server', default='1.loggernet.draker.us'
    )
    parser.add_argument(
        '--username', help='username for LoggerNet server', default='Joe'
    )
    parser.add_argument(
        '--password', help='password for LoggerNet server', default='w4LdL4fe'
    )
    args = parser.parse_args()

    # register Ctrl-C signal handler
    signal.signal(signal.SIGINT, signal_handler)

    if args.username == '':
        args.username = input('Please enter your LoggerNet username')

    if args.password == '':
        args.password = input('Please enter your LoggerNet password')

    # tests for
    # for name, server in dict.items(loggernet_servers):
    #     if name not in ['localhost', 'all']:
    #         logger.info('Performing Operations on {}'.format(name))
    #         loggernet = Cora(server, args.username, args.password)
    #         # loggernet.changeAccount('Joe', 'Schmo', Cora.ACCESS_LEVEL['Full Administrator'])
    #         loggernet.deleteAccount('Joe')

    loggernet = CoraUtil(args.server_ip, args.username, args.password)
    loggernet.set_logger_level(DEBUG)
    # logger.info('{}'.format(loggernet.list_stations()))

    # for station_name in station_list:
    #     station[station_name] = {}
    #     station[station_name]['list-files'] = loggernet.listFiles(station_name)

    # test for listFiles
    # station_name = 'LAB-CR1000'
    # station[station_name] = {}
    # station[station_name]['list-files'] = loggernet.listFiles(station_name)

    # logger.info('{}'.format(station))

    # test for listDevices
    # logger.info('{}'.format(loggernet.list_devices()))

    # logger.info('{}'.format(loggernet.list_tables('draker_dealer-dot-com')))
    # logger.info('{}'.format(loggernet.clock_check('draker_dealer-dot-com')))
    # logger.info('{}'.format(loggernet.list_files('draker_dealer-dot-com')))
    # logger.info('{}'.format(loggernet.get_value('draker_dealer-dot-com', 'Public.datalogger_ip')))
    # logger.info('{}'.format(loggernet.get_value('draker_dealer-dot-com', 'DataTableInfo.DataTableName', 5)))
    # records = loggernet.data_query('draker_dealer-dot-com', 'fifteenMin', '20170601 23:45', '20170602 00:00')
    # records = loggernet.data_query('__statistics__', 'draker_dealer-dot-com_hist', '20170602 20:00', '20170603 00:00')

    # for record in records:
    #     logger.info('{}'.format(record))

    # records = loggernet.data_query('__statistics__', 'draker_dealer-dot-com_std', '20170602', '20170603')
    records = loggernet.data_query('__statistics__', 'sunwize_aspa-tafuna-10_std', '20170602', '20170603')

    for record in records:
        logger.info('{}'.format(record))

    # logger.info('{}'.format(loggernet.list_tables('__statistics__')))
    # logger.info('{}'.format(loggernet.list_files('draker_')))

    # table_list = loggernet.list_tables('draker')
    # logger.info('{}'.format(table_list))
    # try:
    #     table_list.remove('Public')
    # except ValueError:
    #     raise
    # finally:
    #     logger.info('{}'.format(table_list))

    # # test for getValue
    # logger.info('{}'.format(loggernet.getValue(station_name, '.Status.DataFillDays(' + str(1) + ')')))
