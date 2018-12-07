#!/usr/bin/env python

"""
Utilities used in the module
"""

import re
from logging import getLogger
import os

from corautil.errors import CoraError


def format_cora_backup_scripts(filename):
    """
    remove tabs, extra spaces and extraneous new-lines in
    create-backup-script's created by cora

    :param filename: cora backup script to format
    :type filename: str
    :return
    """

    buffer_str = ""
    parsed_file = []

    with open(filename, 'r') as fid:
        for line in fid:
            # remove the line endings
            line = line.rstrip()

            # remove whitespace
            line = re.sub(r'\s+', ' ', line)
            # strip spaces that at the end of the line
            line = line.rstrip(' ')
            # if the cora command is already on a single line just append it to the list
            if line.endswith(';') and buffer_str == "":
                parsed_file.append(line)

            # finish building the cora command and append it to the list when the semi-colon is found
            elif line.endswith(';') and buffer_str != "":
                buffer_str += ' ' + line
                parsed_file.append(buffer_str)
                buffer_str = ""

            # start building the cora command if the line does not contain a semi-colon
            else:
                # append a space to the line if this is not the first line
                if buffer_str != "":
                    buffer_str += ' '

                buffer_str += line

    with open(filename, 'w') as fid:
        fid.write('\n'.join(parsed_file))

    return parsed_file


def remove_quotes(str_list):
    if type(str_list) is list:
        for index, line in enumerate(str_list):
            line = re.sub(r'"', '', line)
            str_list[index] = line

    return str_list


def extract_data(str, command):
    logger = getLogger('corautil.extract_data')

    resp_regex = re.compile(
        r"\{\s(?P<response>.+|\B)\s\}",
        # r"\*" + command + r"(?:\s|,active\s|,ignore\s)\{\s(?P<response>.+|\B)\s\}\s",
        flags=re.DOTALL
    )
    response = resp_regex.search(str)
    if response is not None:
        logger.debug(response.group('response'))

        return response.group('response').strip().split('\n')
