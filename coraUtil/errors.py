#!/usr/bin/env python

"""
Errors reported by the Cora commands
"""

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
        'unsupported by the server': 'The transaction is not supported by the server or by the device specified.',
        'Invalid Action code': 'The value of the action option is invalid.',
        'unknown error': 'The server sent a response code that corascript was unable to recognise.',
        'in progress': 'Another transaction is already in progress.',
        'rejected security code': 'The security code setting for the device is wrong.',
        'communication failure': 'Communication with the datalogger failed.',
        'network is locked': 'Another client has the network locked.',
        'communications disabled': 'Communication with the datalogger is disabled.',
        'Expected the setting identifier': 'Expected the setting identifier as the third argument.',
        'expected the setting value': 'Expected the new value for the setting as the fourth argument.',
        'server session broken': 'The server session was broken while this command was executing.',
        'unsuported transaction': 'One or more required transactions are not supported by the server.',
        'blocked by server security': 'The command could not execute because of server security.',
        'device is online':
            'The command cannot execute because the device (or one of its children) is on-line. Current '
            'versions of the server will force all of the effected devices off-line.',
        'Invalid value name syntax': ''

    }

    def __init__(self, value):
        self.value = CoraError.FAILURES[value]

    def __str__(self):
        return self.value
