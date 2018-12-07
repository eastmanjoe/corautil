#!/usr/bin/env python

"""
LoggerNet Settings that can be changed via cora
"""


class LgrNetSettings(object):
    Settings = {
        'applicationDir': 25,
        'allowRemoteTasksAdmin': 28,
        'autoBackupEnabled': 16,
        'autoBackupBase': 17,
        'autoBackupInterval': 18,
        'autoBackupIncludeCache': 19,
        'autoBackupExtraPaths': 20,
        'autoBackupPath': 21,
        'autoBackupBaleCount': 22,
        'bmp1ComputerId': 6,
        'checkPassWd': 8,
        'commEnabled': 7,
        'commsSettings': 3,
        'cqrSettings': 15,
        'defaultClockSchedule': 29,
        'defaultCollectPortsAndFlags': 45,
        'defaultCollectSchedule': 30,
        'defaultCollectViaAdvise': 35,
        'defaultCsixmlFormatOptions': 62,
        'defaultCustomCsvFormatOptions': 58,
        'defaultDataFileOutputName': 52,
        'defaultDataFileOutputOption': 51,
        'defaultDeleteFilesAfterSynch': 44,
        'defaultDoHoleCollect': 33,
        'defaultFileSynchControlEx': 43,
        'defaultFileSynchMode': 40,
        'defaultFileSynchScheduleBase': 41,
        'defaultFileSynchScheduleInterval': 42,
        'defaultFsArraysToCollectOnFirstPoll': 49,
        'defaultFsCollectAllOnFirstPoll': 48,
        'defaultFsCollectMode': 47,
        'defaultFsMaxArraysToPoll': 50,
        'defaultFsOutputFormat': 46,
        'defaultHoleAdditionEnabled': 34,
        'defaultMaxCacheTableSize': 38,
        'defaultNohFormatOptions': 61,
        'defaultPollForStatistics': 65,
        'defaultRescheduleOnData': 36,
        'defaultSecondaryCollectScheduleEnabled': 31,
        'defaultStayOnCollectSchedule': 32,
        'defaultTableCollectAllOnFirstPoll': 54,
        'defaultTableCollectMode': 53,
        'defaultTableDefsPolicy': 37,
        'defaultTableFileFormat': 57,
        'defaultTableFileStationNameSelector': 63,
        'defaultTableMaxIntervalToPoll': 69,
        'defaultTableMaxRecordsToPoll': 56,
        'defaultTableRecordsToCollectOnFirstPoll': 55,
        'defaultTableSizeFactor': 39,
        'defaultToa5FormatOptions': 59,
        'defaultTob1FormatOptions': 60,
        'dirSeparator': 26,
        'ipManagerUdpPort': 13,
        'ipManagerKey': 14,
        'lowSettings': 5,
        'maxDataFileSize': 64,
        'minConfigRewriteInterval': 23,
        'pakbusComputerId': 11,
        'scheduledOn': 1,
        'stateSettings': 4,
        'systemClk': 9,
        'tranSettings': 2,
        'useGlobalPakbusRouter': 12,
        'userNotes': 27,
        'workingDir': 24
    }

    def __init__(self, setting):
        self.value = LgrNetSettings.Settings[setting]

    def __int__(self):
        return self.value
