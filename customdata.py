from feeds.data_2019 import setData2019_js
from feeds.data_2018 import setData2018_js
import os
import consts
import utils
import gremlin
from re import finditer
import json


def getCustomData(datayear, ecosystem, alldata=False):
    data = []
    if datayear == 2019:
        if ecosystem == 'javascript':
            data = setData2019_js(alldata)
        elif ecosystem == 'java':
            data = setData2019_js(alldata)
        elif ecosystem == 'python':
            data = setData2019_js(alldata)
    elif datayear == 2018:
        if ecosystem == 'javascript':
            data = setData2018_js(alldata)
        elif ecosystem == 'java':
            data = setData2018_js(alldata)
        elif ecosystem == 'python':
            data = setData2018_js(alldata)
    return data


def createpkgjsonFile(packages, versions, pkgfolder):
    pkgFileName = consts.getPkgFileName()
    utils.changeDirectory(pkgfolder)
    if os.path.isfile(pkgFileName):
        print(
            'Package.json already exists, skipping the file creation and package name validation steps...')
        return pkgFileName
    pkgjson = open(pkgFileName, "w+")
    pkgcmdPrefix, pkgcmdSuffix, pkgFindPrefix, pkgFindSuffix = consts.getNPMpkgcheckCmd()
    pkgjson.write('{\n\t"dependencies": {\n')
    timeStart = consts.getDate(True)
    for i in range(len(packages)):
        print('Checking ' + packages[i])
        checkpkg = os.popen(pkgcmdPrefix + packages[i] + pkgcmdSuffix).read()
        if checkpkg.find(pkgFindPrefix + packages[i] + pkgFindSuffix) != -1:
            pkgjson.write('\t\t"' + packages[i] + '": "' + versions[i] + '"')
            if i != len(packages)-1:
                pkgjson.write(',')
            pkgjson.write('\n')
        else:
            del packages[i]
            del versions[i]
    pkgjson.write('\t}\n}')
    return pkgjson.name
    # return 'package.json'


def createMultiplePkgFiles(packages, versions, pkgfolder):
    pkgjsonFiles = []
    utils.changeDirectory(pkgfolder)
    timeStart = consts.getDate(True)
    for i in range(len(packages)):
        dirName = 'pkgfolder' + str(i)
        if not os.path.exists(dirName):
            os.mkdir(dirName)
        print('creating file in: ', dirName)
        pkgjson = open(dirName + '/package.json', "w+")
        pkgcmdPrefix, pkgcmdSuffix, pkgFindPrefix, pkgFindSuffix = consts.getNPMpkgcheckCmd()
        pkgjson.write('{\n\t"dependencies": {\n')
        pkgjson.write('\t\t"' + packages[i] + '": "' + versions[i] + '"')
        pkgjson.write('\n')
        pkgjson.write('\t}\n}')
        pkgjsonFiles.append(pkgjson.name)
    return pkgjsonFiles


def packageLockExits():
    return False


def runnpmaudit(pkgjsonfolder, createAuditReport=False):
    utils.changeDirectory(pkgjsonfolder)
    cvesfound = []
    pkglockcmd, auditcmd = consts.getnpmauditCmd()
    if packageLockExits() == False:
        print('Generating package lock file...')
        pkglocktext = os.popen(pkglockcmd).read()
    print('Running npm audit...')
    auditresult = json.loads(os.popen(auditcmd).read())
    for audititem in auditresult['advisories']:
        for cveitem in auditresult['advisories'][audititem]['cves']:
            cvesfound.append(cveitem)
    if createAuditReport:
        with open(consts.getNPMAuditReportName(), 'w') as outfile:
            json.dump(auditresult, outfile, indent=4)
    return cvesfound


def runAllnpmaudits(pkgjsonFileList):
    for i in range(len(pkgjsonFileList)):
        cvesfound = runnpmaudit(pkgjsonFileList[i].split('/')[0], True)
    return cvesfound


def runDA(ecosys, packages, versions):
    for i in range(len(packages)):
        print(gremlin.fetch_cve_ids(ecosys, packages[i], versions[i]))
    return []
