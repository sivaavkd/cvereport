from feeds.data_2019 import setData2019_js, setData2019_py
from feeds.data_2018 import setData2018_js, setData2018_py
from feeds.data_2017 import setData2017_js, setData2017_py
import os
import consts
import utils
import ghutils
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
            data = setData2019_py(alldata)
    elif datayear == 2018:
        if ecosystem == 'javascript':
            data = setData2018_js(alldata)
        elif ecosystem == 'java':
            data = setData2018_js(alldata)
        elif ecosystem == 'python':
            data = setData2018_py(alldata)
    elif datayear == 2017:
        if ecosystem == 'javascript':
            data = setData2017_js(alldata)
        elif ecosystem == 'java':
            data = setData2017_js(alldata)
        elif ecosystem == 'python':
            data = setData2017_py(alldata)
    return data


def createpkgjsonFile(packagesList, versionsList, pkgfolder, cvedate):
    pkgsToRemove = []
    pkgfolder = pkgfolder + '/pkgfolder_' + str(cvedate)
    if not os.path.exists(pkgfolder):
        os.mkdir(pkgfolder)
    pkgFileName = pkgfolder + '/' + consts.getPkgFileName()
    if os.path.isfile(pkgFileName):
        print(
            'Package.json already exists, Reading it...')
        with open(pkgFileName) as pkgFile:
            pkgData = json.load(pkgFile)
        packagesList = []
        versionsList = []
        for pkginfo, verinfo in pkgData["dependencies"].items():
            packagesList.append(pkginfo)
            versionsList.append(verinfo)
        return packagesList, versionsList
    pkgjson = open(pkgFileName, "w+")
    pkgcmdPrefix, pkgcmdSuffix, pkgFindPrefix, pkgFindSuffix = consts.getNPMpkgcheckCmd()
    pkgjson.write('{\n\t"dependencies": {\n')
    timeStart = consts.getDate(True)
    for i in range(len(packagesList)):
        print('Checking ' + packagesList[i])
        checkpkg = os.popen(
            pkgcmdPrefix + packagesList[i] + pkgcmdSuffix).read()
        if checkpkg.find(pkgFindPrefix + packagesList[i] + pkgFindSuffix) != -1:
            pkgjson.write(
                '\t\t"' + packagesList[i] + '": "' + versionsList[i] + '"')
            if i != len(packagesList)-1:
                pkgjson.write(',')
            pkgjson.write('\n')
        else:
            pkgsToRemove.append(i)
    pkgjson.write('\t}\n}')
    for i in pkgsToRemove[::-1]:
        del packagesList[i]
        del versionsList[i]
    return packagesList, versionsList


def createMultiplePkgFiles(packages, versions, pkgfolder, cvedate):
    pkgjsonFiles = []
    pkgjsonFolders = []
    # bChangedDir = utils.changeDirectory(pkgfolder)
    timeStart = consts.getDate(True)
    dirName = consts.getFolderName() + '/pkgfolder_' + str(cvedate)
    pkgjsonName = dirName + '/' + consts.getPkgFileName()
    pkgjsonFiles.append(pkgjsonName)
    pkgjsonFolders.append(dirName)
    for i in range(len(packages)):
        dirName = consts.getFolderName() + '/pkgfolder_' + str(i) + '_' + str(cvedate)
        if not os.path.exists(dirName):
            os.mkdir(dirName)
        pkgjson = open(dirName + '/' + consts.getPkgFileName(), "w+")
        pkgcmdPrefix, pkgcmdSuffix, pkgFindPrefix, pkgFindSuffix = consts.getNPMpkgcheckCmd()
        pkgjson.write('{\n\t"dependencies": {\n')
        pkgjson.write('\t\t"' + packages[i] + '": "' + versions[i] + '"')
        pkgjson.write('\n')
        pkgjson.write('\t}\n}')
        pkgjsonFiles.append(pkgjson.name)
        pkgjsonFolders.append(dirName)
    return pkgjsonFolders, pkgjsonFiles


def packageLockExits():
    return False


def runnpmaudit(pkgjsonfolder, cvedate, createAuditReport=True):
    bChangedDir = utils.changeDirectory(pkgjsonfolder)
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
    if bChangedDir:
        utils.MoveUpDir()
        utils.MoveUpDir()
    return cvesfound


def runAllnpmaudits(pkgjsonFileList, cvedate):
    for i in range(len(pkgjsonFileList)):
        cvesfound = runnpmaudit(pkgjsonFileList[i].split(
            '/' + consts.getPkgFileName())[0], cvedate)
    return cvesfound


def runDA(ecosys, packages, versions):
    for i in range(len(packages)):
        print(gremlin.fetch_cve_ids(ecosys, packages[i], versions[i]))
    return []


def npm_stack_cvedb_compare(packagedata, versiondata, cvedate):
    ecosystem = consts.Ecosystem.JAVASCRIPT.value
    packages, versions = createpkgjsonFile(
        packagedata, versiondata, consts.getFolderName(), cvedate)
    # pkgjsonFolderList, pkgjsonFileList = createMultiplePkgFiles(
    #     packages, versions, consts.getFolderName(), cvedate)
    npmcves = runnpmaudit(consts.getFolderName() +
                          '/pkgfolder_' + str(cvedate), cvedate)
    # npmcves = runAllnpmaudits(pkgjsonFileList, cvedate)
    # ghutils.npm_createGHRepos(pkgjsonFolderList, pkgjsonFileList)
    print('CVEs that are shown in npm audit are:')
    print(npmcves)
