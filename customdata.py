from feeds.data_2019 import setData2019_js
from feeds.data_2018 import setData2018_js
from os import popen, chdir
import consts
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


def getNPMpkgcheckCmd():
    return 'npm search --json ', '', '[{"name":"', '"'
    # return 'curl "http://npmsearch.com/query?q=', '"', '{"results":[]', ''


def getnpmauditCmd():
    return 'npm i --package-lock-only', 'npm audit --json'


def createpkgjsonFiles(packages, versions, pkgfolder):
    if pkgfolder != '':
        chdir(pkgfolder)
    pkgjson = open('package.json', "w+")
    pkgcmdPrefix, pkgcmdSuffix, pkgFindPrefix, pkgFindSuffix = getNPMpkgcheckCmd()
    pkgjson.write('{\n\t"dependencies": {\n')
    timeStart = consts.getDate(True)
    for i in range(len(packages)):
        print('Checking ' + packages[i])
        checkpkg = popen(pkgcmdPrefix + packages[i] + pkgcmdSuffix).read()
        if checkpkg.find(pkgFindPrefix + packages[i] + pkgFindSuffix) != -1:
            pkgjson.write('\t\t"' + packages[i] + '": "' + versions[i] + '"')
            if i != len(packages)-1:
                pkgjson.write(',')
            pkgjson.write('\n')
    pkgjson.write('\t}\n}')
    return pkgjson.name
    # return 'package.json'


def packageLockExits():
    return False


def runnpmaudit(pkgjsonfile):
    cvesfound = []
    pkglockcmd, auditcmd = getnpmauditCmd()
    if packageLockExits() == False:
        print('Generating package lock file...')
        pkglocktext = popen(pkglockcmd).read()
    print('Running npm audit...')
    auditresult = json.loads(popen(auditcmd).read())
    for audititem in auditresult['advisories']:
        for cveitem in auditresult['advisories'][audititem]['cves']:
            cvesfound.append(cveitem)
    return cvesfound


def runDA(packages, versions):
    return []
