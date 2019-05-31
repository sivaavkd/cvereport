from feeds.data_2019 import setData2019_js
from feeds.data_2018 import setData2018_js
from os import popen
import consts


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


def getNPMpkgcheck():
    return 'npm search --json ', '', '[{"name":"', '"'
    # return 'curl "http://npmsearch.com/query?q=', '"', '{"results":[]', ''


def createpkgjsonFiles(packages, versions, pkgfolder):
    pkgjson = open(pkgfolder + '/package.json', "w+")
    pkgcmdPrefix, pkgcmdSuffix, pkgFindPrefix, pkgFindSuffix = getNPMpkgcheck()
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
    # print('Start Time, End Time: ', timeStart, consts.getDate(True))
