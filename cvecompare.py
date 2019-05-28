import github
import consts
import sys
import utils

CVE_YEAR = consts.getToday().year


def getArgs():
    global CVE_YEAR
    arguments = sys.argv[1:]
    if (len(arguments) > 0):
        if (arguments[0] == "help" or arguments[0] == "h" or arguments[0] == "-help" or arguments[0] == "-h"):
            consts.printHelpText()
            sys.exit(1)
        try:
            CVE_YEAR = arguments[0]
        except:
            consts.printHelpText()
            sys.exit(1)


def getNVDData():
    try:
        return utils.getCVEdataNVD(CVE_YEAR)
    except:
        print(
            'Please make sure you have the NVD feed (json) in feeds folder for the year', CVE_YEAR, '. You can download feeds from https://nvd.nist.gov/vuln/data-feeds')
        exit(1)


def getDBData(repo):
    try:
        return utils.getCVEdataRepo(repo, CVE_YEAR)
    except:
        print("Error while reading data from repo.")
        exit(1)


getArgs()
cveDbRepo = utils.getGHRepo()
cveDBData = getDBData(cveDbRepo)
nvdData = getNVDData()
consts.printNVDrepo(nvdData, cveDBData, CVE_YEAR)
