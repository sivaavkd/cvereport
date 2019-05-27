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
        return utils.getCVEData(CVE_YEAR)
    except:
        print("Please make sure you have the NVD feed (json) in feeds folder.  You can download from https://nvd.nist.gov/vuln/data-feeds")
        exit(1)


def getDBData(repo):
    try:
        return utils.getCVEContent(repo, CVE_YEAR)
    except:
        print("Error while reading data from repo.")
        exit(1)


def compareCVEData(nvd_data, repo_data):
    print('Compare CVE Data')
    print('Our repo has the following CVE data for ' + str(CVE_YEAR))
    print(repo_data)
    print('NVD data for ' + str(CVE_YEAR))
    print(nvd_data)


getArgs()
cveDbRepo = utils.getGHRepo()
cveDBData = getDBData(cveDbRepo)
nvdData = getNVDData()
compareCVEData(nvdData, cveDBData)
