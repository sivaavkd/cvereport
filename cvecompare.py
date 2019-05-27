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


def compareCVEData(data, repo):
    print('Compare CVE Data')
    repoFiles = utils.getCVEContent(repo, CVE_YEAR)
    print('Our repo has the following CVE data for ' + str(CVE_YEAR))
    print(repoFiles)
    print('NVD data for ' + str(CVE_YEAR))
    print(data)


getArgs()
cveDbRepo = utils.getGHRepo()
cveData = utils.getCVEData(CVE_YEAR)
compareCVEData(cveData, cveDbRepo)
