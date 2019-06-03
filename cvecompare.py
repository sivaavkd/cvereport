import github
import consts
import sys
import utils
from dateutil import parser
import customdata

ECOSYSTEM = 'all'
COMPARE_TYPE = 1
CVE_DATE = consts.getDate()
CVE_YEAR = CVE_DATE.year


def getArgs():
    global CVE_YEAR
    global COMPARE_TYPE
    global ECOSYSTEM
    global CVE_DATE
    args = sys.argv[1:]
    if (len(args) > 0):
        if (args[0] == "help" or args[0] == "h" or args[0] == "-help" or args[0] == "-h"):
            consts.printHelpText()
            sys.exit(1)
        try:

            CVE_YEAR = parser.parse(args[0]).year
            CVE_DATE = consts.getDate(False, parser.parse(args[0]).year, parser.parse(
                args[0]).month, parser.parse(args[0]).day)
            if (len(args) > 1):
                COMPARE_TYPE = int(args[1])
            if (len(args) > 2):
                ECOSYSTEM = args[2].lower()
        except:
            consts.printCompareHelp()
            sys.exit(1)


def getNVDData():
    try:
        return utils.getCVEdataNVD(CVE_YEAR)
    except:
        print(
            'Please make sure you have the NVD feed (json) in feeds folder for the year', CVE_YEAR, '. You can download feeds from https://nvd.nist.gov/vuln/data-feeds')
        exit(1)


def getRepoData(ecosystem='all'):
    try:
        cveDbRepo = utils.getGHRepo()
        return utils.getCVEdataRepo(cveDbRepo, CVE_YEAR, ecosystem)
    except:
        print("Error while reading data from repo.")
        exit(1)


def printComparisonReport():
    if COMPARE_TYPE == 1:
        repodata = getRepoData()
        nvddata = getNVDData()
        consts.printNVDrepo(nvddata, repodata, CVE_YEAR)
    elif COMPARE_TYPE == 4:
        npmrepo_data = getRepoData(ECOSYSTEM)
        custom_data = customdata.getCustomData(CVE_YEAR, ECOSYSTEM)
        consts.printComparison(custom_data, npmrepo_data, CVE_YEAR, ECOSYSTEM)
        print('')
        print('CVEs to manually review are:')
        print(utils.getDiffList(custom_data, npmrepo_data))
    elif COMPARE_TYPE == consts.ComparisonType.STACK_CVEDB_ECO.value:
        packagedata, versiondata = utils.getStackData(ECOSYSTEM, CVE_DATE)
        if (ECOSYSTEM == consts.Ecosystem.JAVASCRIPT.value):
            pkgjsonfile = customdata.createpkgjsonFiles(
                packagedata, versiondata, consts.getFolderName())
            npmcves = customdata.runnpmaudit(pkgjsonfile)
            print('CVEs that are shown in npm audit are:')
            print(npmcves)
            dacves = customdata.runDA(packagedata, versiondata)


getArgs()
printComparisonReport()
