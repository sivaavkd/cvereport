import github
import consts
import sys
import utils
from dateutil import parser
import customdata

CVE_YEAR = consts.getToday().year


def getArgs():
    global CVE_YEAR
    arguments = sys.argv[1:]
    if (len(arguments) > 0):
        if (arguments[0] == "help" or arguments[0] == "h" or arguments[0] == "-help" or arguments[0] == "-h"):
            consts.printHelpText()
            sys.exit(1)
        try:
            CVE_YEAR = parser.parse(arguments[0]).year
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


getArgs()
repodata = getRepoData()
nvddata = getNVDData()
consts.printNVDrepo(nvddata, repodata, CVE_YEAR)

# eco_system = 'javascript'
# npmrepo_data = getRepoData(eco_system)
# custom_data = customdata.getCustomData(CVE_YEAR, eco_system)
# consts.printComparison(custom_data, npmrepo_data, CVE_YEAR, eco_system)
# print('')
# print('CVES to manually review are as below:')
# print(utils.getDiffList(custom_data, npmrepo_data))
