import github
import consts
import sys
from dateutil import parser
import utils
import ghutils

CVE_DATE = consts.getToday()
CVE_TO_DATE = consts.getNextday(CVE_DATE)


def getArgs():
    global CVE_DATE
    global CVE_TO_DATE
    arguments = sys.argv[1:]
    if (len(arguments) > 0):
        if (arguments[0] == "help" or arguments[0] == "h" or arguments[0] == "-help" or arguments[0] == "-h"):
            consts.printHelpText()
            sys.exit(1)
        try:
            CVE_DATE = parser.parse(arguments[0])
            if (len(arguments) == 2):
                CVE_TO_DATE = consts.getNextday(parser.parse(arguments[1]))
            else:
                CVE_TO_DATE = consts.getNextday(CVE_DATE)
        except:
            consts.printHelpText()
            sys.exit(1)


def getData():
    cveDbRepo = ghutils.getGHRepo()
    print("Reading CVE information of", cveDbRepo.full_name, "from Github")
    cveData = cveDbRepo.get_issues(
        "none", "all", "none", github.GithubObject.NotSet, "", "", "", CVE_DATE)
    return cveData


def appendCVEs(cveItem, npmcves, javacves, pythoncves):
    if cveItem.title.find("javascript") > 0:
        npmcves.append(cveItem)
    elif cveItem.title.find("java") > 0:
        javacves.append(cveItem)
    elif cveItem.title.find("python") > 0:
        pythoncves.append(cveItem)


def printCVEInfo(cveList, fromDate, ToDate):
    javacves1 = []
    npmcves1 = []
    pythoncves1 = []
    javacves2 = []
    npmcves2 = []
    pythoncves2 = []
    mergedcves = []
    for cveItem in cveList:
        if cveItem.created_at is not None and cveItem.created_at >= fromDate and cveItem.created_at <= ToDate:
            appendCVEs(cveItem, npmcves1, javacves1, pythoncves1)
        if cveItem.closed_at is not None and cveItem.closed_at >= fromDate and cveItem.closed_at <= ToDate:
            appendCVEs(cveItem, npmcves2, javacves2, pythoncves2)
        if consts.bMergeCount():
            cvePull = cveItem.as_pull_request()
            if cvePull.merged_at is not None and cvePull.merged_at >= fromDate and cvePull.merged_at <= ToDate:
                mergedcves.append(cveItem)
    consts.printCVEText(javacves1, npmcves1, pythoncves1,
                        javacves2, npmcves2, pythoncves2, mergedcves)


getArgs()
cveInfo = getData()
if cveInfo is not None:
    printCVEInfo(cveInfo, CVE_DATE, CVE_TO_DATE)
