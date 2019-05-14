import github
import consts
import sys
from dateutil import parser

CVE_DATE = consts.getToday()
# CVE_DATE = datetime.datetime(2019,4,14)
# CVE_TO_DATE = datetime.datetime(2019,4,11)
CVE_TO_DATE = consts.getNextday(CVE_DATE)

def getArgs():
    global CVE_DATE
    global CVE_TO_DATE
    arguments = sys.argv[1:]
    if (len(arguments)>0):
        if (arguments[0]=="help" or arguments[0]=="h" or arguments[0]=="-help" or arguments[0]=="-h"):
            consts.printHelpText()
            sys.exit(1)
        CVE_DATE = parser.parse(arguments[0])
        if (len(arguments)==2):
            CVE_TO_DATE = consts.getNextday(parser.parse(arguments[1]))
        else:
            CVE_TO_DATE = consts.getNextday(CVE_DATE)

def getData():
    ACCESS_TOKEN = consts.getAccessToken()
    REPO_NAME = consts.getRepoName()
    myGitHub = github.Github(ACCESS_TOKEN)
    cveDbRepo = myGitHub.get_repo(REPO_NAME)
    print ("Reading CVE information of", cveDbRepo.full_name , "from Github")
    cveData = cveDbRepo.get_issues("none","all","none",github.GithubObject.NotSet,"","","", CVE_DATE)
    return cveData

def printCVEInfo(cveList,fromDate,ToDate):
    javacves1 = []
    npmcves1 = []
    pythoncves1 = []
    javacves2 = []
    npmcves2 = []
    pythoncves2 = []
    mergedcves = []
    for cveItem in cveList:
        if cveItem.created_at is not None and cveItem.created_at >= fromDate and cveItem.created_at <= ToDate:
            if cveItem.title.find("javascript") > 0:
                npmcves1.append(cveItem)
            elif cveItem.title.find("java") > 0:
                javacves1.append(cveItem)
            elif cveItem.title.find("python") > 0:
                pythoncves1.append(cveItem)
        if cveItem.closed_at is not None and cveItem.closed_at >= fromDate and cveItem.closed_at <= ToDate:
            if cveItem.title.find("javascript") > 0:
                npmcves2.append(cveItem)
            elif cveItem.title.find("java") > 0:
                javacves2.append(cveItem)
            elif cveItem.title.find("python") > 0:
                pythoncves2.append(cveItem)
        cvePull = cveItem.as_pull_request()
        if cvePull.merged_at is not None and cvePull.merged_at >= fromDate and cvePull.merged_at <= ToDate:
            mergedcves.append(cveItem)
    print("OPEN CVE information")
    print ("Java -", len(javacves1))
    print ("Node -", len(npmcves1))
    print ("Pypi -",len(pythoncves1))
    print ("--------------")
    print("CLOSED CVE information")
    print ("Java -", len(javacves2))
    print ("Node -", len(npmcves2))
    print ("Pypi -",len(pythoncves2))
    print ("--------------")
    print("Merged CVEs",len(mergedcves))
getArgs()
cveInfo = getData()
if cveInfo is not None:
    printCVEInfo(cveInfo,CVE_DATE,CVE_TO_DATE)
