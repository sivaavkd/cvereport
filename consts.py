import datetime


def getAccessToken():
    return "YOUR KEY"


def getRepoName():
    return "fabric8-analytics/cvedb"


def getToday():
    return datetime.datetime(datetime.datetime.today().year, datetime.datetime.today().month, datetime.datetime.today().day)


def getNextday(thisDay):
    return thisDay + datetime.timedelta(days=1)


def bMergeCount():
    return False


def printHelpText():
    print("Usage: Run the program without any arguments and data will be for today")
    print("Pass FromDate ONLY to get data for a particular date")
    print("Pass FromDate and ToDate to get data between two dates")
    print("------------------------------------------------------")
    print("Example 1: python3 cvereport.py (returns the open and closed CVEs today)")
    print("Example 2: python3 cvereport.py 2019-05-01 (returns open and closed CVEs on 1st May 2019)")
    print("Example 3: python3 cvereport.py 2019-05-01 2019-05-03 (returns open and closed CVEs from 1st May to 3rd May including both days)")


def printCVEText(javacves1, npmcves1, pythoncves1, javacves2, npmcves2, pythoncves2, mergedcves):
    print("OPEN CVE information")
    print("Java -", len(javacves1))
    print("Node -", len(npmcves1))
    print("Pypi -", len(pythoncves1))
    print("--------------")
    print("CLOSED CVE information")
    print("Java -", len(javacves2))
    print("Node -", len(npmcves2))
    print("Pypi -", len(pythoncves2))
    if (bMergeCount()):
        print("--------------")
        print("Merged CVEs", len(mergedcves))
