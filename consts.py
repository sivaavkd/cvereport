import datetime
from enum import Enum


class ComparisonType(Enum):
    NVD_CVEDB_ALL = 1
    NVD_CVEDB_ECO = 2
    CUSTOM_CVEDB_ALL = 3
    CUSTOM_CVEDB_ECO = 4
    STACK_CVEDB_ALL = 5
    STACK_CVEDB_ECO = 6


class Ecosystem(Enum):
    JAVA = 'java'
    JAVASCRIPT = 'javascript'
    PYTHON = 'python'
    GOLANG = 'go'


def getRepoName():
    return "fabric8-analytics/cvedb"


def getFolderName():
    return 'feeds'


def getDate(includetime=False, thisyear=0, thismonth=0, thisday=0):
    if thisyear == 0:
        thisyear = datetime.datetime.today().year
    if thismonth == 0:
        thismonth = datetime.datetime.today().month
    if thisday == 0:
        thisday = datetime.datetime.today().day
    if includetime:
        return datetime.datetime.today()
    else:
        return datetime.date(thisyear, thismonth, thisday)


def getNextday(thisDay):
    return thisDay + datetime.timedelta(days=1)


def distinctList(mylist):
    return list(dict.fromkeys(mylist))


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


def printCompareHelp():
    print("Usage: Run the program without any arguments and data will be for this year")
    print("Pass Year to get data for a particular Year")
    print("Example 1: python3 cvecompare.py (comparision of CVE data of this year)")
    print("Example 2: python3 cvecompare.py 2018 (comparision of CVE data of 2018)")


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


def printNVDrepo(nvd_data, repo_data, year):
    print('cvedb repo has', len(repo_data), 'CVES for ' + str(year))
    print('NVD data has', len(nvd_data), 'CVES for ' + str(year))


def printComparison(master_data, repo_data, year, ecosystem):
    print('cvedb repo has', len(repo_data), 'CVES for ' +
          str(year) + ' for ecosystem: ' + ecosystem)
    print('Master dataset has', len(master_data), 'CVES for ' +
          str(year) + ' for ecosystem: ' + ecosystem)
