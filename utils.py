import consts
import github
import json
import sys
import os
import ghtoken


def getGHRepo():
    try:
        ACCESS_TOKEN = ghtoken.getAccessToken()
        REPO_NAME = consts.getRepoName()
        myGitHub = github.Github(ACCESS_TOKEN)
        cveDbRepo = myGitHub.get_repo(REPO_NAME)
        print("Reading CVE information of", cveDbRepo.full_name, "from Github")
        return cveDbRepo
    except:
        print("Error while reading Github data.  Please make sure you have a working access token in getAccessToken() of consts.py")
        sys.exit(1)


def getNVDfileName(fileyear):
    return consts.getFolderName() + '/nvdcve-1.0-' + str(fileyear) + '.json'


def getStackfileName(filedate):
    return consts.getFolderName() + '/stkrpt_' + str(filedate) + '.json'


def getCVElist(repoContent, year):
    cvelist = []
    # looping through each file name within an ecosystem specific directory in cvedb gh repo
    for cveFile in repoContent:
        # in the Filename with full path, find the subfolder of the year
        ymlLoc = str(cveFile).find(str(year) + '/')
        if ymlLoc > 0:
            # construct CVE_ID using the filename in CVE-YEAR-ID format
            cvelist.append(
                'CVE-' + str(year) + '-' + str(cveFile)[ymlLoc+len(str(year))+1:len(str(cveFile))-7])
    return cvelist


def getCVEdataRepo(repo, year, ecosystem='all'):
    cveFiles = []
    # read directory contents of each ecosystem as per the gh repo structure of cvedb
    cveContentJava = repo.get_dir_contents(
        'database/java/' + str(year))
    cveContentJS = repo.get_dir_contents(
        'database/javascript/' + str(year))
    cveContentPython = repo.get_dir_contents(
        'database/python/' + str(year))
    if ecosystem == 'all' or ecosystem == 'java':
        cveFiles.extend(getCVElist(cveContentJava, year))
    if ecosystem == 'all' or ecosystem == 'javascript':
        cveFiles.extend(getCVElist(cveContentJS, year))
    if ecosystem == 'all' or ecosystem == 'python':
        cveFiles.extend(getCVElist(cveContentPython, year))
    return cveFiles


def getCVEdataNVD(year):
    cveIDs = []
    print('Reading CVE information from NVD feed')
    with open(getNVDfileName(year)) as cveFile:
        cveData = json.load(cveFile)
        for cveitem in cveData["CVE_Items"]:
            for cveitemkey, cveitemval in cveitem.items():
                # CVE_Items is an array, not a JSON - and hence, needs a different way of handling
                if (cveitemkey == "cve"):
                    for cvekey, cveval in cveitemval.items():
                        if (cvekey == "CVE_data_meta"):
                            cveIDs.append(cveval["ID"])
    return cveIDs


def getDiffList(nvd_data, repo_data):
    return list(set(nvd_data)-set(repo_data))


def getStackData(ecosystem, cvedate):
    packageNames = []
    packageVersions = []
    print('Reading package information from stack file')
    with open(getStackfileName(cvedate)) as stackFile:
        stackData = json.load(stackFile)
    for package in stackData["stacks_summary"]["npm"]["unique_dependencies_with_frequency"]:
        packageNames.append(str(package).split(' ')[0])
        packageVersions.append(str(package).split(' ')[1])
    return packageNames, packageVersions


def changeDirectory(dirName):
    currDir = os.getcwd()
    print(currDir)
    if not currDir.endswith('/' + dirName) and dirName != '':
        if currDir.find('pkgfolder') >= 0:
            os.chdir('..')
        print(os.getcwd())
        os.chdir(dirName)
