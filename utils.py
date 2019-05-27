import consts
import github
import json


def getGHRepo():
    ACCESS_TOKEN = consts.getAccessToken()
    REPO_NAME = consts.getRepoName()
    myGitHub = github.Github(ACCESS_TOKEN)
    cveDbRepo = myGitHub.get_repo(REPO_NAME)
    print("Reading CVE information of", cveDbRepo.full_name, "from Github")
    return cveDbRepo


def getCVEdataFileName(year):
    return 'feeds/nvdcve-1.0-' + str(year) + '.json'


def getCVEs(ecosystemContent, year, cvelist):
    for cveFile in ecosystemContent:
        ymlLoc = str(cveFile).find(str(year) + '/')
        if ymlLoc > 0:
            cvelist.append(
                'CVE-' + str(year) + '-' + str(cveFile)[ymlLoc+len(str(year))+1:len(str(cveFile))-7])
    return cvelist


def getCVEContent(repo, year):
    cveFiles = []
    cveContentJava = repo.get_dir_contents(
        'database/java/' + str(year))
    cveContentJS = repo.get_dir_contents(
        'database/javascript/' + str(year))
    cveContentPython = repo.get_dir_contents(
        'database/python/' + str(year))
    getCVEs(cveContentJava, year, cveFiles)
    getCVEs(cveContentJS, year, cveFiles)
    getCVEs(cveContentPython, year, cveFiles)
    return json.dumps(cveFiles)


def getCVEData(year):
    cveIDs = []
    with open(getCVEdataFileName(year)) as cveFile:
        cveData = json.load(cveFile)
        for cveitem in cveData["CVE_Items"]:
            for cveitemkey, cveitemval in cveitem.items():
                if (cveitemkey == "cve"):
                    for cvekey, cveval in cveitemval.items():
                        if (cvekey == "CVE_data_meta"):
                            cveIDs.append(cveval["ID"])
    return json.dumps(cveIDs)
