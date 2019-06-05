import github
import ghtoken
import consts
import sys
import os


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


def getFilesList(pkgFileName):
    fileList = []
    pkglockFileName = pkgFileName.split('.json')[0] + '-lock' + '.json'
    npmauditFileName = pkgFileName.split(consts.getPkgFileName())[
        0] + 'npmaudit.json'
    fileList.append(pkgFileName)
    fileList.append(pkglockFileName)
    fileList.append(npmauditFileName)
    return fileList


def createGHFiles(ghorg, reponame, fileNames):
    ghrepo = ghorg.create_repo(reponame)
    print('repo ', reponame, ' created')
    for fileName in fileNames:
        with open(fileName, 'rb') as input_file:
            filedata = input_file.read()
        ghrepo.create_file(fileName, consts.getCommitMsg(), filedata)
    print('files pushed')


def deleteAllRepos(ghorg):
    ghrepos = ghorg.get_repos()
    for ghrepo in ghrepos:
        ghrepo.delete()
    print('flushed out all repos')


def npm_createGHRepos(repos, files):
    ACCESS_TOKEN = ghtoken.getAccessToken()
    myGitHub = github.Github(ACCESS_TOKEN)
    ghorg = myGitHub.get_organization(consts.getRepoName(True))
    deleteAllRepos(ghorg)
    for i in range(len(repos)):
        createGHFiles(ghorg, repos[i], getFilesList(files[i]))
