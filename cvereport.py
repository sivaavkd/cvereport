import github
import datetime
import consts
ACCESS_TOKEN = consts.getAccessToken()
REPO_NAME = consts.getRepoName()
CVE_DATE = datetime.datetime(datetime.datetime.today().year,datetime.datetime.today().month,datetime.datetime.today().day)
# CVE_DATE = datetime.datetime(2019,4,14)
# CVE_TO_DATE = datetime.datetime(2019,4,11)
CVE_TO_DATE = CVE_DATE + datetime.timedelta(days=1)
myGitHub = github.Github(ACCESS_TOKEN)
cveDbRepo = myGitHub.get_repo(REPO_NAME)
print ("Reading CVE information of", cveDbRepo.full_name , "from Github")
cveData = cveDbRepo.get_issues("none","all","none",github.GithubObject.NotSet,"","","", CVE_DATE)

def printCVEInfo(cveList):
    javacves1 = []
    npmcves1 = []
    pythoncves1 = []
    javacves2 = []
    npmcves2 = []
    pythoncves2 = []
    for cveItem in cveList:
        if cveItem.created_at is not None and cveItem.created_at >= CVE_DATE and cveItem.created_at <= CVE_TO_DATE:
            if cveItem.title.find("javascript") > 0:
                npmcves1.append(cveItem)
            elif cveItem.title.find("java") > 0:
                javacves1.append(cveItem)
            elif cveItem.title.find("python") > 0:
                pythoncves1.append(cveItem)
        if cveItem.closed_at is not None and cveItem.closed_at >= CVE_DATE and cveItem.closed_at <= CVE_TO_DATE:
            if cveItem.title.find("javascript") > 0:
                npmcves2.append(cveItem)
            elif cveItem.title.find("java") > 0:
                javacves2.append(cveItem)
            elif cveItem.title.find("python") > 0:
                pythoncves2.append(cveItem)
    print("OPEN CVE information")
    print ("Java -", len(javacves1))
    print ("Node -", len(npmcves1))
    print ("Pypi -",len(pythoncves1))
    print ("--------------")
    print("CLOSED CVE information")
    print ("Java -", len(javacves2))
    print ("Node -", len(npmcves2))
    print ("Pypi -",len(pythoncves2))
    
printCVEInfo(cveData)
