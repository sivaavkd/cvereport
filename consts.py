import datetime

def getAccessToken():
    return "YOUR KEY"

def getRepoName():
    return "fabric8-analytics/cvedb"

def getToday():
    return datetime.datetime(datetime.datetime.today().year,datetime.datetime.today().month,datetime.datetime.today().day)

def getNextday(thisDay):
    return thisDay + datetime.timedelta(days=1)