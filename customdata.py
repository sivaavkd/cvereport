from feeds.data_2019 import setData2019_js
from feeds.data_2018 import setData2018_js


def getCustomData(datayear, ecosystem, alldata=False):
    data = []
    if datayear == 2019:
        if ecosystem == 'javascript':
            data = setData2019_js(alldata)
        elif ecosystem == 'java':
            data = setData2019_js(alldata)
        elif ecosystem == 'python':
            data = setData2019_js(alldata)
        return data
    elif datayear == 2018:
        if ecosystem == 'javascript':
            data = setData2018_js(alldata)
        elif ecosystem == 'java':
            data = setData2018_js(alldata)
        elif ecosystem == 'python':
            data = setData2018_js(alldata)
        return data
        return data
