import consts
import json
from dateutil import parser


def getCVEdict(cvedetails, vendorid):
    premiumcve = consts.getPremiumCVEText(vendorid)
    if vendorid == 1:
        return {'ecosystem': cvedetails["language"],
                'cves': cvedetails["cves"] or premiumcve, 'package': cvedetails["package"],
                'versions': cvedetails["vulnerableVersions"],
                'published': cvedetails["publicationTime"], 'vendorurl': cvedetails["url"]}


def getcveinfo(vendorfilename, vendorid):
    cvedict = {}
    cveinfo = []
    vendorEcosys = consts.getVendorEcosystems(vendorid)
    with open(vendorfilename) as filename:
        cveData = json.load(filename)
    for cvekey, cveval in cveData.items():
        if cvekey in vendorEcosys:
            for cvedetails in cveval:
                cvedict = getCVEdict(cvedetails, vendorid)
                cveinfo.append(cvedict)
    return cveinfo


def readVendorData(vendorid=1):
    vendorFiles = consts.getVendorFileNames(vendorid)
    vendorEcosys = consts.getVendorEcosystems(vendorid)
    cveList = []
    for vendorFile in vendorFiles:
        cveList.extend(getcveinfo(vendorFile, vendorid))
    print(cveList)


readVendorData()
