import json
import traceback
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import time
from ghtoken import getGremlinURL


def get_session_retry(retries=3, backoff_factor=0.2, status_forcelist=(404, 500, 502, 504),
                      session=None):
    """Set HTTP Adapter with retries to session."""
    session = session or requests.Session()
    retry = Retry(total=retries, read=retries, connect=retries,
                  backoff_factor=backoff_factor, status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    return session


def execute_gremlin_dsl(payloads):
    """Execute the gremlin query and return the response."""
    try:
        print(payloads)
        resp = get_session_retry().post(getGremlinURL(), data=json.dumps(payloads))
        if resp.status_code == 200:
            json_response = resp.json()
            return json_response
        else:
            print("HTTP error {}. Error retrieving Gremlin data.".format(
                resp.status_code))
            return None
    except Exception as e:
        print(e)
        return None


def fetch_cve_ids(eco, pkg, ver):
    # cur_date = (datetime.utcnow()).strftime('%Y%m%d')
    query_str = "g.V().has('pecosystem', '{arg0}')." \
                "has('pname', '{arg1}')" \
                ".has('version', '{arg2}')" \
                ".out('has_cve')" \
                ".values('cve_id');"
    query_str = query_str.format(arg0=eco, arg1=pkg, arg2=ver)
    res = execute_gremlin_dsl({'gremlin': query_str})
    data = res.get("result", {}).get("data", [-1])
    return data
