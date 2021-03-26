import re

QUAY_API_BASE_URL = 'https://quay.io/'
JIRA_SERVER = 'https://issues.redhat.com'

CVE_RE = re.compile('CVE-\d+-\d+')

def parse_cves(description):
    if not description:
        return []

    return sorted(set(CVE_RE.findall(description)))


def join_collection(collection, sep=', '):
    return sep.join(collection)
