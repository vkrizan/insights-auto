import os
import os.path
import sys
from urllib.parse import urlparse
import requests
import argparse
from getpass import getpass, getuser
from jira import JIRA

from pprint import pprint

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'insights_auto')
)

from insights_auto import QuayApi, JiraVulnerabilityReporter, JIRA_SERVER, QUAY_API_BASE_URL


QUAY_REPOSITORY = 'cloudservices'


def get_quay_auth(base_url=QUAY_API_BASE_URL):
    session = os.environ.get('QUAY_IO_SESSION')
    if not session:
        return

        sys.exit(1)

    domain = urlparse(base_url).netloc

    jar = requests.cookies.RequestsCookieJar()
    jar.set('session', session, domain=domain)
    return {'cookies': jar}


def arg_parser():
    parser = argparse.ArgumentParser(
        description='Create vulnerability Jiras from Quay.io scanning results'
    )

    parser.add_argument('image_name', metavar='IMAGE_NAME',
                        help='an integer for the accumulator')
    parser.add_argument('jira_project', metavar='JIRA_PROJECT',
                        help='Jira project name (e.g. RHICOMPL)')
    parser.add_argument('-u', metavar='JIRA_USERNAME', dest='jira_username',
                        help='Jira username (NOT email), default current user')

    return parser


def setup_quay(args):
    authorization = get_quay_auth()
    if not authorization:
        print('Please set the QUAY_IO_SESSION environment value')
        print('grabbed from browser.')
        sys.exit(1)

    quay = QuayApi(
        authorization=authorization,
        repository=QUAY_REPOSITORY,
    )

    return quay


def setup_jira(args):
    jira_username = args.jira_username or getuser()
    jira_pass = getpass('Jira password: ')
    return JIRA(server=JIRA_SERVER, basic_auth=(jira_username, jira_pass))


def run(raw_args):
    parser = arg_parser()
    args = parser.parse_args(raw_args)

    jira = setup_jira(args)
    quay = setup_quay(args)

    image, vulnerabilities = quay.get_image_vulnerabilities(args.image_name)

    quay_page_url = quay.fmt_vulnerabilities_url(args.image_name, image)
    quay_text = f'Quay:\n* {quay_page_url}'

    reporter = JiraVulnerabilityReporter(
        jira, args.jira_project,
        additional_text=quay_text
    )
    reporter.report(vulnerabilities)

if __name__ == '__main__':
    run(sys.argv[1:])
