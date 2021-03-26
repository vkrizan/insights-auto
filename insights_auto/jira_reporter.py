import jira
from .common import parse_cves, join_collection


class JiraVulnerabilityReporter:
    def __init__(self, jira_conn, project, additional_text=None):
        self.jira_conn = jira_conn
        self.project = project
        self._reported_cves = None
        self.additional_text = additional_text

    def report(self, vulnerabilities):
        for vulnerability in vulnerabilities:
            if not vulnerability.cves:
                print(f'SKIPPED found vulnerability on {vulnerability.package_name} - No CVEs')
                continue

            self.report_vulnerability(vulnerability)
            print()

    def report_vulnerability(self, vulnerability):
        print(f'Found vulnerability on {vulnerability.package_name}')
        print('CVEs:', join_collection(vulnerability.cves))

        new_cves = set(vulnerability.cves) - self.reported_cves
        if not new_cves:
            print('  [SKIPPED] Already reported')
            return

        print(f'  Reporting JIRA to {self.project} for CVEs', join_collection(new_cves))
        new_issue = self.report_jira(vulnerability, new_cves)
        print('  [DONE] Reported as', new_issue.key)

    @property
    def reported_cves(self):
        if self._reported_cves is not None:
            return self._reported_cves

        reported_issues = self.get_existing_issues()
        collected_cves = set()
        for issue in reported_issues:
            issue_cves = parse_cves(issue.fields.summary)
            collected_cves.update(issue_cves)

        self._reported_cves = collected_cves
        return collected_cves

    def get_existing_issues(self):
        return self.jira_conn.search_issues(
            f'project = {self.project} AND labels = Security'
        )

    def report_jira(self, vulnerability, new_cves):
        summary = self._jira_summary(vulnerability, new_cves)
        print('  Summary:', summary)

        return self.jira_conn.create_issue(
            project=self.project,
            summary=summary,
            description=self._jira_description(vulnerability, new_cves),
            components=[{'name': 'Security'}],
            issuetype={'name': 'Bug'},
            security={'name': 'Red Hat Internal'},
            labels=['Security'] + list(new_cves)
        )

    def _jira_summary(self, vulnerability, new_cves):
        parts = list(new_cves)
        parts.append(vulnerability.erratum)
        parts.append(vulnerability.severity)
        parts.append(vulnerability.package_name)
        return ' '.join(parts)

    def _jira_description(self, vulnerability, new_cves):
        parts = [
            '_As reported in Quay.io_',
            self._fmt_vuln_description(vulnerability),
            f'Erratum: {vulnerability.link}',
            self._cve_links(new_cves)
        ]

        if self.additional_text:
            parts.append(self.additional_text)

        return '\n\n'.join(parts)

    def _fmt_vuln_description(self, vulnerability):
        return '\n'.join(['{code:none}', vulnerability.description.strip(), '{code}'])

    def _cve_links(self, cves):
        parts = ['CVE Links:']
        for cve in cves:
            parts.append(f'* https://access.redhat.com/security/cve/{cve}')
        return '\n'.join(parts)

