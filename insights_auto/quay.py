from urllib.parse import urlparse, urljoin
import re
import requests
from .common import parse_cves, QUAY_API_BASE_URL


class QuayApi:

    def __init__(self, base_url=QUAY_API_BASE_URL, authorization=None, repository=None):
        self.base_url = base_url
        self.authorization = authorization
        self.repository = repository

    def get_image_tags(self, image_name):
        path = f'api/v1/repository/{self.repository}/{image_name}/tag/'
        response = self.get(path, params={
            'limit': 40,
            'page': 1,
            'onlyActiveTags': 'true'
        })
        return response['tags']

    def get_image(self, image_name, tag='latest'):
        images = self.get_image_tags(image_name)
        return next((image for image in images if image.get('name') == tag), None)

    def get_image_security(self, image_name, tag='latest'):
        image = self.get_image(image_name, tag=tag)
        manifest_digest = image['manifest_digest']
        path = (f'api/v1/repository/{self.repository}/{image_name}'
                f'/manifest/{manifest_digest}/security')
        return image, self.get(path, params={'vulnerabilities': 'true'})

    def get_image_vulnerabilities(self, image_name, tag='latest'):
        image, security = self.get_image_security(image_name, tag=tag)
        features = security['data']['Layer']['Features']
        vulnerabilities = list(QuayVulenrability.from_v1_features(features))
        return image, vulnerabilities


    def get(self, path, **kwargs):
        kwargs = self._enrich_request_kwargs(kwargs)
        req = requests.get(urljoin(self.base_url, path), **kwargs)
        req.raise_for_status()
        return req.json()

    def fmt_vulnerabilities_url(self, image_name, image):
        manifest_digest = image['manifest_digest']
        return urljoin(self.base_url,
                       f'repository/{self.repository}/{image_name}'
                       f'/manifest/{manifest_digest}?tab=vulnerabilities')

    def _enrich_request_kwargs(self, kwargs):
        kwargs = dict(kwargs)
        if self.authorization:
            for (key, value) in self.authorization.items():
                kwargs.setdefault(key, {}).update(value)
        return kwargs


class QuayVulenrability:

    def __init__(self, package_name=None, version=None, fixed_version=None,
                 link=None, erratum=None, cves=None, description=None, severity=None):
        self.package_name = package_name
        self.version = version
        self.fixed_version = fixed_version
        self.link = link
        self.erratum = erratum
        self.cves = cves or ()
        self.description = description
        self.severity = severity

    @classmethod
    def from_v1_features(cls, features):
        for feature in features:
            yield from cls.from_v1_feature(feature)

    @classmethod
    def from_v1_feature(cls, feature):
        if not feature.get('Vulnerabilities'):
            return
        vulns = feature.get('Vulnerabilities', ())

        for vulnerability in vulns:
            yield cls(
                package_name=feature['Name'],
                version=feature['Version'],
                fixed_version=vulnerability['FixedBy'],
                link=vulnerability['Link'],
                erratum=vulnerability['Name'],
                cves=parse_cves(vulnerability['Description']),
                description=vulnerability['Description'],
                severity=vulnerability['Severity']
            )

    def __str__(self):
        return f"{self.__class__.__name__}({self.package_name}, cves=[{','.join(self.cves)}])"
