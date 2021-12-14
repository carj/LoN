import configparser
import json
import xml
import xml.etree.ElementTree as ET

import requests
from requests.auth import HTTPBasicAuth


atom_slug_map = dict()
atom_scope_map = dict()


def create_tree(result, scope_id, parent_scope_id, ref_code):
    root = ET.Element('Root', attrib={"xmlns": "https://archive.unog.ch"})
    if scope_id:
        ET.SubElement(root, 'System_ID').text = str(scope_id)
    if parent_scope_id:
        ET.SubElement(root, 'Parent_ID').text = str(parent_scope_id)
    if result['level_of_description']:
        ET.SubElement(root, 'Level').text = str(result['level_of_description'])
    if ref_code:
        ET.SubElement(root, 'RefCode').text = str(ref_code)
    if ref_code:
        ET.SubElement(root, 'RefCodeAP').text = str(ref_code)
    if 'title' in result:
        ET.SubElement(root, 'Title').text = str(result['title'])
    if 'translated title' in result:
        ET.SubElement(root, 'TranslatedTitle').text = str(result['translated title'])
    if 'dates' in result:
        if result['dates'][0]['date']:
            ET.SubElement(root, 'CreationDates').text = str(result['dates'][0]['date'])

    if 'archivists_notes' in result:
        for note in result['archivists_notes']:
            s = note.split(":")
            if 'Term of protection' == s[0]:
                ET.SubElement(root, 'TermOfProtection').text = str(s[1])
            if 'Retention period to' == s[0]:
                ET.SubElement(root, 'EndOfTermOfProtection').text = str(s[1])
            if 'Retention period duration' == s[0]:
                ET.SubElement(root, 'LengthOfTermOfProtection').text = str(s[1])

    if 'scope_and_content' in result:
        ET.SubElement(root, 'ScopeAndContent').text = str(result['scope_and_content'])

    if 'creators' in result:
        if 'history' in result['creators'][0] and 'inherited_from' not in result['creators'][0]:
            ET.SubElement(root, 'AdminHistory').text = str(result['creators'][0]['history'])

    if 'archival_history' in result:
        ET.SubElement(root, 'ArchivalHistory').text = str(result['archival_history'])
    if 'extent_and_medium' in result:
        ET.SubElement(root, 'Extent').text = str(result['extent_and_medium'])
    if 'creator' in result:
        ET.SubElement(root, 'Creator').text = str(result['creator'])
    if 'system_of_arrangement' in result:
        ET.SubElement(root, 'SystemOfArrangement').text = str(result['system_of_arrangement'])
    if 'languages_of_description' in result:
        ET.SubElement(root, 'Language').text = str(result['languages_of_description'])
    if 'related_units_of_description' in result:
        ET.SubElement(root, 'RelatedMaterial').text = str(result['related_units_of_description'])

    return root


def get_parent_slug_from_record(record):
    if 'parent' in record:
        return record['parent']
    else:
        return None


def get_scope_ref_from_record(record):
    identifiers = record['alternative_identifiers']
    scope_map = list(filter(lambda x: filterId(x, 'Ref code'), identifiers))
    if len(scope_map) == 0:
        return None
    return scope_map[0]['identifier']


def get_scope_id_from_record(record):
    identifiers = record['alternative_identifiers']
    scope_map = list(filter(lambda x: filterId(x, 'Scope ID'), identifiers))
    if len(scope_map) == 0:
        return None
    return scope_map[0]['identifier']


def filterId(d, name):
    for k, v in d.items():
        if v == name:
            return k


class AToMCatalogue:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('credentials.properties')
        self.atom_host = config['credentials']['atom_host']
        if not self.atom_host.startswith("http"):
            self.atom_host = f"https://{self.atom_host}"
        if "atom_basic_auth_user" in config['credentials']:
            self.atom_basic_auth_user = config['credentials']['atom_basic_auth_user']
        else:
            self.atom_basic_auth_user = None

        if "atom_basic_auth_passwd" in config['credentials']:
            self.atom_basic_auth_passwd = config['credentials']['atom_basic_auth_passwd']
        else:
            self.atom_basic_auth_passwd = None

        self.atom_rest_api_key = config['credentials']['atom_rest_api_key']

    def close(self):
        pass

    def get_parent_scope_id_from_record(self, record):
        if 'parent' in record:
            parent_slug = record['parent']
            record = self.get_by_slug(parent_slug)
            return get_scope_id_from_record(record)
        else:
            return None

    def get_by_slug(self, slug):

        if slug in atom_slug_map:
            return atom_slug_map[slug]

        headers = {'REST-API-Key': self.atom_rest_api_key}
        path = "/api/informationobjects"
        url = f"{self.atom_host}{path}/{slug}"
        if self.atom_basic_auth_user:
            response = requests.get(url, auth=HTTPBasicAuth(self.atom_basic_auth_user, self.atom_basic_auth_passwd),
                                    headers=headers)
        else:
            response = requests.get(url, headers=headers)
        if response.status_code == requests.codes.ok:
            json_response = str(response.content.decode('utf-8'))
            atom_response = json.loads(json_response)
            atom_response['slug'] = slug
            if atom_response.get('title') is None:
                atom_response['title'] = atom_response.get('translated title')
            if atom_response['title'] is None:
                atom_response['title'] = get_scope_ref_from_record(atom_response)

            atom_slug_map[slug] = atom_response
            return atom_response
        else:
            raise RuntimeError(response.content)

    def get_by_id(self, scope_id):
        return self.get_by_scope_id(scope_id)

    def get_by_scope_id(self, scope_id):

        if scope_id in atom_scope_map:
            return atom_scope_map[scope_id]

        headers = {'REST-API-Key': self.atom_rest_api_key}
        path = "api/preservica/altIdentifier"
        url = f"{self.atom_host}/{path}"
        params = {'id': scope_id, 'label': "Scope ID"}

        if self.atom_basic_auth_user:
            response = requests.get(url, auth=HTTPBasicAuth(self.atom_basic_auth_user, self.atom_basic_auth_passwd),
                                    headers=headers, params=params)
        else:
            response = requests.get(url, headers=headers, params=params)
        if response.status_code == requests.codes.ok:
            json_response = str(response.content.decode('utf-8'))
            atom_response = json.loads(json_response)
            slug = atom_response['slug']
            atom_scope_map[scope_id] = self.get_by_slug(slug)
            return atom_scope_map[scope_id]
        else:
            raise RuntimeError(response.content)

    def get_by_ref(self, code):
        return self.get_by_ref_code(code)

    def get_by_ref_code(self, ref_code):
        headers = {'REST-API-Key': self.atom_rest_api_key}
        path = "api/preservica/altIdentifier"
        url = f"{self.atom_host}/{path}"
        params = {'id': ref_code, 'label': "Ref code"}

        if self.atom_basic_auth_user:
            response = requests.get(url, auth=HTTPBasicAuth(self.atom_basic_auth_user, self.atom_basic_auth_passwd),
                                    headers=headers, params=params)
        else:
            response = requests.get(url, headers=headers, params=params)
        if response.status_code == requests.codes.ok:
            json_response = str(response.content.decode('utf-8'))
            atom_response = json.loads(json_response)
            slug = atom_response['slug']
            return self.get_by_slug(slug)
        else:
            print(f"No record in ATOM with Ref Code {ref_code}")
            return None


if __name__ == "__main__":
    c = AToMCatalogue()

    r = c.get_by_slug("supplementary-questionnaire-correspondence-with-australia")
    print(r)
    print("Scope ID: " + get_scope_id_from_record(r))
    print("Ref Code: " + get_scope_ref_from_record(r))
    print("Parent: " + get_parent_slug_from_record(r))

    print("Parent ID: " + c.get_parent_scope_id_from_record(r))

    r = c.get_by_slug("supplementary-questionnaire-correspondence-with-australia")
    print(r)
    element = create_tree(r, get_scope_id_from_record(r), c.get_parent_scope_id_from_record(r),
                          get_scope_ref_from_record(r))
    xml_doc = xml.etree.ElementTree.tostring(element, encoding="utf-8").decode("utf-8")
    print(xml_doc)
    parent = get_parent_slug_from_record(r)
    while parent is not None:
        r = c.get_by_slug(parent)
        print(r)
        element = create_tree(r, get_scope_id_from_record(r), c.get_parent_scope_id_from_record(r),
                              get_scope_ref_from_record(r))
        xml_doc = xml.etree.ElementTree.tostring(element, encoding="utf-8").decode("utf-8")
        print(xml_doc)
        parent = get_parent_slug_from_record(r)

