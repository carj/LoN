import os
import jaydebeapi
import xml.etree.ElementTree as ET


def _convert_to_map(cursor):
    column_names = [record[0].lower() for record in cursor.description]
    column_and_values = [dict(zip(column_names, record)) for record in cursor.fetchall()]
    for row in column_and_values:
        for key, value in row.items():
            if value is not None:
                row[key] = value.replace("\\n", u"\n")

        if row['title'] is None:
            row['title'] = row['translated title']
        if row['title'] is None:
            row['title'] = row['ref. code']

    return column_and_values


def create_tree(result):
    root = ET.Element('Root', attrib={"xmlns": "https://archive.unog.ch"})
    if result['id']:
        ET.SubElement(root, 'System_ID').text = result['id']
    if result['parent id']:
        ET.SubElement(root, 'Parent_ID').text = result['parent id']
    if result['level']:
        ET.SubElement(root, 'Level').text = result['level']
    if result['ref. code']:
        ET.SubElement(root, 'RefCode').text = result['ref. code']
    if result['ref. code ap']:
        ET.SubElement(root, 'RefCodeAP').text = result['ref. code ap']
    if result['title']:
        ET.SubElement(root, 'Title').text = result['title']
    if result['translated title']:
        ET.SubElement(root, 'TranslatedTitle').text = result['translated title']
    if result['creation date(s)']:
        ET.SubElement(root, 'CreationDates').text = result['creation date(s)']
    if result['term of protection']:
        ET.SubElement(root, 'TermOfProtection').text = result['term of protection']
    if result['length of top']:
        ET.SubElement(root, 'LengthOfTermOfProtection').text = result['length of top']
    if result['end of top']:
        ET.SubElement(root, 'EndOfTermOfProtection').text = result['end of top']
    if result['scope and content']:
        ET.SubElement(root, 'ScopeAndContent').text = result['scope and content']
    if result['type of archival material']:
        ET.SubElement(root, 'TypeOfArchivalMaterial').text = result['type of archival material']
    if result['administration history']:
        ET.SubElement(root, 'AdminHistory').text = result['administration history']
    if result['archival history']:
        ET.SubElement(root, 'ArchivalHistory').text = result['archival history']
    if result['extent']:
        ET.SubElement(root, 'Extent').text = result['extent']
    if result['creator']:
        ET.SubElement(root, 'Creator').text = result['creator']
    if result['system of arrangement']:
        ET.SubElement(root, 'SystemOfArrangement').text = result['system of arrangement']
    if result['language']:
        ET.SubElement(root, 'Language').text = result['language']
    if result['related material']:
        ET.SubElement(root, 'RelatedMaterial').text = result['related material']
    if result['remarks']:
        ET.SubElement(root, 'Remarks').text = result['remarks']
    if result['processing period']:
        ET.SubElement(root, 'ProcessingPeriod').text = result['processing period']

    return root


class Submission:
    pass


class ProgressDB:
    def __init__(self, java_home, db_path, jar_path):
        os.environ["JAVA_HOME"] = java_home
        self.connection = jaydebeapi.connect(
            "org.h2.Driver", f"jdbc:h2:{db_path};AUTO_SERVER=TRUE;IFEXISTS=TRUE", ["sa", ""], jar_path)

    def close(self):
        self.connection.close()

    def truncate(self):
        cursor = self.connection.cursor()
        cursor.execute("TRUNCATE TABLE DOCUMENTS;")
        cursor.close()

    def check_in_progress(self, refcode):
        result = self.check_in_refCode(refcode)
        if len(result) == 0:
            result = self.check_in_refCodeAP(refcode)
        if len(result) == 1:
            return result[0]
        else:
            return None

    def check_in_refCode(self, refcode):
        query = f"select * from DOCUMENTS WHERE REFCODE_UPPER = '{refcode.upper()}'"
        cursor = self.connection.cursor()
        cursor.execute(query)
        column_names = [record[0].lower() for record in cursor.description]
        column_and_values = [dict(zip(column_names, record)) for record in cursor.fetchall()]
        cursor.close()
        return column_and_values

    def check_in_refCodeAP(self, refcode):
        query = f"select * from DOCUMENTS WHERE REFCODE_A_UPPER = '{refcode.upper()}'"
        cursor = self.connection.cursor()
        cursor.execute(query)
        column_names = [record[0].lower() for record in cursor.description]
        column_and_values = [dict(zip(column_names, record)) for record in cursor.fetchall()]
        cursor.close()
        return column_and_values

    def save_not_matched(self, folderName, refCode, batch):
        query = "INSERT INTO NOT_MATCHED (FOLDER, REFCODE, BATCH) values (?,?,?)"
        cursor = self.connection.cursor()
        cursor.execute(query, (folderName, refCode, batch))
        cursor.close()

    def save(self, submisson):
        query = "insert into DOCUMENTS (systemId, parentId, xipRef, title, refCode, refCodeAP, sipName, " \
                "ingested, SIP_SIZE, JP2, PDF) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        cursor = self.connection.cursor()
        cursor.execute(query, (submisson.systemId, submisson.parentId, submisson.xipRef, submisson.title,
                               submisson.refCode, submisson.refCodeAP, submisson.sipName,
                               submisson.ingested, submisson.SIP_SIZE, submisson.JP2, submisson.PDF))
        cursor.close()


class Catalogue:
    def __init__(self, java_home, db_path, jar_path):
        os.environ["JAVA_HOME"] = java_home
        self.connection = jaydebeapi.connect(
            "org.h2.Driver", f"jdbc:h2:{db_path};IFEXISTS=TRUE;DATABASE_TO_UPPER=TRUE", ["sa", ""], jar_path)

    def close(self):
        self.connection.close()

    def get_by_ref_code(self, code):
        return self.select_query(f'select * from Fonds where REF_CODE_UPPER = ' + f"'{code.upper().strip()}'")

    def get_by_ref_code_ap(self, code):
        return self.select_query(f'select * from Fonds where REF_CODE_A_UPPER = ' + f"'{code.upper().strip()}'")

    def get_by_id(self, system_id):
        result = self.select_query(f"select * from Fonds where ID = {int(system_id)}")
        assert len(result) == 1
        return result[0]

    def get_by_ref(self, code):
        result = self.get_by_ref_code(code)
        if len(result) == 0:
            result = self.get_by_ref_code_ap(code)
        if len(result) == 1:
            return result[0]
        else:
            return None

    def select_query(self, query):
        cursor = self.connection.cursor()
        cursor.execute(query)
        return_result = _convert_to_map(cursor)
        cursor.close()

        return return_result
