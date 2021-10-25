import configparser
import os
import time
import csv
import xml.etree.ElementTree
import xml.dom.minidom
from pathlib import Path
from multiprocessing import Pool
from pyPreservica import *
import base64
import uuid
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import boto3
from boto3.s3.transfer import TransferConfig
from requests.auth import HTTPBasicAuth

from Catalogue import ProgressDB, Submission
from atom import AToMCatalogue, get_scope_ref_from_record, get_scope_id_from_record, create_tree, atom_scope_map, atom_slug_map

REF_NO = "REF"
ScopeArchivID = "ScopeArchivID"

MAX_BUCKET_SIZE = 12

POOL_SIZE = 4

folder_map = dict()

transfer_config = boto3.s3.transfer.TransferConfig()

ref_code__map = dict()


class ThreadCallBack:
    def __init__(self, progressDB):
        self.progressDB = progressDB

    def __call__(self, result):
        self.progressDB.save(result)
        print(f"Completed Upload of {result.refCode}")


class ProgressPercentage:

    def __init__(self, filename):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        # To simplify, assume this is hooked up to a single filename
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._size) * 100
            sys.stdout.write("\r%s  %s / %s  (%.2f%%)" % (self._filename, self._seen_so_far, self._size, percentage))
            sys.stdout.flush()


class UUIDCallback:
    def __init__(self, ident):
        self.ident = ident

    def __call__(self):
        return self.ident


class CSVFixityCallBack:

    def __init__(self, csv_folder):
        self.csv_folder = csv_folder

    def __call__(self, filename, full_path):
        path = Path(full_path)
        csv_name = str(path.with_suffix('.csv'))
        csv_name = csv_name.replace("JP2", "CSV")
        fixity_value = ""
        with open(csv_name, mode='r', encoding='utf-8-sig') as csv_file:
            csv_reader = csv.DictReader(csv_file, delimiter=',')
            for row in csv_reader:
                fixity_value = row['file_checksum_sha256']

        return "SHA256", fixity_value.lower()


def get_PDF_JPEG_CSV(path):
    format_folders = [f.path for f in os.scandir(path) if f.is_dir()]
    assert len(format_folders) == 3
    return format_folders


def get_document_locations(format_paths):
    document_map = dict()
    for path in format_paths:
        box_folders = [f.path for f in os.scandir(path) if f.is_dir()]
        for box_path in box_folders:
            document_paths = [f.path for f in os.scandir(box_path) if f.is_dir()]
            for document_path in document_paths:
                document = os.path.basename(document_path)
                document_map.setdefault(document, [])
                document_map[document].append(document_path)
    return document_map


def get_code_from_box(document):
    document = document.strip()
    document = document.replace("-", "/")
    return document


def does_folder_exist(entity, system_id):  # TODO
    if system_id in folder_map:
        return folder_map[system_id]
    entities = entity.identifier(ScopeArchivID, system_id)
    if len(entities) > 1:
        for e in entities:
            print(e)
        print(system_id)
    assert len(entities) < 2
    if len(entities) == 1:
        folder = entities.pop()
        folder_map[system_id] = folder
        return folder_map[system_id]
    else:
        return None


def get_levels(cat, record, levels):
    parent_id = cat.get_parent_scope_id_from_record(record)
    if parent_id is not None:
        levels.append(parent_id)
        parent_item = cat.get_by_scope_id(parent_id)
        get_levels(cat, parent_item, levels)
    return


def create_folder(cat, entity, item, parent_ref, tag, parent_scope_id):  # TODO
    scope_id = get_scope_id_from_record(item)
    ref_code = get_scope_ref_from_record(item)
    title = ref_code
    if not title:
        if 'title' in item:
            title = item['title']
        elif 'translated title' in item:
            title = item['translated title']

    title = title.replace("&", "&amp;")

    if ref_code:
        description = ref_code

    if 'translated title' in item:
        description = item['translated title'].replace("&", "&amp;")

    if 'title' in item:
        description = item['title'].replace("&", "&amp;")

    folder = entity.create_folder(title=title, description=description, security_tag=tag, parent=parent_ref)
    entity.add_identifier(folder, ScopeArchivID, scope_id)
    entity.add_identifier(folder, "AToM-Slug", item['slug'])
    if ref_code:
        entity.add_identifier(folder, "REF", ref_code)
    else:
        ref_code = ""

    element = create_tree(item, scope_id, parent_scope_id, ref_code)
    xml_doc = xml.etree.ElementTree.tostring(element, encoding="utf-8").decode("utf-8")
    entity.add_metadata(folder, "https://archive.unog.ch", xml_doc)

    folder_map[scope_id] = folder

    return folder


def create_parent_series(cat, entity, system_id, tag):
    folder = does_folder_exist(entity, system_id)
    if folder is not None:
        return folder

    item = cat.get_by_scope_id(system_id)
    parent_id = cat.get_parent_scope_id_from_record(item)
    if parent_id is None:
        print(f"Creating Folder with id: {system_id}")
        return create_folder(catalogue, entity, item, None, security_tag, parent_id)

    parent_item = cat.get_by_scope_id(parent_id)
    parent_item_id = get_scope_id_from_record(parent_item)

    assert parent_id == parent_item_id

    parent_folder = does_folder_exist(entity, parent_item_id)
    if parent_folder is not None:
        scope_id = get_scope_id_from_record(item)
        print(f"Creating Folder with id: {scope_id}")
        return create_folder(cat, entity, item, parent_folder.reference, tag, parent_id)
    else:
        return create_parent_series(cat, entity, parent_item_id, tag)


def get_folder(entity, record, cat, tag):
    parent_id = cat.get_parent_scope_id_from_record(record)
    folder = does_folder_exist(entity, parent_id)
    if folder is not None:
        return folder

    folder_ids = list()
    get_levels(cat, record, folder_ids)
    folder_ids.reverse()
    for system_id in folder_ids:
        folder_map[system_id] = create_parent_series(cat, entity, system_id, tag)

    return folder_map[parent_id]


def _unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def decrypt(key, cypher_text):
    base64_decoded = base64.b64decode(cypher_text)
    aes = cryptography.hazmat.primitives.ciphers.algorithms.AES(key.encode("UTF-8"))
    cipher = Cipher(algorithm=aes, mode=modes.ECB())
    decryptor = cipher.decryptor()
    output_bytes = decryptor.update(base64_decoded) + decryptor.finalize()
    return _unpad(output_bytes.decode("utf-8"))


def session_key(server, bucket_name, username, password, aeskey):
    request = requests.get(f"https://{server}/api/admin/locations/upload?refresh={bucket_name}",
                           auth=HTTPBasicAuth(username, password))
    if request.status_code == requests.codes.ok:
        xml_response = str(request.content.decode('utf-8'))
        entity_response = xml.etree.ElementTree.fromstring(xml_response)
        a = entity_response.find('.//a')
        b = entity_response.find('.//b')
        c = entity_response.find('.//c')
        aws_type = entity_response.find('.//type')
        endpoint = entity_response.find('.//endpoint')

        access_key = decrypt(aeskey, a.text)
        secret_key = decrypt(aeskey, b.text)
        session_token = decrypt(aeskey, c.text)
        source_type = decrypt(aeskey, aws_type.text)
        endpoint = decrypt(aeskey, endpoint.text)

        return access_key, secret_key, session_token, source_type, endpoint


def create_package(folder, document, content_paths, item, config, scope_id, catalogue):
    for path in content_paths:
        if "PDF" in path:
            pdf_document_folder = path
        if "CSV" in path:
            csv_document_folder = path
        if "JP2" in path:
            jp2_document_folder = path

    pdf_documents = [f.path for f in os.scandir(pdf_document_folder) if f.is_file() and f.name.endswith('.pdf')]
    csv_documents = [f.path for f in os.scandir(csv_document_folder) if f.is_file() and f.name.endswith('.csv')]
    jp2_documents = [f.path for f in os.scandir(jp2_document_folder) if f.is_file() and f.name.endswith('.jp2')]

    assert len(pdf_documents) == 1
    assert len(csv_documents) == len(jp2_documents)

    export_folder = config['credentials']['export_folder']
    username = config['credentials']['username']
    bucket_name = config['credentials']['upload.bucket']
    password = config['credentials']['password']
    server = config['credentials']['server']
    aeskey = config['credentials']['AESkey']
    tenant = config['credentials']['tenant']

    preservation_files_list = list()
    access_files_list = list()

    access_files_list.append(pdf_documents[0])
    all_files = 1
    for d in jp2_documents:
        preservation_files_list.append(d)
        all_files += 1

    fixity_callback = CSVFixityCallBack(csv_document_folder)

    scope_ref = get_scope_ref_from_record(item)

    assert get_scope_id_from_record(item) == scope_id

    identifiers = {"ScopeArchivID": scope_id, "REF": scope_ref, "AToM-Slug": item['slug']}  # todo

    asset_title = scope_ref
    asset_description = scope_ref

    if 'translated title' in item:
        asset_description = item['translated title']
    else:
        if 'title' in item:
            asset_description = item['title']
        else:
            asset_description = scope_ref

    parent_scope_id = catalogue.get_parent_scope_id_from_record(item)

    element = create_tree(item, scope_id, parent_scope_id, scope_ref)
    xml_doc = xml.etree.ElementTree.tostring(element, encoding="utf-8", xml_declaration=True).decode("utf-8")
    metadata_path = os.path.join(export_folder, scope_id + ".xml")
    with open(metadata_path, "w", encoding="utf-8") as md:
        md.write(xml_doc)

    asset_metadata = dict()
    asset_metadata["https://archive.unog.ch"] = metadata_path

    xipref = str(uuid.uuid4())

    security_tag = config['credentials']['security.tag']
    security_tag_private = config['credentials']['security.tag.private']

    #term_of_protection = item['note top']
    #if term_of_protection:
    #    security_tag = security_tag_private
    #    print(f"Setting private security tag because note ToP is {term_of_protection}")

    package_path = complex_asset_package(Title=asset_title, Description=asset_description, SecurityTag=security_tag,
                                         preservation_files_list=preservation_files_list,
                                         Preservation_Content_Description="Single Page JP2000 Image",
                                         Access_Content_Description="Multipage PDF document",
                                         access_files_list=access_files_list, Identifiers=identifiers,
                                         export_folder=export_folder, parent_folder=folder,
                                         Asset_Metadata=asset_metadata, IO_Identifier_callback=UUIDCallback(xipref),
                                         Preservation_files_fixity_callback=fixity_callback)

    access_key, secret_key, session_token, source_type, endpoint = session_key(server, bucket_name, username,
                                                                               password,
                                                                               aeskey)

    session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                            aws_session_token=session_token)
    s3 = session.resource(service_name="s3")

    workflow = WorkflowAPI(server=server, username=username, password=password, tenant=tenant)
    workflow_size = len(list(workflow.workflow_instances(workflow_state="Active", workflow_type="Ingest")))

    while workflow_size > MAX_BUCKET_SIZE:
        time.sleep(120)
        workflow_size = len(list(workflow.workflow_instances(workflow_state="Active", workflow_type="Ingest")))
        print(f"Workflow Size: {workflow_size}")

    upload_key = str(uuid.uuid4())
    s3_object = s3.Object(bucket_name, upload_key)
    metadata = dict()
    metadata['key'] = upload_key
    metadata['name'] = upload_key + ".zip"
    metadata['bucket'] = bucket_name
    metadata['status'] = 'ready'
    metadata['collectionreference'] = folder.reference
    metadata['size'] = str(Path(package_path).stat().st_size)
    metadata['numberfiles'] = str(all_files)
    metadata['createdby'] = "python"

    metadata_map = {'Metadata': metadata}

    s3_object.upload_file(package_path, Callback=ProgressPercentage(package_path), ExtraArgs=metadata_map,
                          Config=transfer_config)
    sys.stdout.write(u"\n")
    sys.stdout.flush()

    print(f"Upload of {asset_title} complete.")

    sys.stdout.flush()

    ##add to progress
    submission = Submission()
    submission.systemId = scope_id
    submission.parentId = parent_scope_id
    submission.xipRef = xipref
    submission.title = asset_description[:500]
    submission.refCode = scope_ref
    submission.refCodeAP = scope_ref
    submission.sipName = upload_key
    submission.ingested = False
    submission.SIP_SIZE = int(metadata['size'])
    submission.JP2 = str(pdf_document_folder)
    submission.PDF = str(jp2_document_folder)

    os.remove(metadata_path)
    os.remove(package_path)

    return submission


def try_to_find_record_from_folder(folder, cat):
    if folder in ref_code__map:
        ref_code = ref_code__map[folder]
    else:
        ref_code = get_code_from_box(folder)

    result = cat.get_by_ref(ref_code)
    if result is not None:
        return result, ref_code
    else:
        return None, ref_code


def main():
    num_processed = 0

    dry_run = bool(config['credentials'].get("dry.run", fallback="True") == "True")

    batch_paths = list()
    for i in range(1, 50):
        key = "batch.path.{0}".format(i)
        key = config['credentials'].get(key, "")
        if key:
            batch_paths.append(key)

    entity = EntityAPI()
    print(entity)

    max_submission = int(config['credentials']['max.submission'])

    numb_submission = int(0)

    threadCallBack = ThreadCallBack(progress)

    pool = Pool(processes=POOL_SIZE)

    for path in batch_paths:
        batch_id = os.path.basename(os.path.dirname(path))
        with open(f"{batch_id}.csv", 'w', newline='') as not_matched_csv:
            csv_writer = csv.writer(not_matched_csv)
            csv_writer.writerow(("Batch ID", "Folder Name", "Ref Code Guess"))
            paths = get_PDF_JPEG_CSV(path)
            document_map = get_document_locations(paths)
            for key in document_map:
                result, ref_code = try_to_find_record_from_folder(key, catalogue)
                if result is not None:
                    in_progress = progress.check_in_progress(ref_code)
                    if in_progress is not None:
                        print(f"{ref_code} found in the in-progress database. Skipping....")
                        continue
                    system_id = get_scope_id_from_record(result)
                    result = catalogue.get_by_id(system_id)

                    assert get_scope_id_from_record(result) == system_id  # check the calls match
                    identifiers = entity.identifier(ScopeArchivID, system_id)
                    if len(identifiers) == 1:
                        asset = identifiers.pop()
                        print(f"{ref_code} already exists with ref: {asset.reference}. Skipping....")
                    elif len(identifiers) == 0:
                        print(f"{ref_code} does not exists, creating new asset...")
                        num_processed = num_processed + 1
                        if dry_run:
                            print(f"Dry-run enabled skipping...")
                            continue
                        else:
                            folder = get_folder(entity, result, catalogue, security_tag)
                            content_paths = document_map[key]

                            pool.apply_async(func=create_package, args=(folder, key, content_paths, result, config, system_id, catalogue),
                                             callback=threadCallBack)
                            numb_submission = numb_submission + 1
                            if max_submission > 0:
                                if numb_submission >= max_submission:
                                    print("Max Submission Reached")
                                    break
                    elif len(identifiers) > 1:
                        print(f"Found Duplicate Assets for {ref_code}")
                else:
                    csv_writer.writerow((batch_id, key, ref_code))
                    progress.save_not_matched(key, ref_code, batch_id)
                    print(f"Could not match folder name {key} to a valid ref code. Tried to use {ref_code}")

    pool.close()
    print(f"Waiting for Uploads to Complete")
    pool.join()

    print(num_processed)


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('credentials.properties')

    java_home = config['credentials']['java_home']
    catalogue_path = config['credentials']['catalogue.path']
    jar_path = config['credentials']['jar_path']
    document_path = config['credentials']['document.path']
    security_tag = config['credentials']['security.tag']

    catalogue = AToMCatalogue()
    progress = ProgressDB(java_home, document_path, jar_path)

    main()

    catalogue.close()
    progress.close()
