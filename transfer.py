#!/usr/bin/env python

import os
import sys
import urllib

import googleapiclient.discovery
import googleapiclient.errors
import googleapiclient.http
import httplib2
import oauth2client.client


DEBUG = False


def get_drive_service():
    OAUTH2_SCOPE = 'https://www.googleapis.com/auth/drive'
    CLIENT_SECRETS = 'client_secrets.json'
    flow = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS, OAUTH2_SCOPE)
    flow.redirect_uri = oauth2client.client.OOB_CALLBACK_URN
    authorize_url = flow.step1_get_authorize_url()
    os.system('open "{}"'.format(urllib.unquote(authorize_url)))
    print('Link for authorization: {}'.format(authorize_url))
    if sys.version_info[0] > 2:
        code = input('Verification code: ').strip()
    else:
        code = raw_input('Verification code: ').strip()
    credentials = flow.step2_exchange(code)
    http = httplib2.Http()
    credentials.authorize(http)
    drive_service = googleapiclient.discovery.build('drive', 'v2', http=http)
    return drive_service


def get_permission_id_for_email(service, email):
    try:
        id_resp = service.permissions().getIdForEmail(email=email).execute()
        return id_resp['id']
    except googleapiclient.errors.HttpError as e:
        print('An error occured: {}'.format(e))


def grant_ownership(service, drive_item, permission_id):
    try:
        permission = service.permissions().get(fileId=drive_item['id'],
                                               permissionId=permission_id).execute()
        permission['role'] = 'owner'
        print('    Upgrading existing permissions to ownership.')
        return service.permissions().update(fileId=drive_item['id'], permissionId=permission_id,
                                            body=permission, transferOwnership=True).execute()
    except googleapiclient.errors.HttpError as e:
        if e.resp.status != 404:
            print('An error occurred updating ownership permissions: {}'.format(e))
            return

    print('    Creating new ownership permissions.')
    permission = {'role': 'owner',
                  'type': 'user',
                  'id': permission_id}
    try:
        service.permissions().insert(fileId=drive_item['id'], body=permission,
                                     emailMessage='Automated recursive transfer of ownership.').execute()
    except googleapiclient.errors.HttpError as e:
        print('An error occurred inserting ownership permissions: {}'.format(e))


def process_all_files(service, callback=None, permission_id=None, minimum_prefix=None,
                      current_prefix=None, folder_id='root', filter=None):
    if minimum_prefix is None:
        minimum_prefix = []
    if current_prefix is None:
        current_prefix = []
    if filter is None:
        filter = lambda x: True

    if DEBUG:
        print('Gathering file listings for prefix {}...'.format(current_prefix))

    page_token = None
    while True:
        try:
            param = {}
            if page_token:
                param['pageToken'] = page_token
            children = service.children().list(folderId=folder_id, **param).execute()
            for child in children.get('items', []):
                item = service.files().get(fileId=child['id']).execute()
                if item['kind'] == 'drive#file':
                    is_folder = item['mimeType'] == 'application/vnd.google-apps.folder'
                    if filter(item) and current_prefix[:len(minimum_prefix)] == minimum_prefix:
                        file_type = 'Folder' if is_folder else 'File'
                        print(
                            u'{}: {} ({}, {})'.format(file_type, item['title'], current_prefix, item['id']))
                        callback(service, item, permission_id)
                    if is_folder:
                        if DEBUG:
                            print(u'Explore: {} ({}, {})'.format(item['title'], current_prefix,
                                                                item['id']))
                        next_prefix = current_prefix + [item['title']]
                        comparison_length = min(len(next_prefix), len(minimum_prefix))
                        if minimum_prefix[:comparison_length] == next_prefix[:comparison_length]:
                            process_all_files(service, callback, permission_id, minimum_prefix,
                                              next_prefix, item['id'], filter=filter)
            page_token = children.get('nextPageToken')
            if not page_token:
                break
        except googleapiclient.errors.HttpError as e:
            print('An error occurred: {}'.format(e))
            break


def is_owned_by(user):
    def filter(item):
        return reduce(lambda a, u: a or u['emailAddress'] == user, item['owners'], False)
    return filter


if __name__ == '__main__':
    minimum_prefix = sys.argv[1].decode('utf-8')
    previous_owner = sys.argv[2].decode('utf-8')
    new_owner = sys.argv[3].decode('utf-8')
    print('Changing all files at path "{}" to owner "{}"'.format(minimum_prefix, new_owner))
    minimum_prefix_split = minimum_prefix.split(os.path.sep)
    print('Prefix: {}'.format(minimum_prefix_split))
    service = get_drive_service()
    permission_id = get_permission_id_for_email(service, new_owner)
    print('User {} is permission ID {}.'.format(new_owner, permission_id))
    process_all_files(service, grant_ownership, permission_id,
                      minimum_prefix_split, filter=is_owned_by(previous_owner))
