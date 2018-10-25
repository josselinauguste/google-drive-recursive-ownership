#!/usr/bin/env python

import os
import sys

import googleapiclient.errors

from transfer import get_drive_service, process_all_files, get_permission_id_for_email, is_owned_by


def remove_access_to(permission_id):
    def call(service, drive_item):
        print('    Remove permission.')
        return service.permissions().delete(fileId=drive_item['id'],
                                            permissionId=permission_id).execute()

    return call


def is_accessible_by(user, permission_id):
    check_owner = is_owned_by(user)

    def check_access(service, drive_item):
        try:
            service.permissions().get(fileId=drive_item['id'], permissionId=permission_id).execute()
            return True
        except googleapiclient.errors.HttpError:
            return False

    def filter(service, drive_item):
        return not check_owner(service, drive_item) and check_access(service, drive_item)

    return filter


if __name__ == '__main__':
    minimum_prefix = sys.argv[1].decode('utf-8')
    from_user = sys.argv[2].decode('utf-8')
    minimum_prefix_split = minimum_prefix.split(os.path.sep)
    service = get_drive_service()
    permission_id = get_permission_id_for_email(service, from_user)
    process_all_files(service, remove_access_to(permission_id),
                      minimum_prefix_split, filter=is_accessible_by(from_user, permission_id))
