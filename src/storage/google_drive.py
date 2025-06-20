from datetime import datetime
import io
import logging
from typing import BinaryIO, Optional

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from requests_oauthlib import OAuth2Session

from .models import GoogleOAuthToken


logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/drive.file']


@deconstructible
class GoogleDriveStorage(Storage):
    _google_credentials: Optional[Credentials] = None
    _drive_service: Optional[Resource] = None

    def __init__(self):
        self.flow = InstalledAppFlow.from_client_secrets_file(
            settings.GOOGLE_DRIVE_STORAGE_CLIENT_SECRET_FILE_PATH,
            SCOPES,
            redirect_uri=settings.GOOGLE_DRIVE_STORAGE_OAUTH_REDIRECT_URI,
        )

    def get_authorization_url(self) -> tuple[str, str]:
        # returns a tuple of (url, state). prompt=consent makes sure we do a
        # full reauth and get a refresh token
        return self.flow.authorization_url(prompt='consent')

    def exchange_code(self, code: str) -> None:
        new_token = self.flow.fetch_token(code=code)

        self._persist_token(
            new_token['refresh_token'],
            new_token['access_token'],
            new_token['expires_at'],
        )

    def _persist_token(
        self, refresh_token: str, access_token: str, expires_at: float
    ) -> None:
        token = GoogleOAuthToken.objects.first()

        if token:
            token.refresh_token = refresh_token
            token.access_token = access_token
            token.expires_at = expires_at
            token.save(update_fields=['refresh_token', 'access_token', 'expires_at'])
        else:
            GoogleOAuthToken.objects.create(
                refresh_token=refresh_token,
                access_token=access_token,
                expires_at=expires_at,
            )

    def _refresh_token(self) -> None:
        active_token = GoogleOAuthToken.objects.first()

        if not active_token:
            raise Exception('Missing active token for Google drive storage')

        google_refresh_session = OAuth2Session(
            self.flow.client_config['client_id'],
            token={
                'refresh_token': active_token.refresh_token,
                'access_token': active_token.access_token,
                'expires_at': active_token.expires_at,
            },
        )

        new_token = google_refresh_session.refresh_token(
            'https://accounts.google.com/o/oauth2/token',
            client_id=self.flow.client_config['client_id'],
            client_secret=self.flow.client_config['client_secret'],
        )

        self._persist_token(
            new_token['refresh_token'],
            new_token['access_token'],
            new_token['expires_at'],
        )

    def _get_drive_service(self, rebuild: bool = False) -> Resource:
        # initialize credentials and service and cache them
        if not self._drive_service or rebuild:
            active_token = GoogleOAuthToken.objects.first()

            if not active_token:
                raise Exception('Missing active token for Google drive storage')

            self._google_credentials = Credentials(
                token=active_token.access_token,
                expiry=datetime.fromtimestamp(active_token.expires_at),
                refresh_token=active_token.refresh_token,
            )
            self._drive_service = build(
                'drive', 'v3', credentials=self._google_credentials
            )

        # refresh the access token if it is expired
        if self._google_credentials.expired:
            self._refresh_token()
            return self._get_drive_service(rebuild=True)
        else:
            return self._drive_service

    def _get_drive_list_extra_kwargs(self, drive_id: Optional[str]) -> dict:
        # if storing in a shared drive there are a few arguments we need to use
        # when listing files
        if drive_id:
            return {
                'driveId': drive_id,
                'includeItemsFromAllDrives': True,
                'corpora': 'drive',
                'supportsAllDrives': True,
            }
        else:
            return {}

    def _get_drive_list_query(self, file_name: str, parent: Optional[str]) -> str:
        if parent:
            return f"'{parent}' in parents and name = '{file_name}'"
        else:
            return f"name = '{file_name}'"

    def exists(self, name: str) -> bool:
        # on google drive you can upload multiple files with the same name, so
        # always return False
        return False

    def url(self, name: str) -> Optional[str]:
        # get the file and return a url leading to its web view on drive
        try:
            file_get_result = (
                self._get_drive_service()
                .files()
                .get(
                    fileId=name,
                    fields='webViewLink',
                    supportsAllDrives=True,
                )
                .execute()
            )

            return file_get_result['webViewLink']
        except HttpError as ex:
            if ex.resp.status == 404:
                logger.error(f'google drive storage url file {name} not found')
                return None
            else:
                raise

    def _save(self, name: str, content: File) -> str:
        parent = settings.GOOGLE_DRIVE_STORAGE_BASE_FOLDER_ID
        drive_id = settings.GOOGLE_DRIVE_STORAGE_DRIVE_ID

        path_parts = name.split('/')
        file_name = path_parts.pop()

        for path_part in path_parts:
            # walk down the folder tree, finding the specific folder each time
            # and creating it if it does not exist yet
            path_list_result = (
                self._get_drive_service()
                .files()
                .list(
                    q=self._get_drive_list_query(path_part, parent),
                    pageSize=1,
                    fields='files(id)',
                    **self._get_drive_list_extra_kwargs(drive_id),
                )
                .execute()
            )

            if len(path_list_result['files']) > 0:
                parent = path_list_result['files'][0]['id']
            else:
                # create a missing intermediate folder
                path_create_result = (
                    self._get_drive_service()
                    .files()
                    .create(
                        body={
                            'name': path_part,
                            'mimeType': 'application/vnd.google-apps.folder',
                            'driveId': drive_id,
                            'parents': [parent],
                        },
                        supportsAllDrives=True,
                    )
                    .execute()
                )

                parent = path_create_result['id']

        # create the file
        media_body = MediaIoBaseUpload(content.file, content.content_type)
        path_create_result = (
            self._get_drive_service()
            .files()
            .create(
                body={
                    'name': file_name,
                    'parents': [parent],
                },
                media_body=media_body,
                supportsAllDrives=True,
            )
            .execute()
        )

        return path_create_result['id']

    def _open(self, name: str, mode: str = 'rb') -> BinaryIO:
        file_download_request = self._get_drive_service().files().get_media(fileId=name)
        out_file = io.BytesIO()

        media_downloader = MediaIoBaseDownload(out_file, file_download_request)
        done = False

        # download each chunk until we are done
        while not done:
            _, done = media_downloader.next_chunk()

        # seek back and return the buffer
        out_file.seek(0)
        return out_file
