import os
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from core import db
from flask import Blueprint, request, g, current_app
from micawber import ProviderRegistry, Provider
from micawber.exceptions import ProviderNotFoundException
import requests
from requests.exceptions import RequestException
from urlparse import urlparse, parse_qs
from psycopg2 import IntegrityError
from psycopg2.extensions import AsIs
import json
import uuid

from queue_workers.emails import send_registration_email, send_password_reset_email, \
    send_account_report_email, send_request_email_change_email
from queue_workers.cell_phone_sms import send_cell_phone_sms
from queue_workers.slacknotif import send_notif

from auth import requires_auth, generate_jwt_token, verify_jwt

from error import InvalidUsage

from utils import valid_image, success_response, ensure_valid_uuid, ensure_valid_token, \
    validate_request, validate_response, get_request_data, ensure_valid_email, \
    image_delete, account_upload_and_resize_image
from PIL import Image


@account.route('/signup', methods=['POST'])
@validate_request()
@validate_response()
def account_signup():
    req = get_request_data()
    facebook_user_id = None

    if 'facebook_auth_token' in req:
        try:
            fb = requests.get(
                'https://graph.facebook.com/debug_token',
                params={'input_token': req['facebook_auth_token'],
                        'access_token': current_app.config['FB_ACCESS_TOKEN']}).json()

            if 'error' in fb:
                error_msg = fb['error']['message']
                error_type = fb['error']['type']
                current_app.logger.error('{}: {}'.format(error_type, error_msg))
                raise InvalidUsage(error_msg, error_type)

            if not fb['data']['is_valid']:
                raise InvalidUsage('Invalid Facebook login session.',
                                   'invalid_facebook_login')

            facebook_user_id = fb['data']['user_id']

            fb = requests.get('https://graph.facebook.com/v2.5/me?access_token={}'
                              '&fields=email'.
                              format(req['facebook_auth_token'])).json()

            if 'email' not in fb:
                raise InvalidUsage('Email from Facebook account is required',
                                   'facebook_email_required')

            req['email'] = fb['email']

        except RequestException as e:
            current_app.logger.error(e)
            raise InvalidUsage('Error contacting Facebook for '
                               'authorization verification.',
                               'facebook_communication_error')

    req['password_hash'] = generate_password_hash(req['password'])
    req['facebook_user_id'] = facebook_user_id

    fields = ['account_type', 'username', 'first_name', 'last_name', 'company_name',
              'email', 'phone_number', 'bio', 'latitude', 'longitude']

    for f in fields:
        if f not in req:
            req[f] = None

    # Set these fields to empty string if not present
    # Because they cannot be saved as NULL in database
    # TODO probably better to make fields empty by default in DB
    for f in ['first_name', 'last_name', 'company_name']:
        if not req[f]:
            req[f] = ''

    with db.get_db_cursor(commit=True) as cur:
        cur.execute('''
                    SELECT
                    account_signup (%(account_type)s, %(username)s, %(password_hash)s,
                                    %(first_name)s, %(last_name)s, %(company_name)s,
                                    %(email)s, %(phone_number)s,
                                    %(bio)s, %(latitude)s, %(longitude)s,
                                    %(facebook_user_id)s)
                    AS response
                    ''', req)
        res = cur.fetchone()['response']
        if not res['success']:
            raise InvalidUsage(res['message'], res['status'])
        cur.execute('''
                    SELECT row_to_json(accounts) as account_info
                    FROM accounts
                    WHERE account_id = %(account_id)s
                    ''', res)
        account = cur.fetchone()['account_info']

        # Send confirm email and SMS pin
        send_registration_email.delay(account)
        send_cell_phone_sms.delay(account)

        # Slack notif
        send_notif.delay(title='New Signup', first_name=account['first_name'],
                         email=account['email'], username=account['username'],
                         facebook_user_id=account['facebook_user_id'])

        errors = []
        if 'facebook_auth_token' in req:
            try:
                remote = (requests.get(
                    'https://graph.facebook.com/v2.5/me'
                    '?access_token={}&fields=cover'
                    .format(req['facebook_auth_token']))
                    .json())['cover']['source']
                img = requests.get(remote)
                image_id = account_upload_and_resize_image(
                    cur,
                    BytesIO(img.content), 'cover.jpg', account['account_uuid'], 'cover',
                    'Facebook cover photo.',
                    'Retreived {}.'.format(datetime.now()
                                           .strftime("%Y-%m-%d %H:%M:%S")))
                cur.execute('''
                            UPDATE accounts
                            SET cover_photo_id=%s
                            WHERE account_uuid=%s
                            ''', (image_id, account['account_uuid']))
            except Exception:
                current_app.logger.exception("Error retreiving cover photo from Facebook")
                errors.append('Error retreiving cover photo from Facebook.')
            try:
                img = requests.get(
                    'http://graph.facebook.com/v2.5/{}/picture?type=large'.
                    format(facebook_user_id))
                image_id = account_upload_and_resize_image(
                    cur,
                    BytesIO(img.content), 'profile.jpg',
                    account['account_uuid'], 'profile',
                    'Facebook profile photo.',
                    'Retreived {}.'.format(datetime.now()
                                           .strftime("%Y-%m-%d %H:%M:%S")))
                cur.execute('''
                            UPDATE accounts
                            SET profile_photo_id=%s
                            WHERE account_uuid=%s
                            ''', (image_id, account['account_uuid']))
            except Exception:
                current_app.logger.exception(
                    "Error retreiving profile photo from Facebook")
                errors.append('Error retreiving profile photo from Facebook.')
    resp = success_response({'data': {'account_uuid': account['account_uuid']}})
    if len(errors) > 0:
        resp['errors'] = errors
    return resp
