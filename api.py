import datetime
import json
from flask import Flask, request, jsonify, render_template, redirect, session , url_for, flash
from flask_cors import CORS
import requests
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
import google_auth_oauthlib.flow
import flask

app = Flask(__name__)
app.secret_key = '$123321$'
CORS(app)
app.app_context() 
# cred = credentials.Certificate("firebase_serviceaccount.json")
# firebase_admin.initialize_app(cred)

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        id_token = request.json.get('idToken')
        if not id_token:
            return jsonify({'error': 'ID token is missing'}), 400
        print(id_token)
        # Log in the user
        login_response = requests.post('http://127.0.0.1:3232/login_with_google', json={'id_token': id_token})
        print(f"Login response: {login_response.status_code} - {login_response.text}")

        if login_response.status_code == 200:
            auth_status = login_response.json().get('message')
            user_email = login_response.json().get('user_email')
            sheet_url = login_response.json().get('sheet_url')
            if auth_status:
                print("success")
                session['user_email'] = user_email
                session['sheet_url'] = sheet_url
                return redirect(url_for('Msheet'))
        else:
            print("error")
            return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_email')
    return redirect(url_for('login'))

@app.route('/Msheet', methods=['GET', 'POST'])
def Msheet():
    if request.method == 'POST':
        email = session.get('user_email')
        sheet_url = session.get('sheet_url')
        
        if not email:
            return jsonify({"error": "User not logged in"}), 401
        input_sheet_url = request.form['sheet_url']
        if sheet_url is None:
            try:
                response = requests.post('http://127.0.0.1:3232/update_sheet_url', json={'email': email, 'sheet_url': input_sheet_url })

                if response.status_code == 200:
                    session['sheet_url'] = input_sheet_url
                    flash('SHEET URL UPDATED SUCCESSFULLY')
                    return redirect(url_for('Msheet'))
                else:
                    flash('FAILED ')
                    return redirect(url_for('Msheet'))
            except Exception as e:
                flash('UNEXPECTED ERROR PLEASE TRY AGAIN')
                print(f"Error: {e}")
                return redirect(url_for('Msheet'))
        else:
            flash('SHEET URL ALREADY EXIST')
            return redirect(url_for('Msheet'))
    email = session.get('user_email')
    sheet_url = session.get('sheet_url')
    updated = session.get('updated')
    updated = bool(updated)
    print(sheet_url , updated)
    return render_template('sheeturl.html', url=sheet_url, updated=updated , user_email=email)

@app.route('/gsheetworking', methods=['GET', 'POST'])
def gsheetworking():
    if request.method == 'POST':
        email = session.get('user_email')
        sheet_url = session.get('sheet_url')
        if not email:
            return jsonify({"error": "User not logged in"}), 401
        if not sheet_url:
            return jsonify({"error": "No sheet url found"}), 501
        
        no_of_pages = request.form.get('noOfPages')
        if no_of_pages is not None:
            try:
                no_of_pages = int(no_of_pages)
            except ValueError:
                return jsonify({"error": "Invalid value for noOfPages, must be an integer"}), 400
        try:
            data = {
                'email': email,
                'sheet_url': sheet_url,
                'platform': request.form.get('platform'),
                'titleInfo': request.form.get('titleInfo', '').split(', '),
                'roles': request.form.get('roles', '').split(', '),
                'industry': request.form.get('industry', '').split(', '),
                'locations': request.form.get('locations', '').split(', '),
                'required': request.form.get('required'),
                'noOfPages': no_of_pages
            }
            print(data)
        except Exception as e:
            print(f"Error: {e}")
        try:
            response = requests.post('http://127.0.0.1:3232/googlesheetWorking', json=data)

            if response.status_code == 200:
                session['updated'] = True
                flash('SHEET UPDATED SUCCESSFULLY')
                return redirect(url_for('Msheet'))
            else:
                flash('FAILED UPDATING SHEET')
                return redirect(url_for('gsheetworking'))
        except Exception as e:
            flash('UNEXPECTED ERROR PLEASE TRY AGAIN')
            print(f"Error: {e}")
            return redirect(url_for('gsheetworking'))
    return render_template('gsheetWorking.html')












CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://mail.google.com/']

@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  # The URI created here must exactly match one of the authorized redirect URIs
  # for the OAuth 2.0 client, which you configured in the API Console. If this
  # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
  # error.
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state

  return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)
  print(credentials)
  return flask.redirect(flask.url_for('gmailworking'))

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

























@app.route('/gmailworking', methods=['GET', 'POST'])
def gmailworking():
    if request.method == 'POST':
        email = session.get('user_email')
        password = session.get('user_pass')
        sheet_url = session.get('sheet_url')
        print(sheet_url , password)
        if not email:
            return jsonify({"error": "User not logged in"}), 401
       
        data = {
            'email': email,
            'sheet_url' : sheet_url,
            'subject': request.form.get('subject'),
            'mailmsg': request.form.get('email'),
            'time': request.form.get('timeToStart'),
            'clink': request.form.get('calendlyLink'),
            'password' : password
        }
        print(data)
        subject = data.get('subject')
        if subject:
            try:
                response = requests.post('https://emerging-special-stingray.ngrok-free.app/gmailWorking', json=data)
                if response.status_code == 200:
                    session['updated'] = True
                    flash('STARTED SENDING MAILS')
                    return redirect(url_for('Msheet'))
                else:
                    flash('FAILED SENDING MAILS')
                    return redirect(url_for('gmailworking'))
            except Exception as e:
                flash('UNEXPECTED ERROR PLEASE TRY AGAIN')
                print(f"Error: {e}")
                return redirect(url_for('gmailworking'))
    return render_template('gmailWorking.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
