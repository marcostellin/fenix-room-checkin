from flask import Flask
from flask import render_template
from flask import Response
from flask import redirect, url_for
import json
from flask import session, request
import fenixedu



application = Flask(__name__)
application.secret_key = "\x8f\xb1q\x8d\x96e\xdd,\xbe]|\xf9\x03r\xdc\xee\xf3\xbf.i\xfd\xbe2\x16"

application.config['REDIRECT_URI'] = "http://room-checkin.us-west-2.elasticbeanstalk.com/authorized"
application.config['CLIENT_ID'] = "1132965128044586"
application.config['CLIENT_SECRET'] = "pUJJ1hK2COuTjwurjP6TiZhgXFEVo+dm5dGivY2b7WQGDy+/0tOdrkscT2wSmP0/kBwxj8HnnqgXqoOw7t0eFg=="
application.config['BASE_URL'] = "https://fenix.tecnico.ulisboa.pt/"
application.config['DEBUG'] = True


@application.route('/')
def index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('user_login'))


    
    return str(session.get('access_token'))


@application.route('/authorized')
def user_auth():
	code = request.args.get('code')
	config = fenixedu.FenixEduConfiguration(application.config['CLIENT_ID'], 
											application.config['REDIRECT_URI'],
											application.config['CLIENT_SECRET'],
											application.config['BASE_URL'])

	client = fenixedu.FenixEduClient(config)
	user = client.get_user_by_code(code)
	session['access_token'] = user.access_token

	return redirect(url_for('index'))


@application.route('/login')
def user_login():
	config = fenixedu.FenixEduConfiguration(application.config['CLIENT_ID'], 
											application.config['REDIRECT_URI'],
											application.config['CLIENT_SECRET'],
											application.config['BASE_URL'])

	client = fenixedu.FenixEduClient(config)
	url = client.get_authentication_url()

	return render_template('login.html', url=url)













"""
counter = 0


@application.route('/')
def hello_world():
	message = "Hello World!"
	return render_template('index.html', message=message)

@application.route('/increment')
def increment():
	global counter 
	counter += 1
	dic = {'count': counter}

	return Response(json.dumps(dic), mimetype="application/json")
"""
