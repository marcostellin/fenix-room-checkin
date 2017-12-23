from flask import Flask
from flask import render_template
from flask import Response
from flask import redirect, url_for
from flask import session, request, jsonify

from make_request import *
import json
import fenixedu
import boto3
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime
import memcache
from werkzeug.security import generate_password_hash, check_password_hash
import os
import dateutil.parser



application = Flask(__name__)
application.secret_key = "\x8f\xb1q\x8d\x96e\xdd,\xbe]|\xf9\x03r\xdc\xee\xf3\xbf.i\xfd\xbe2\x16"

application.config['REDIRECT_URI'] = "http://room-checkin.us-west-2.elasticbeanstalk.com/authorized"
application.config['CLIENT_ID'] = "1132965128044586"
application.config['CLIENT_SECRET'] = "pUJJ1hK2COuTjwurjP6TiZhgXFEVo+dm5dGivY2b7WQGDy+/0tOdrkscT2wSmP0/kBwxj8HnnqgXqoOw7t0eFg=="
application.config['BASE_URL'] = "https://fenix.tecnico.ulisboa.pt/"
application.config['DEBUG'] = True
application.config['DB_ENDPOINT'] = "https://dynamodb.us-west-2.amazonaws.com"
application.config['MC_ENDPOINT'] = "room-checkin.7ravpu.cfg.usw2.cache.amazonaws.com:11211"


@application.route('/')
def index():

    user_logged_in = is_logged_in(session.get('access_token'))
    admin_logged_in = is_admin_logged_in(session.get('username'), session.get('access_token'))

    return render_template('index.html', user_logged=user_logged_in, admin_logged=admin_logged_in)


@application.route('/authorized')  #CHANGE URL TO ADMIN STYLE
def user_auth():
    code = request.args.get('code')
    config = fenixedu.FenixEduConfiguration(application.config['CLIENT_ID'], 
											application.config['REDIRECT_URI'],
											application.config['CLIENT_SECRET'],
											application.config['BASE_URL'])


    client = fenixedu.FenixEduClient(config)
    user = client.get_user_by_code(code)
    data = FenixRequest().get_person(user.access_token)
    session['access_token'] = user.access_token
    session['username'] = data['username']

    return redirect(url_for('index'))

@application.route('/admin/authorized' , methods=['POST'])
def admin_auth():

    username = request.form.get('user')
    password = request.form.get('password')

    admin_entry = getItemDB(table = 'Admins', key={'username' : username})

    if admin_entry and check_password_hash(admin_entry['password'], password):

        if is_admin_expired(admin_entry['expires']):

            new_access_token = os.urandom(20)
            updateDB(table='Admins', 
                     key={'username':username}, 
                     update_expr='SET access_token = :val0, expires = :val1', 
                     expr_vals={':val0': new_access_token, ':val1': (datetime.now() + timedelta(days=1)).isoformat(' ')}
                     )


            session['access_token'] = new_access_token
            session['username'] = username

        else:

            session['access_token'] = admin_entry['access_token']
            session['username'] = admin_entry['username']

        return render_template('login_status.html', success=True)

    return render_template('login_status.html', success=False)


@application.route('/login')
def login():
	config = fenixedu.FenixEduConfiguration(application.config['CLIENT_ID'], 
											application.config['REDIRECT_URI'],
											application.config['CLIENT_SECRET'],
											application.config['BASE_URL'])

	client = fenixedu.FenixEduClient(config)
	url = client.get_authentication_url()

	return render_template('login.html', fenix_url=url)


@application.route('/dashboard')
def dashboard():

    #DEBUG ONLY
    #session['username']='ist427286'

    if not is_logged_in(session.get('access_token')) or not is_admin_logged_in(session.get('username'), session.get('access_token')):
        return redirect(url_for('login'))

    user_in = getItemDB(table='Checkins', key={'user_id' : session.get('username')})
    
    if not user_in:
        other_users = []
    else:
        other_users = searchDB(table='Checkins', index_name='room_id', key_expr=Key('room_id').eq(user_in['room_id']))

    return render_template('dashboard.html', user_in=user_in, user_list=other_users)
   

@application.route('/results')
def results():

    user_logged_in = is_logged_in(session.get('access_token'))
    admin_logged_in = is_admin_logged_in(session.get('username'), session.get('access_token'))

    room_name = request.args.get('query').lower()

    mc = memcache.Client([application.config['MC_ENDPOINT']], debug=1)

    room_list = mc.get(room_name)

    if not room_list:
        key = Key('room_initial').eq(room_name[0]) & Key('room_name').begins_with(room_name)
        room_list = json.dumps(searchDB(table='Rooms', key_expr=key))
        mc.set(room_name, room_list)
    

    return render_template('results.html', result_set=json.loads(room_list), user_logged=user_logged_in, admin_logged=admin_logged_in)

@application.route('/rooms/<id>')
def rooms(id):
    
    user_logged_in = is_logged_in(session.get('access_token'))
    admin_logged_in = is_admin_logged_in(session.get('username'), session.get('access_token'))


    request = FenixRequest()
    data = request.get_space_id(space_id=id)
    room_info={}
    room_info['room_name'] = data['name']
    room_info['floor_name'] = "0"
    room_info['building_name'] = ""
    room_info['campus_name'] = ""

    

    while 'parentSpace' in data:

        if data['parentSpace']['type'] == 'FLOOR':
            room_info['floor_name'] = data['parentSpace']['name']

        if data['parentSpace']['type'] == 'BUILDING':
            room_info['building_name'] = data['parentSpace']['name']

        if data['parentSpace']['type'] == 'CAMPUS':
            room_info['campus_name'] = data['parentSpace']['name']

        data = request.get_space_id(space_id=data['parentSpace']['id'])




    return render_template('room_info.html', room_name=room_info['room_name'], 
                                             building_name=room_info['building_name'], 
                                             floor_name=room_info['floor_name'],
                                             campus_name=room_info['campus_name'],
                                             url=url_for('checkin', id=id),
                                             user_logged=user_logged_in,
                                             admin_logged=admin_logged_in)


@application.route('/rooms/<id>/checkin')
def checkin(id):

    #DEBUG ONLY
    #username = "ist427286"

    if not is_logged_in(session.get('access_token')):
        return redirect(url_for('login'))

    username = session.get('username')

    room_info = FenixRequest().get_space_id(space_id=id)
    
    cur_time = datetime.now().isoformat(' ')

    new_check_in={}
    new_check_in['user_id'] = username
    new_check_in['room_id'] = id
    new_check_in['date_in'] = cur_time
    new_check_in['room_name'] = room_info['name']

    user_in = searchDB(table='Checkins', key_expr=Key('user_id').eq(username))

    if user_in:
        key={'user_id':username}
        deleteDB(table='Checkins', key=key)

        new_history_entry={}
        new_history_entry['user_id'] = username
        new_history_entry['room_id'] = id
        new_history_entry['date_in'] = user_in[0]['date_in']
        new_history_entry['date_out'] = cur_time
        new_history_entry['room_name'] = user_in[0]['room_name']
        putDB(table='History', item=new_history_entry)

    putDB(table='Checkins', item=new_check_in)

    return redirect(url_for('dashboard'))

@application.route('/rooms/<id>/checkout')
def checkout(id):

    #DEBUG ONLY
    #username = "ist427286"

    if not is_logged_in(session.get('access_token')):
        return redirect(url_for('login'))

    username = session.get('username')

    user_in = searchDB(table='Checkins', key_expr=Key('user_id').eq(username))
    cur_time = datetime.now().isoformat(' ')

    if user_in:
        key={'user_id':username}
        deleteDB(table='Checkins', key=key)

        new_history_entry={}
        new_history_entry['user_id'] = username
        new_history_entry['room_id'] = id
        new_history_entry['date_in'] = user_in[0]['date_in']
        new_history_entry['date_out'] = cur_time
        new_history_entry['room_name'] = user_in[0]['room_name']
        putDB(table='History', item=new_history_entry)

    return redirect(url_for('dashboard'))


@application.route('/logout')
def logout():
    session.pop('username',None)
    session.pop('access_token',None)

    return redirect(url_for('index'))


@application.route('/debug/message')
def debug_index():
    if session.get('debug_user') is None:
        session['debug_user'] = 'testUser'
        session['debug_admin'] = 'testAdmin'

    return render_template('debug.html')

@application.route('/debug/new_message', methods=['POST'])
def new_message():


    to = session.get('debug_user')
    fromm = session.get('debug_admin')
    cur_time = datetime.now().isoformat(' ')

    new_message={}
    new_message['to'] = to
    new_message['from'] = fromm
    new_message['date'] = cur_time
    new_message['flashed'] = 'F'
    new_message['content'] = request.form.get('msg')

    putDB(table='Messages', item=new_message)


    return redirect(url_for('debug_index'))

@application.route('/debug/get_messages', methods=['GET', 'POST'])
def get_messages():

    user = session.get('debug_user')
    messages = searchDB(table='Messages', key_expr=Key('to').eq(user), filter_expr=Attr('flashed').eq('F'))

    if request.method == "GET":
        
        return jsonify(messages)

    if request.method == "POST":

        for item in messages:
            updateDB(table='Messages', key={'to':item['to'], 'date':item['date']}, update_expr='SET flashed = :val', expr_vals={':val': 'T'})

        return 'OK'

    

#LOGIN FUNCTIONS

def is_logged_in(access_token):

    if access_token is None:
        return False

    data = FenixRequest().get_person(access_token)

    if 'error' in data:
        session.pop('access_token')
        session.pop('username')

        return False

    return True

def is_admin_expired(exp_date):

    cur_time = datetime.now()
    expires_in = dateutil.parser.parse(exp_date)

    return (expires_in-cur_time).seconds < 0

def is_admin_logged_in(username, access_token):

    print(username)
    print(access_token)

    if access_token is None:
        return False

    admin_entry = getItemDB(table = 'Admins', key={'username' : username})

    print(admin_entry)

    if not admin_entry:
        raise ValueError('Provided username not in DB')
    
    if admin_entry['access_token'] != access_token:
        print(admin_entry['access_token'])
        return False

    if is_admin_expired(admin_entry['expires']):
        return False

    return True









#DATABASE OPERATIONS HELPERS


def searchDB(table, key_expr, index_name=None, filter_expr=None):

    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    if not index_name:
        if not filter_expr:
            result_set = table.query(
                KeyConditionExpression=key_expr,
            )
        else:
            result_set = table.query(
                KeyConditionExpression=key_expr,
                FilterExpression=filter_expr
            )
    else:
        if not filter_expr:
            result_set = table.query(
                IndexName=index_name,
                KeyConditionExpression=key_expr,
            )
        else:
            result_set = table.query(
                IndexName=index_name,
                KeyConditionExpression=key_expr,
                FilterExpression=filter_expr
            )

    return result_set['Items']

def putDB(table, item):

    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    table.put_item(Item=item)

def deleteDB(table, key):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    response=table.delete_item(Key=key)

def updateDB(table, key, update_expr, expr_vals):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    table.update_item(Key=key,
                      UpdateExpression=update_expr,
                      ExpressionAttributeValues=expr_vals,  
                     )

def getItemDB(table, key):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    result = table.get_item(Key=key)

    if 'Item' in result:
        return result['Item']
    else:
        return {}

    #return result['Item']

