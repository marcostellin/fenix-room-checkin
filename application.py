from flask import Flask
from flask import render_template
from flask import Response
from flask import redirect, url_for
from flask import session, request, jsonify

from make_request import *
import json
import fenixedu
import boto3
import time
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime, timedelta
import memcache
from werkzeug.security import generate_password_hash, check_password_hash
import os
from base64 import b64encode
import dateutil.parser
from api import Error



application = Flask(__name__)
application.secret_key = "\x8f\xb1q\x8d\x96e\xdd,\xbe]|\xf9\x03r\xdc\xee\xf3\xbf.i\xfd\xbe2\x16"

application.config['REDIRECT_URI'] = "http://room-checkin.us-west-2.elasticbeanstalk.com/authorized"
application.config['CLIENT_ID'] = "1132965128044586"
application.config['CLIENT_SECRET'] = "pUJJ1hK2COuTjwurjP6TiZhgXFEVo+dm5dGivY2b7WQGDy+/0tOdrkscT2wSmP0/kBwxj8HnnqgXqoOw7t0eFg=="
application.config['BASE_URL'] = "https://fenix.tecnico.ulisboa.pt/"
application.config['DEBUG'] = True
application.config['DB_ENDPOINT'] = "https://dynamodb.us-west-2.amazonaws.com"
application.config['MC_ENDPOINT'] = "room-checkin.7ravpu.cfg.usw2.cache.amazonaws.com:11211"


@application.before_request
def make_session_permanent():
     session.permanent = True
     application.permanent_session_lifetime = timedelta(days=1)


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

    print(user.access_token)

    session['access_token'] = user.access_token
    session['username'] = data['username']

    return redirect(url_for('index'))

@application.route('/admin/authorized' , methods=['POST'])
def admin_auth():

    username = request.form.get('user')
    password = request.form.get('password')

    admin_entry = getItemDB(table = 'Admins', key={'username' : username})

    if admin_entry and check_password_hash(admin_entry['password'], password):

        session['access_token'] = admin_entry['access_token']
        session['username'] = admin_entry['username']

        if is_admin_expired(admin_entry['expires']):

            new_access_token = b64encode(os.urandom(64)).decode('utf-8')
            updateDB(table='Admins', 
                     key={'username':username}, 
                     update_expr='SET access_token = :val0, expires = :val1', 
                     expr_vals={':val0': new_access_token, ':val1': (datetime.now() + timedelta(days=1)).isoformat(' ')}
                     )
            session['access_token'] = new_access_token
            session['username'] = username

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

    if not is_logged_in(session.get('access_token')) and not is_admin_logged_in(session.get('username'), session.get('access_token')):
        session.pop('username', None)
        session.pop('access_token', None)
        return redirect(url_for('login'))

    user_logged = is_logged_in(session.get('access_token'))
    admin_logged = is_admin_logged_in(session.get('username'), session.get('access_token'))

    if user_logged:

        user_in = getItemDB(table='Checkins', key={'user_id' : session.get('username')})
        
        if not user_in:
            other_users = []
        else:
            other_users = searchDB(table='Checkins', index_name='room_id', key_expr=Key('room_id').eq(user_in['room_id']))

        return render_template('dashboard.html', 
                                user_in=user_in, 
                                user_list=other_users, 
                                user_logged=user_logged, 
                                admin_logged=admin_logged)
    if admin_logged:

        checkin_list = scanDB(table='Checkins')
    
        return render_template('dashboard.html', 
                                user_logged=user_logged, 
                                admin_logged=admin_logged, 
                                checkin_list=checkin_list)

    return redirect(url_for('login'))
   

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

    if 'error' in data:
        return redirect(url_for('static', filename='404.html'), 404)


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


    user_in = searchDB(table='Checkins', key_expr=Key('room_id').eq(id), index_name='room_id')
    prev_history = searchDB(table='History', key_expr=Key('room_id').eq(id), index_name='room_id-index')

    return render_template('room_info.html', room_name=room_info['room_name'], 
                                             building_name=room_info['building_name'], 
                                             floor_name=room_info['floor_name'],
                                             campus_name=room_info['campus_name'],
                                             url=url_for('checkin', id=id),
                                             user_logged=user_logged_in,
                                             admin_logged=admin_logged_in,
                                             user_in=user_in,
                                             prev_history=prev_history
                                             )


@application.route('/rooms/<id>/checkin')
def checkin(id):

    if not is_logged_in(session.get('access_token')):
        session.pop('username', None)
        session.pop('access_token', None)
        return redirect(url_for('login'))

    username = session.get('username')

    room_info = FenixRequest().get_space_id(space_id=id)

    if 'error' in room_info:
        return redirect(url_for('static', filename='404.html'), 404)

    
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
        session.pop('username', None)
        session.pop('access_token', None)
        return redirect(url_for('login'))

    data = FenixRequest().get_space_id(space_id=id)

    if 'error' in data:
        return redirect(url_for('static', filename='404.html'), 404)

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

@application.route('/user/<username>/messages', methods=['POST', 'GET'])
def msg_list(username):

    if request.method == 'POST':
        if not is_admin_logged_in(session.get('username'), session.get('access_token')):
            session.pop('username', None)
            session.pop('access_token', None)
            return redirect(url_for('login'))

        to = username
        sender = session.get('username')
        cur_time = datetime.now().isoformat(' ')

        new_message={}
        new_message['id'] = str(int(round(time.time() * 1000)))
        new_message['to'] = to
        new_message['from'] = sender
        new_message['date'] = cur_time
        new_message['flashed'] = 'F'
        new_message['read'] = 'F'
        new_message['content'] = request.form.get('msg')

        putDB(table='Messages', item=new_message)


        return redirect(url_for('index'))

    if request.method == 'GET':
        
        if not is_logged_in(session.get('access_token')):
            session.pop('username', None)
            session.pop('access_token', None)
            return redirect(url_for('login'))

        user_logged = is_logged_in(session.get('access_token'))

        msg_list = searchDB(table='Messages', key_expr=Key('to').eq(username), index_name='to-index')

        messages_sorted = sorted(msg_list, key = lambda msg: msg['date'], reverse=True)

        return render_template('message_list.html', msg_list=messages_sorted, user_logged=user_logged)


@application.route('/admin/message/<username>')
def write_msg(username):

    if not is_admin_logged_in(session.get('username'), session.get('access_token')):
        session.pop('username', None)
        session.pop('access_token', None)
        return redirect(url_for('login'))

    return render_template('send_message.html', username=username)


@application.route('/user/ajax/messages')
def get_messages():

    user = session.get('username')

    if user is None:
        return "[]"

    messages = searchDB(table='Messages', key_expr=Key('to').eq(user), filter_expr=Attr('flashed').eq('F'), index_name='to-index')

    if not messages:
        return 'No messages', 404

    messages_sorted = sorted(messages, key = lambda msg: msg['date'])

    #print(messages_sorted)

    return jsonify(messages_sorted[0])

@application.route('/user/ajax/messages/<msg_id>', methods=['POST'])
def update_messages(msg_id):    

    updateDB(table='Messages', key={'id': msg_id}, update_expr='SET flashed = :val', expr_vals={':val': 'T'})

    return 'OK', 200


#API Users 

@application.route('/api/rooms')
def api_search_rooms():

    query_string = request.args.get('query')

    if not query_string:
        return jsonify(Error().bad_request('Bad query')), 400

    key = Key('room_initial').eq(query_string[0].lower()) & Key('room_name').begins_with(query_string.lower())
    room_list = searchDB(table='Rooms', key_expr=key, proj_expr="room_id, room_name")

    return jsonify({"Results": room_list})

@application.route('/api/room/<room_id>')
def api_room_info(room_id):

    request = FenixRequest()
    data = request.get_space_id(space_id=room_id)

    if 'error' in data:
        return jsonify(Error().not_found('Room not found')), 404

    room_info={}
    room_info['name'] = data['name']
    room_info['floor'] = "0"
    room_info['building'] = ""
    room_info['campus'] = ""

    

    while 'parentSpace' in data:

        if data['parentSpace']['type'] == 'FLOOR':
            room_info['floor'] = data['parentSpace']['name']

        if data['parentSpace']['type'] == 'BUILDING':
            room_info['building'] = data['parentSpace']['name']

        if data['parentSpace']['type'] == 'CAMPUS':
            room_info['campus'] = data['parentSpace']['name']

        data = request.get_space_id(space_id=data['parentSpace']['id'])

    return jsonify(room_info)

@application.route('/api/checkins/<room_id>', methods=['POST', 'DELETE'])
def api_checkin(room_id):

    if request.method == 'POST':

        access_token = request.args.get('access_token')
        implicit_checkout = request.args.get('implicit_checkout')

        if access_token is None or implicit_checkout is None:
            return jsonify(Error().bad_request('Missing parameters')), 400

        if implicit_checkout != 'true' and implicit_checkout != "false":
            return jsonify(Error().bad_request('implicit_checkout wrong value')), 400

        if not is_logged_in(access_token):
            return jsonify(Error().not_authorized('Invalid access token')), 410

        room_info = FenixRequest().get_space_id(space_id=room_id)

        if 'error' in room_info:
            return jsonify(Error().not_found('Room not found')), 404

        user_data = FenixRequest().get_person(access_token)

        user_in = getItemDB(table='Checkins', key={'user_id' : user_data['username']})

        if user_in and implicit_checkout == 'false':
            return jsonify(Error().conflict('User already checked-in in another room')), 409

        cur_time = datetime.now().isoformat(' ')

        if user_in and implicit_checkout == 'true':
            key={'user_id':user_data['username']}
            deleteDB(table='Checkins', key=key)

            new_history_entry={}
            new_history_entry['user_id'] = user_data['username']
            new_history_entry['room_id'] = room_id
            new_history_entry['date_in'] = user_in['date_in']
            new_history_entry['date_out'] = cur_time
            new_history_entry['room_name'] = user_in['room_name']
            putDB(table='History', item=new_history_entry)


        new_check_in={}
        new_check_in['user_id'] = user_data['username']
        new_check_in['room_id'] = room_id
        new_check_in['date_in'] = cur_time
        new_check_in['room_name'] =room_info['name']

        putDB(table='Checkins', item=new_check_in)

        return 'OK', 200
    
    if request.method == 'DELETE':
        access_token = request.args.get('access_token')
        
        if access_token is None:
            return jsonify(Error().bad_request('Missing parameters')), 400

        if not is_logged_in(access_token):
            return jsonify(Error().not_authorized('Invalid access token')), 410

        user_data = FenixRequest().get_person(access_token)

        user_in = getItemDB(table='Checkins', key={'user_id' : user_data['username']})

        if not user_in:
            return jsonify(Error().not_found('User not checked-in in any room')), 404

        if user_in['room_id'] != room_id:
            return jsonify(Error().not_found('User not checked-in in specified room')), 404

        cur_time = datetime.now().isoformat(' ')

        if user_in:
            key={'user_id':user_data['username']}
            deleteDB(table='Checkins', key=key)

            new_history_entry={}
            new_history_entry['user_id'] = user_data['username']
            new_history_entry['room_id'] = room_id
            new_history_entry['date_in'] = user_in['date_in']
            new_history_entry['date_out'] = cur_time
            new_history_entry['room_name'] = user_in['room_name']
            putDB(table='History', item=new_history_entry)

        return 'DELETED', 204

@application.route('/api/checkins/list')
def api_checkin_list():

    access_token = request.args.get('access_token')
        
    if access_token is None:
        return jsonify(Error().bad_request('Missing parameters')), 400

    if not is_logged_in(access_token):
        return jsonify(Error().not_authorized('Invalid access token')), 410

    user_data = FenixRequest().get_person(access_token)
    user_in = getItemDB(table='Checkins', key={'user_id' : user_data['username']})

    if not user_in:
        return jsonify(Error().not_found('User not checked-in in any room')), 404

    other_users = searchDB(table='Checkins', index_name='room_id', key_expr=Key('room_id').eq(user_in['room_id']), proj_expr="user_id")

    response = {}
    response['room_id'] = user_in['room_id']
    response['room_name'] = user_in['room_name']
    response['users'] = other_users

    return jsonify(response)

@application.route('/api/messages')
def api_messages():
    access_token = request.args.get('access_token')
    if access_token is None:
        return jsonify(Error().bad_request('Missing parameters')), 400

    if not is_logged_in(access_token):
        return jsonify(Error().not_authorized('Invalid access token')), 410

    user_data = FenixRequest().get_person(access_token)

    msg_list = searchDB(table='Messages', key_expr=Key('to').eq(user_data['username']), index_name='to-index')

    return jsonify({'items' : msg_list})


@application.route('/api/<user_id>/messages/<msg_id>', methods=['POST'])
def api_readmsg(user_id, msg_id):

    access_token = request.args.get('access_token')
    if access_token is None:
        return jsonify(Error().bad_request('Missing parameters')), 400

    if not is_logged_in(access_token):
        return jsonify(Error().not_authorized('Invalid access token')), 410

    user_data = FenixRequest().get_person(access_token)

    if 'error' in user_data:
        return jsonify(Error().not_found('User not found')), 404

    if user_data['username'] != user_id:
        return jsonify(Error().not_authorized('Not authorized')), 410

    msg = getItemDB(table='Messages', key={'id' : msg_id})

    if not msg:
        return jsonify(Error().not_found('Message not found')), 404

    updateDB(table='Messages', key={'id': msg_id}, update_expr='SET flashed = :val', expr_vals={':val': 'T'})

    return 'OK', 200


@application.route('/api/<user_id>/messages/<msg_id>')
def api_getmsg(user_id, msg_id):

    access_token = request.args.get('access_token')
    if access_token is None:
        return jsonify(Error().bad_request('Missing parameters')), 400

    if not is_logged_in(access_token):
        return jsonify(Error().not_authorized('Invalid access token')), 410

    user_data = FenixRequest().get_person(access_token)

    if 'error' in user_data:
        return jsonify(Error().not_found('User not found')), 404

    if user_data['username'] != user_id:
        return jsonify(Error().not_authorized('Not authorized')), 410

    msg = getItemDB(table='Messages', key={'id' : msg_id})

    if not msg:
        return jsonify(Error().not_found('Message not found')), 404

    return jsonify(msg)

# API admins

@application.route('/api/<room_id>/history')
def api_admin_history(room_id):

    access_token = request.args.get('access_token')
    username = request.args.get('username')

    if access_token is None or username is None:
        return jsonify(Error().bad_request('Missing parameters')), 400

    if not is_admin_logged_in(username, access_token):
        return jsonify(Error().not_authorized('Invalid credentials or expired token')), 410

    prev_history = searchDB(table='History', key_expr=Key('room_id').eq(room_id), index_name='room_id-index', proj_expr="user_id, room_name, date_in, date_out")

    return jsonify({'items' : prev_history})

@application.route('/api/<room_id>/checkins')
def api_admin_checkins_room(room_id):

    access_token = request.args.get('access_token')
    username = request.args.get('username')

    if access_token is None or username is None:
        return jsonify(Error().bad_request('Missing parameters')), 400

    if not is_admin_logged_in(username, access_token):
        return jsonify(Error().not_authorized('Invalid credentials or expired token')), 410

    user_in = searchDB(table='Checkins', key_expr=Key('room_id').eq(room_id), index_name='room_id', proj_expr='user_id, room_name, date_in')

    return jsonify({'items' : user_in})

@application.route('/api/checkins')
def api_admin_checkins():

    access_token = request.args.get('access_token')
    username = request.args.get('username')

    if access_token is None or username is None:
        return jsonify(Error().bad_request('Missing parameters')), 400

    if not is_admin_logged_in(username, access_token):
        return jsonify(Error().not_authorized('Invalid credentials or expired token')), 410

    checkin_list = scanDB(table='Checkins')

    return jsonify({'items' : checkin_list})

@application.route('/api/<user_id>/messages', methods=['POST'])
def api_admin_sendmsg(user_id):

    access_token = request.form.get('access_token')
    username = request.form.get('username')
    msg = request.form.get('msg')

    if access_token is None or username is None or msg is None:
        return jsonify(Error().bad_request('Missing parameters')), 400

    if not is_admin_logged_in(username, access_token):
        return jsonify(Error().not_authorized('Invalid credentials or expired token')), 410


    to = user_id
    sender = username
    cur_time = datetime.now().isoformat(' ')

    new_message={}
    new_message['to'] = to
    new_message['id'] = str(int(round(time.time() * 1000)))
    new_message['from'] = sender
    new_message['date'] = cur_time
    new_message['flashed'] = 'F'
    new_message['read'] = 'F'
    new_message['content'] = msg

    putDB(table='Messages', item=new_message)

    return 'Sent', 201





#LOGIN FUNCTIONS

def is_logged_in(access_token):

    if access_token is None:
        return False

    data = FenixRequest().get_person(access_token)

    if 'error' in data:

        return False

    return True

def is_admin_expired(exp_date):

    cur_time = datetime.now()
    expires_in = dateutil.parser.parse(exp_date)

    print(cur_time)
    print(expires_in)
    print(expires_in-cur_time)
    print((expires_in-cur_time).days)

    return (expires_in-cur_time).days < 0

def is_admin_logged_in(username, access_token):

    if access_token is None:
        return False

    admin_entry = getItemDB(table = 'Admins', key={'username' : username})

    if not admin_entry:
        return False
    
    if admin_entry['access_token'] != access_token:
        print(admin_entry['access_token'])
        return False

    if is_admin_expired(admin_entry['expires']):
        return False

    return True









#DATABASE OPERATIONS HELPERS


def searchDB(table, key_expr, index_name=None, filter_expr=None, proj_expr=None):

    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    if not index_name:
        if not filter_expr:
            if not proj_expr:
                result_set = table.query(
                    KeyConditionExpression=key_expr,
                )
            else:
                result_set = table.query(
                    KeyConditionExpression=key_expr,
                    ProjectionExpression=proj_expr
                )
        else:
            if not proj_expr:
                result_set = table.query(
                    KeyConditionExpression=key_expr,
                    FilterExpression=filter_expr
                )
            else:
                result_set = table.query(
                    KeyConditionExpression=key_expr,
                    FilterExpression=filter_expr,
                    ProjectionExpression=proj_expr
                )
    else:
        if not filter_expr:
            if not proj_expr:
                result_set = table.query(
                    IndexName=index_name,
                    KeyConditionExpression=key_expr,
                )
            else:
                result_set = table.query(
                    IndexName=index_name,
                    KeyConditionExpression=key_expr,
                    ProjectionExpression=proj_expr
                )
        else:
            if not proj_expr:
                result_set = table.query(
                    IndexName=index_name,
                    KeyConditionExpression=key_expr,
                    FilterExpression=filter_expr
                )
            else:
                result_set = table.query(
                    IndexName=index_name,
                    KeyConditionExpression=key_expr,
                    FilterExpression=filter_expr,
                    ProjectionExpression=proj_expr,
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

def scanDB(table):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    result_set=table.scan()

    return result_set['Items']

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

