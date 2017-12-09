from flask import Flask
from flask import render_template
from flask import Response
from flask import redirect, url_for
from make_request import *
import json
from flask import session, request
import fenixedu
import boto3
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime
import memcache



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
    if not is_logged_in(session.get('access_token')):
        return redirect(url_for('login'))

    #return render_template('index.html', username=session.get('username'))
    return redirect(url_for('dashboard'))

@application.route('/authorized')
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
    #session['username']="ist427286"

    if not is_logged_in(session.get('access_token')):
        return redirect(url_for('login'))

    user_in = searchDB(table='Checkins', key_expr=Key('user_id').eq(session.get('username')))
    
    if not user_in:
        welcome_msg = 'Welcome %s, you are not checked-in in any room' % session.get('username')
        other_users = []
    else:
        welcome_msg = 'Welcome %s, you are checked-in in room ' % session.get('username') + user_in[0]['room_name'].upper()
        other_users = searchDB(table='Checkins', index_name='room_id', key_expr=Key('room_id').eq(user_in[0]['room_id']))

    return render_template('dashboard.html', welcome=welcome_msg, user_list=other_users)
   

@application.route('/search')
def search():
    
    return render_template('search.html')

@application.route('/results')
def results():

    room_name = request.args.get('query').lower()

    mc = memcache.Client([application.config['MC_ENDPOINT']], debug=1)

    room_list = mc.get(room_name)

    print(room_list)

    if not room_list:
        key = Key('room_initial').eq(room_name[0]) & Key('room_name').begins_with(room_name)
        room_list = json.dumps(searchDB(table='Rooms', key_expr=key))
        mc.set(room_name, room_list)
    

    return render_template('results.html', result_set=json.loads(room_list))

@application.route('/rooms/<id>')
def rooms(id):
    
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
                                             url=url_for('checkin', id=id))


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
        new_history_entry['room_name'] = room_info['name']
        putDB(table='History', item=new_history_entry)

    putDB(table='Checkins', item=new_check_in)

    return redirect(url_for('dashboard'))





#LOGIN FUNCTIONS

def is_logged_in(access_token):

    if access_token is None:
        return False

    data = FenixRequest().get_person(access_token)

    if 'error' in data:
        return False

    return True





#DATABASE OPERATIONS HELPERS


def searchDB(table, key_expr, index_name=None):

    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    if index_name == None:
        result_set = table.query(
            KeyConditionExpression=key_expr,
        )
    else:
        result_set = table.query(
            IndexName=index_name,
            KeyConditionExpression=key_expr,
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
    print(json.dumps(response))

def updateDB(table, key, update_expr, expr_vals):
    dynamodb = boto3.resource('dynamodb', region_name='us-west-2', endpoint_url=application.config['DB_ENDPOINT'])
    table = dynamodb.Table(table)

    table.update_item(Key=key,
                      UpdateExpression=update_expr,
                      ExpressionAttributeValues=expr_vals,  
                     )

