from flask import Flask

application = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'
