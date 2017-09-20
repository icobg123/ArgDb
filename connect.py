import os

import datetime
import uuid

import jsonschema
from bson import regex
from flask import Flask, jsonify, session, abort, request, render_template, redirect, url_for, \
    send_from_directory
from flask_pymongo import PyMongo
from flask.helpers import flash
from jsonschema import validate
from jsonschema import Draft3Validator
from jsonschema import Draft4Validator
from bson import json_util
from passlib.apps import custom_app_context as pwd_context
import json
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.wsgi import SharedDataMiddleware

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'

app.config['MONGO_DBNAME'] = 'argdbconnect'
app.config[
    'MONGO_URI'] = 'mongodb://argdb:argdbnapier@ds137191.mlab.com:37191/argdbconnect'
mongo = PyMongo(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

argument_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "id": "http://example.com/example.json",
    "properties": {
        "analyst_email": {
            "default": "siwells@gmail.com",
            "description": "An explanation about the purpose of this instance.",
            "id": "/properties/analyst_email",
            "pattern": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$)",
            "title": "The analyst_email schema",
            "type": "string"
        },
        "analyst_name": {
            "default": "Simon Wells",
            "description": "An explanation about the purpose of this instance.",
            "id": "/properties/analyst_name",
            "title": "The analyst_name schema",
            "type": "string"
        },
        "created": {
            "default": "2017-07-11T16:32:36",
            "description": "An explanation about the purpose of this instance.",
            "id": "/properties/created",
            "title": "The created schema",
            "type": "string"
        },
        "edges": {
            "id": "/properties/edges",
            "items": {
                "id": "/properties/edges/items",
                "properties": {
                    "id": {
                        "default": "d7bcef81-0d74-4ae5-96f9-bfb07031f1fa",
                        "description": "The id of the edge",
                        "id": "/properties/edges/items/properties/id",
                        "maxLength": 19,
                        "pattern": "(((\\d|[a-zA-Z]){4})\\-){3}(\\d|[a-zA-Z]){4}",
                        "title": "The id schema",
                        "type": "string"
                    },
                    "source_id": {
                        "default": "49a786ce-9066-4230-8e18-42086882a160",
                        "description": "The Id of the node from which the Edge begins",
                        "id": "/properties/edges/items/properties/source_id",
                        "maxLength": 19,
                        "pattern": "(((\\d|[a-zA-Z]){4})\\-){3}(\\d|[a-zA-Z]){4}",
                        "title": "The source_id schema",
                        "type": "string"
                    },
                    "target_id": {
                        "default": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45",
                        "description": "The Id of the node from at which the Edge ends",
                        "id": "/properties/edges/items/properties/target_id",
                        "maxLength": 19,
                        "pattern": "(((\\d|[a-zA-Z]){4})\\-){3}(\\d|[a-zA-Z]){4}",
                        "title": "The target_id schema",
                        "type": "string"
                    }
                },
                "required": [
                    "id",
                    "target_id",
                    "source_id"
                ],
                "type": "object"
            },
            "type": "array"
        },
        "edited": {
            "default": "2017-07-11T16:32:36",
            "description": "An explanation about the purpose of this instance.",
            "id": "/properties/edited",
            "title": "The edited schema",
            "type": "string"
        },
        "id": {
            "default": "94a975db-25ae-4d25-93cc-1c07c932e2f8",
            "description": "The Id of the document (argument scheme/a)",
            "id": "/properties/id",
            "maxLength": 19,
            "pattern": "(((\\d|[a-zA-Z]){4})\\-){3}(\\d|[a-zA-Z]){4}",
            "title": "The id schema",
            "type": "string"
        },
        "metadata": {
            "id": "/properties/metadata",
            "properties": {
                "description": "This accepts anything, as long as it's valid JSON.",
                "title": "Empty Object"
            },
            "type": "object"
        },
        "nodes": {
            "id": "/properties/nodes",
            "items": {
                "properties": {
                    "id": {
                        "default": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45",
                        "description": "The Id of the node",
                        "maxLength": 19,
                        "pattern": "(((\\d|[a-zA-Z]){4})\\-){3}(\\d|[a-zA-Z]){4}",
                        "type": "string"
                    },
                    "metadata": {
                        "type": "object"
                    },
                    "sources": {
                        "type": "array"
                    },
                    "text": {
                        "type": "string"
                    },
                    "type": {
                        "default": "atom",
                        "pattern": "\\b(atom|scheme)\\b",
                        "type": "string"
                    }
                },
                "required": [
                    "id",
                    "type"
                ],
                "type": "object"
            },
            "type": "array"
        },
        "resources": {
            "type": "array"
        }
    },
    "required": [
        "id",
        "nodes",
        "edges",
        "created",
        "analyst_email",
        "analyst_name",
        "edited"
    ],
    "type": "object"
}

app.config['ALLOWED_EXTENSIONS'] = set(['json'])


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        users = mongo.db.users
        token = None

        if 'username' in session:
            login_user = users.find_one({'name': session['username']})
            token = login_user.get('token')
            # if 'x-access-token' in request.headers:

            # token =
            # TODO: Figure out how to pull the token data for the correct user
            # token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            token_data = jwt.decode(token, app.config['SECRET_KEY'])
            # current_user = users.find_one({'name': session['username']})
            current_user = users.find_one({'public_id': token_data['public_id']})
            # current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    argument = mongo.db.argument
    # schema = open("uploads/schema.json").read()
    # data = open("uploads/correct_format.json").read()
    # Header Data for debugging
    req_headers = request.headers
    if request.method == 'POST':
        # check if the post request has the file part
        if request.files['file'].filename == '':
            err = "Please select a File."
            return render_template('upload.html', err=err, argument_schema=argument_schema)
        else:
            file = request.files['file']
            filename = secure_filename(file.filename)

            if filename and allowed_file(file.filename):
                parsed_to_string = file.read().decode("utf-8")
                parsed_to_json = json.loads(parsed_to_string)
                # parsed_to_json = request.get_json()
                # TODO: the validator checks against the schema and inserts the provided json only if it contains the
                # TODO: required fields and it will upload it to the
                v = Draft4Validator(argument_schema)
                # if Draft3Validator(schema).is_valid([2, 3, 4]):
                if v.is_valid(parsed_to_json):
                    post_id = argument.insert_one(parsed_to_json).inserted_id
                valid = v.is_valid(parsed_to_json)
                if valid:
                    outcome = "Successful Upload"
                else:
                    outcome = "Unsuccessful Upload"

                # if validate(parsed_to_json, schema):
                #     post_id = argument.insert_one(parsed_to_json).inserted_id
                # parsed_to_json_type = json.dumps(parsed_to_json)
                return render_template('upload_results.html', json_parsed=parsed_to_json, outcome=outcome, validator=v,
                                       req_headers=req_headers,
                                       string_parsed=parsed_to_string,
                                       type=valid)  # 201 to show that the upload was successful
            else:
                err = "Wrong file extension. Please upload a JSON document."
                return render_template('upload.html', err=err, argument_schema=argument_schema)

    return render_template('upload.html', argument_schema=argument_schema)


@app.route('/handle_data', methods=['POST'])
def handle_data():
    projectpath = request.form['projectFilepath']
    # your code


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)


app.add_url_rule('/uploads/<filename>', 'uploaded_file',
                 build_only=True)
app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
    '/uploads': app.config['UPLOAD_FOLDER']
})


@app.route('/', methods=['GET', 'POST'])
def home():
    err = None

    if request.method == 'POST':
        if not request.form['argumentString']:
            err = 'Please provide a search term'
        # elif not request.form['region']:
        #     err = 'Please set your region'
        else:
            argumentString = request.form['argumentString']

            return redirect(url_for('get_one_argument', argString=argumentString))

    return render_template('homepage.html', err=err)


@app.route('/argument', methods=['GET'])
def get_all_arguments():
    argument = mongo.db.argument

    output = []

    for q in argument.find():
        output.append({"name": q["name"], "contents": q["contents"]})

    output = json.dumps(output)
    # jsont = ({'result': output})
    # r = json.dumps(output)
    # print(type(r))
    # loaded_r = json.load(r)
    return render_template('search_results.html', json=output)


@app.route('/argument/<argString>', methods=['GET'])
def get_one_argument(argString):
    argument = mongo.db.argument
    argString = argString.replace(" ", "|")
    typeOF = type(argString)
    # TODO: Separate into /api/ and /web/
    # search_wordss = []
    #
    # for search_words in argString:
    #     search_wordss.append('/' + search_words + '/')
    # q = argument.find_one({'name': name})

    # mongo.db.argument.ensure_index([('name': 'text')], 'name' = 'search_index')

    # argument.create_index([("name", "text")])

    # qs = argument.find({"name": {'$regex': argString, '$options': 'i'}})
    # qs = argument.find({"name": {'$in': argString}})

    qss = argument.find({"$text": {"$search": argString}}).count()
    # qss = argument.find({"$text": {"$search": argString}}).count()

    with_regex = argument.find(
        {"nodes.text": {'$regex': ".*" + argString + ".*", "$options": "i"}})
    # with_regex_1 = argument.find(
    #     {"name": {'$regex': ".*" + argString + ".*", '$options': 'i'}})
    # TODO: counts how many results were found

    count_me = with_regex.count()
    # q = list(argument.find({'$text:': {'$search': argString}}))

    # if q:
    #     output = {'name': q['name'], 'contents': q['contents']}
    # else:
    #     output = 'No results Found'

    output = []
    for q in with_regex:
        output.append({
            # "MongoDB ID": q["_id"],
            "Analyst Email": q["analyst_email"],
            "Analyst Name": q["analyst_name"],
            "Created": q["created"],
            "Edges": q["edges"],
            "Edited": q["edited"],
            "id": q["id"],
            "Metadata": q["metadata"],
            "Nodes": q["nodes"],
            "Resources": q["resources"],

        })

        # output = json.dumps(output, sort_keys=True, indent=4, separators=(',', ': '))
    # with_regex = jsonify(with_regex)
    typeOF = type(output)
    return render_template('search_results.html', json=output, typeof=typeOF,
                           argString=argString,
                           with_regex=with_regex,
                           cursor=count_me)


# return jsonify({'result': output})


@app.route('/argument', methods=['POST'])
def add_argument():
    argument = mongo.db.argument

    name = request.json['name']
    contents = request.json['contents']

    argument_id = argument.insert({'name': name, 'contents': contents})

    new_argument = argument.find_one({'_id': argument_id})

    output = {'name': new_argument['name'], 'contents': new_argument['contents']}

    return jsonify({'result': output})


# Disable caching for development purposes
@app.after_request
def apply_caching(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response


# Display JSON neatly in the templates
def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


# Add a custom filter to Jinja2
app.jinja_env.filters['tojson_pretty'] = to_pretty_json


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'name': request.form['username']})
        # existing_user = users.find({'name': request.form['username']}, {"id": 1}).limit(1)
        # asd = users.find({"id": parsed_to_json.get("id")}, {"id": 1}).limit(1)
        # existing_user = users.find_one({'name': request.form['username']})

        if existing_user is None:
            hased_pass = generate_password_hash(request.form['pass'], method='sha256')
            # hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
            users.insert({'public_id': uuid.uuid4().hex, 'name': request.form['username'], 'password': hased_pass,
                          'token': '123'})
            session['username'] = request.form['username']
            return redirect(url_for('login'))

        return 'That username already exists!'

    return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        users = mongo.db.users
        login_user = users.find_one({'name': request.form['username']})

        if login_user:
            if check_password_hash(login_user.get('password'), request.form['pass']):
                # if pwd_context.verify(request.form['pass'], login_user['password']):
                session['username'] = request.form['username']
                # Cretion of the Token
                token = jwt.encode(
                    {'public_id': login_user.get('public_id'),
                     'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
                    app.config['SECRET_KEY'])
                users.update_one(
                    {"_id": login_user.get('_id')},
                    {
                        "$set": {
                            "token": token

                        }
                    }
                )
                session['token'] = token.decode('UTF-8')
                # session['user_id'] = login_user.get('_id')
                # return session['username']
                return redirect(url_for('index'))

        return 'Invalid username/password combination'

    return render_template('index.html')


@app.route('/user_page')
@token_required
def index(current_user):
    users = mongo.db.users
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        token = login_user.get('token')

        user_id = current_user.get('public_id')
        # admin = str(current_user.get('admin'))
        if not current_user.get('admin'):
            admin = "no admin"
        else:
            admin = "yes admin"

        # return 'You are logged in as ' + jsonify(current_user) + " " + token.decode(
        #     'UTF-8') + " Current User "
        return 'You are logged in as ' + user_id + " " + token.decode(
            'UTF-8') + " Current User " + admin

    return render_template('index.html')


if __name__ == '__main__':
    app.secret_key = 'mysecret'
    app.run(debug=True)
