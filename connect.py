import os

from flask.globals import current_app
from flask_mail import Mail, Message
# from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired,
                          URLSafeTimedSerializer)
import datetime
import uuid
from datetime import timedelta
from typing import re
import sadface
import graphviz
from flask_paginate import Pagination, get_page_parameter, get_page_args
from graphviz import Source
import jsonschema
from bson import regex
from flask import Flask, jsonify, session, abort, request, render_template, redirect, Markup, url_for, \
    send_from_directory
from flask_pymongo import PyMongo, pymongo
from flask.helpers import flash
from jsonschema import validate
from jsonschema import Draft3Validator
from jsonschema import Draft4Validator
from bson import json_util
# from flask_paginate import Pagination, get_page_args
from passlib.apps import custom_app_context as pwd_context
import json
import jwt
import re
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.wsgi import SharedDataMiddleware

os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin/'

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config.from_pyfile('config.cfg')
s = URLSafeTimedSerializer('Thisisasecret!')
app.config['MONGO_DBNAME'] = 'argdbconnect'
app.config[
    'MONGO_URI'] = 'mongodb://argdb:argdbnapier@ds137191.mlab.com:37191/argdbconnect'
mongo = PyMongo(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Regex for IDs - [a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}
# Regex for Email - (^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)
argument_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "id": "http://example.com/example.json",
    "properties": {
        "sadface": {
            "id": "/properties/sadface",
            "properties": {
                "analyst_email": {
                    "default": "siwells@gmail.com",
                    "description": "An explanation about the purpose of this instance.",
                    "id": "/properties/sadface/properties/analyst_email",
                    "title": "The analyst_email schema",
                    "type": "string"
                },
                "analyst_name": {
                    "default": "Simon Wells",
                    "description": "An explanation about the purpose of this instance.",
                    "id": "/properties/sadface/properties/analyst_name",
                    "title": "The analyst_name schema",
                    "type": "string"
                },
                "created": {
                    "default": "2017-07-11T16:32:36",
                    "description": "An explanation about the purpose of this instance.",
                    "id": "/properties/sadface/properties/created",
                    "title": "The created schema",
                    "type": "string"
                },
                "edges": {
                    "id": "/properties/sadface/properties/edges",
                    "items": {
                        "id": "/properties/sadface/properties/edges/items",
                        "properties": {
                            "id": {
                                "default": "d7bcef81-0d74-4ae5-96f9-bfb07031f1fa",
                                "description": "An explanation about the purpose of this instance.",
                                "id": "/properties/sadface/properties/edges/items/properties/id",
                                "title": "The id schema",
                                "type": "string"
                            },
                            "source_id": {
                                "default": "49a786ce-9066-4230-8e18-42086882a160",
                                "description": "An explanation about the purpose of this instance.",
                                "id": "/properties/sadface/properties/edges/items/properties/source_id",
                                "title": "The source_id schema",
                                "type": "string"
                            },
                            "target_id": {
                                "default": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45",
                                "description": "An explanation about the purpose of this instance.",
                                "id": "/properties/sadface/properties/edges/items/properties/target_id",
                                "title": "The target_id schema",
                                "type": "string"
                            }
                        },
                        "type": "object"
                    },
                    "type": "array"
                },
                "edited": {
                    "default": "2017-07-11T16:32:36",
                    "description": "An explanation about the purpose of this instance.",
                    "id": "/properties/sadface/properties/edited",
                    "title": "The edited schema",
                    "type": "string"
                },
                "id": {
                    "default": "94a975db-25ae-4d25-93cc-1c07c932e2f8",
                    "description": "An explanation about the purpose of this instance.",
                    "id": "/properties/sadface/properties/id",
                    "title": "The id schema",
                    "type": "string"
                },
                "metadata": {
                    "id": "/properties/sadface/properties/metadata",
                    "properties": {
                        "description": "This accepts anything, as long as it's valid JSON.",
                        "title": "Empty Object"
                    },
                    "type": "object"
                },
                "nodes": {
                    "id": "/properties/sadface/properties/nodes",
                    "items": {
                        "id": "/properties/sadface/properties/nodes/items",
                        "properties": {
                            "id": {
                                "default": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45",
                                "description": "An explanation about the purpose of this instance.",
                                "id": "/properties/sadface/properties/nodes/items/properties/id",
                                "title": "The id schema",
                                "type": "string"
                            },
                            "metadata": {
                                "id": "/properties/sadface/properties/nodes/items/properties/metadata",
                                "properties": {
                                    "description": "This accepts anything, as long as it's valid JSON.",
                                    "title": "Empty Object"
                                },
                                "type": "object"
                            },
                            "sources": {
                                "id": "/properties/sadface/properties/nodes/items/properties/sources",
                                "items": {
                                    "description": "This accepts anything, as long as it's valid JSON.",
                                    "title": "Empty Object"
                                },
                                "type": "array"
                            },
                            "text": {
                                "default": "The 'Hang Back' campaign video should not have been published, and should be withdrawn.",
                                "description": "An explanation about the purpose of this instance.",
                                "id": "/properties/sadface/properties/nodes/items/properties/text",
                                "title": "The text schema",
                                "type": "string"
                            },
                            "type": {
                                "default": "atom",
                                "description": "An explanation about the purpose of this instance.",
                                "id": "/properties/sadface/properties/nodes/items/properties/type",
                                "title": "The type schema",
                                "type": "string"
                            }
                        },
                        "type": "object"
                    },
                    "type": "array"
                },
                "resources": {
                    "id": "/properties/sadface/properties/resources",
                    "items": {
                        "description": "This accepts anything, as long as it's valid JSON.",
                        "title": "Empty Object"
                    },
                    "type": "array"
                }
            },
            "type": "object"
        }
    },
    "type": "object"
}

argument_schema_bck = {
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

                        "title": "The id schema",
                        "type": "string"
                    },
                    "source_id": {
                        "default": "49a786ce-9066-4230-8e18-42086882a160",
                        "description": "The Id of the node from which the Edge begins",
                        "id": "/properties/edges/items/properties/source_id",
                        "maxLength": 19,

                        "title": "The source_id schema",
                        "type": "string"
                    },
                    "target_id": {
                        "default": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45",
                        "description": "The Id of the node from at which the Edge ends",
                        "id": "/properties/edges/items/properties/target_id",
                        "maxLength": 19,

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

mail = Mail(app)


def clever_function():
    return u'HELLO'


app.jinja_env.globals.update(clever_function=clever_function)


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)


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
    # if request.method == 'POST':
    #     if request.form['argumentString']:
    #         return search_for_arg()
    argument = mongo.db.argument
    # schema = open("uploads/schema.json").read()
    # data = open("uploads/correct_format.json").read()
    # Header Data for debugging
    users = mongo.db.users
    username = ""
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        username = login_user.get('name')
        public_id = login_user.get('public_id')
    else:
        public_id = "Unregistered User"

    req_headers = request.headers
    if request.method == 'POST':
        # if request.form['btn'] == 'Upload':
        if 'btn' in request.form:
            # if request.form['argumentString']:
            #     return search_for_arg()
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
                        parsed_to_json['uploader'] = public_id
                        post_id = argument.insert_one(parsed_to_json).inserted_id
                    valid = v.is_valid(parsed_to_json)
                    if valid:
                        outcome = "Successful Upload"
                    else:
                        outcome = "Unsuccessful Upload"

                    # if validate(parsed_to_json, schema):
                    #     post_id = argument.insert_one(parsed_to_json).inserted_id
                    # parsed_to_json_type = json.dumps(parsed_to_json)
                    return render_template('upload_results.html', json_parsed=parsed_to_json, outcome=outcome,
                                           validator=v,
                                           req_headers=req_headers,
                                           string_parsed=parsed_to_string,
                                           current_user=username,
                                           type=valid)  # 201 to show that the upload was successful
                else:
                    err = "Wrong file extension. Please upload a JSON document."
                    return render_template('upload.html', err=err, argument_schema=argument_schema,
                                           current_user=username)
        elif 'argumentString' in request.form:
            return search_for_arg()

    return render_template('upload.html', argument_schema=argument_schema, current_user=username)


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


def search_for_arg():
    users = mongo.db.users
    username = ""
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        username = login_user.get('name')
    if not request.form['argumentString']:
        err = 'Please provide a search term'
        return render_template('homepage.html', err=err, current_user=username)

        # elif not request.form['region']:
    # err = 'Please set your region'
    else:
        argumentString = request.form['argumentString']

        return redirect(url_for('get_one_argument', argString=argumentString))


@app.route('/', methods=['GET', 'POST'])
def home():
    err = None
    users = mongo.db.users
    username = ""
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        username = login_user.get('name')

    if request.method == 'POST':
        return search_for_arg()
        # return search_for_arg(username)

    # if request.method == 'POST':
    #     if not request.form['argumentString']:
    #         err = 'Please provide a search term'
    #     # elif not request.form['region']:
    #     #     err = 'Please set your region'
    #     else:
    #         argumentString = request.form['argumentString']
    #
    #         return redirect(url_for('get_one_argument', argString=argumentString))

    return render_template('homepage.html', err=err, current_user=username)


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


@app.route('/argument/by/<ArgId>', methods=['GET', 'POST'])
# @token_required
def get_argument_by_id(ArgId):
    if 'argumentString' in request.form:
        if request.form['argumentString']:
            return search_for_arg()

    # if not current_user.get('admin'):
    #     return jsonify({'message': 'Cannot perform that function!'})
    users = mongo.db.users
    username = ""
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        username = login_user.get('name')
    argument = mongo.db.argument
    # ArgId = ArgId.replace(" ", "|")
    search_results = argument.find_one({"sadface.id": {'$regex': ".*" + ArgId + ".*", "$options": "i"}})
    sadface_results = search_results.get("sadface", {})
    result = sadface_results.get('id')
    arg_found = json.dumps({'argument IDs': ({
        "Analyst Email": sadface_results.get("analyst_email"),
        "Analyst Name": sadface_results.get("analyst_name"),
        "Created": sadface_results.get("created"),
        "Edges": sadface_results.get("edges"),
        "Edited": sadface_results.get("edited"),
        "id": sadface_results.get("id"),
        "Metadata": sadface_results.get("metadata"),
        "Nodes": sadface_results.get("nodes"),
        "Resources": sadface_results.get("resources")})}, sort_keys=False, indent=2)

    sadface.sd = sadface_results
    dot_string = sadface.export_dot()
    graph = graphviz.Source(dot_string, format='svg')

    return render_template('single_arg.html', argument=arg_found, arg_id=result, current_user=username,
                           graph=Markup(graph.pipe().decode('utf-8')))


# # TODO: Advamced Search
# @app.route('/advanced_search', methods=['GET', 'POST'])
# # @token_required
# def advanced_search():
#     if 'argumentString' in request.form:
#         if request.form['argumentString']:
#             return search_for_arg()
#
#     # if not current_user.get('admin'):
#     #     return jsonify({'message': 'Cannot perform that function!'})
#     users = mongo.db.users
#     username = ""
#     if 'username' in session:
#         login_user = users.find_one({'name': session['username']})
#         username = login_user.get('name')
#     argument = mongo.db.argument
#     analyst_email = request.form.get('analyst_email')
#     analyst_name = request.form.get('analyst_name')
#     ArgId = "icara".replace(" ", "|")
#     search_results = argument.find({"sadface.analyst_email": analyst_email, "sadface.analyst_name": analyst_name})
#     # search_results = argument.find_one({"sadface.id": {'$regex': ".*" + ArgId + ".*", "$options": "i"}})
#     sadface_results = search_results.get("sadface", {})
#     result = sadface_results.get('id')
#     arg_found = json.dumps({'argument IDs': ({
#         "Analyst Email": sadface_results.get("analyst_email"),
#         "Analyst Name": sadface_results.get("analyst_name"),
#         "Created": sadface_results.get("created"),
#         "Edges": sadface_results.get("edges"),
#         "Edited": sadface_results.get("edited"),
#         "id": sadface_results.get("id"),
#         "Metadata": sadface_results.get("metadata"),
#         "Nodes": sadface_results.get("nodes"),
#         "Resources": sadface_results.get("resources")})}, sort_keys=False, indent=2)
#
#     sadface.sd = sadface_results
#     dot_string = sadface.export_dot()
#     graph = graphviz.Source(dot_string, format='svg')
#
#     return render_template('advanced_search.html', argument=arg_found, arg_id=result, current_user=username,
#                            graph=Markup(graph.pipe().decode('utf-8')))
#

# TODO: Advamced Searcj
@app.route('/advanced_search', methods=['GET', 'POST'])
# @app.route('/advanced_search?page=1', methods=['GET', 'POST'])
# @token_required
def advanced_search():
    if request.method == 'POST' and 'argumentString' in request.form:
        return search_for_arg()
    err = None
    users = mongo.db.users
    username = ""
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        username = login_user.get('name')

    if 'analyst_name' in session and 'analyst_email' in session and 'id' in session:
        session.pop('analyst_name', None)
        session.pop('analyst_email', None)
        session.pop('id', None)

    return render_template('advanced_search.html', current_user=username, err=err)


@app.route('/advanced_search_results', methods=['GET', 'POST'])
# @token_required
def advanced_search_find():
    users = mongo.db.users
    username = ""
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        username = login_user.get('name')

    if request.method == 'GET' and 'analyst_name' not in session and 'analyst_email' not in session and 'id' not in session:
        return redirect(url_for('advanced_search'))

        # if (request.form['analyst_name'] == "" and request.form['analyst_email'] == "" and request.form[
        #     'document_id'] == "") and (request.method == 'GET'
        #                                and 'analyst_name' not in session
        #                                and 'analyst_email' not in session
        #                                and 'id' not in session):
        #     err = "Please fill in at least one field"
        #     return render_template('advanced_search.html', err=err, current_user=username)
        # return redirect(url_for('advanced_search', err=err))

    if 'analyst_name' and 'analyst_email' and 'document_id' in request.form:
        if not (request.form['analyst_name'] or request.form['analyst_email'] or request.form['document_id']):
            err = 'Please fill in at least one field'
            return render_template('advanced_search.html', err=err)

    if request.method == 'POST' and 'argumentString' in request.form:
        return search_for_arg()

    argument = mongo.db.argument
    err = None
    page, per_page, offset = get_page_args()
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    # page, per_page, offset = get_page_args()
    # per_page = 5
    # page = request.args.get(get_page_parameter(), type=int, default=1)
    # offset = int(request.args['offset'])
    # limit = int(request.args['limit'])
    # typeOF = type(argString)
    # TODO: Separate into /api/ and /web/
    per_page = 10
    offset = (page - 1) * per_page

    # argString = argString.replace(" ", "|")
    # if 'advanced_search' in request.form or request.args.get('page') or 'analyst_email' in session:
    #
    # if 'analyst_email' in session:
    #     analyst_email = session['analyst_email']
    # else:
    #     analyst_email = request.form['analyst_email']
    #     session['analyst_email'] = request.form['analyst_email']
    #
    # if 'analyst_name' in session:
    #     analyst_name = session['analyst_name']
    # else:
    #     analyst_name = request.form['analyst_name']
    #     session['analyst_name'] = request.form['analyst_name']

    # if (not request.form.get('analyst_email')) or (not request.form.get('analyst_name')):

    # search_fields = {"analyst_email": analyst_email, "analyst_name": analyst_name}

    # for field, value in search_fields.items():
    #     if str(field) in session and not request.form.get(str(field)):
    #         # search_fields[str(field)] = session[str(field)]
    #         value = session[str(field)]
    #     else:
    #         value = request.form[str(field)]
    #         # search_fields[str(field)] = request.form[str(field)]
    #         session[str(field)] = request.form[str(field)]

    if 'analyst_name' in session and not request.form.get('analyst_name'):
        analyst_name = session['analyst_name']
    else:
        analyst_name = request.form['analyst_name']
        session['analyst_name'] = request.form['analyst_name']

    if 'analyst_email' in session and not request.form.get('analyst_email'):
        analyst_email = session['analyst_email']
    else:
        analyst_email = request.form['analyst_email']
        session['analyst_email'] = request.form['analyst_email']
    if 'id' in session and not request.form.get('document_id'):
        id = session['id']
    else:
        id = request.form['document_id']
        session['id'] = request.form['document_id']

    # analyst_email = request.form.get('analyst_email')
    # analyst_name = request.form.get('analyst_name')
    ArgId = "icara".replace(" ", "|")

    # search_results = argument.find(
    #     {"sadface.nodes.text": {'$regex': ".*" + argString + ".*", "$options": "i"}}).skip(offset).limit(per_page)

    search_fields = {"analyst_email": analyst_email, "analyst_name": analyst_name, "id": id}
    populated_search_fields = []
    query_dict = {}
    # for each item in the form check if it has information inside and adds it to a list with all query parameters
    for key, value in search_fields.items():
        if value:
            populated_search_fields.append(key)

    # for each query parameter add its contents to a dict in order to
    # create the query which to pass to the mongoGB search function
    for field in populated_search_fields:
        query_dict['sadface.' + field] = search_fields[field]

    f = request.data
    # for key in f.keys():
    #     for value in f.getlist(key):
    #         search_fields.append(key + ":" + value)
    # print(key, ":", value)
    # search_results = argument.find(
    #     {"sadface.analyst_email": analyst_email, "sadface.analyst_name": analyst_name}).skip(offset).limit(per_page)

    search_results = argument.find(query_dict).skip(offset).limit(per_page)
    count_me = search_results.count()
    # last_id = search_results[offset]['_id']
    # pagination = Pagination(page=page, total=search_results.count(), search=search, record_name='users')
    pagination = get_pagination(page=page,
                                per_page=per_page,
                                total=count_me,
                                offset=offset,
                                formreq=f,
                                record_name='users',
                                format_total=True,
                                format_number=True,
                                )
    # documents = argument.find({'_id': {'$lte': last_id}}).sort('_id', pymongo.DESCENDING).limit(limit)
    # # TODO: counts how many results were found
    # next_url = '/argument/' + argString.replace("|", "+") + "?limit=" + str(limit) + '&offset=' + str(offset + limit)
    # prev_url = '/argument/' + argString.replace("|", "+") + "?limit=" + str(limit) + '&offset=' + str(offset - limit)
    # (total, processed_text1) = argument.ProcessQuery(search_results, offset, per_page)  # MongoDB query
    nodes_text = []
    output = []
    for q in search_results:
        output.append({
            # "MongoDB ID": q["_id"],
            "Analyst Email": q['sadface']["analyst_email"],
            "Analyst Name": q['sadface']["analyst_name"],
            "Created": q['sadface']["created"],
            "Edges": q['sadface']["edges"],
            "Edited": q['sadface']["edited"],
            "id": q['sadface']["id"],
            # "Metadata": q['sadface']["metadata"],
            "Nodes": q['sadface']["nodes"],
            # "Resources": q['sadface']["resources"],

        })

    # For each doc that matches the search result go through all nodes and return the text which contains the search
    # for document in output:
    #     for node in document['Nodes']:
    #         if 'text' in node:
    #             if re.search(r".*" + argString + r".*", node['text'], re.IGNORECASE):
    #                 wordLimit = 10
    #                 text = node['text'].split(' ')
    #                 firstNwords = ' '.join(text[:wordLimit])
    #                 if len(text) > wordLimit:
    #                     firstNwords += "..."
    #                 nodes_text.append(firstNwords)
    #                 break

    # output = json.dumps(output, sort_keys=True, indent=4, separators=(',', ': '))
    # with_regex = jsonify(with_regex)
    # pagination = Pagination(page=page, per_page=per_page, offset=offset,
    #                         total=count_me, record_name='List')
    typeOF = type(output)
    return render_template('advanced_search_results.html', json=output, typeof=typeOF,
                           populated_search_fields=populated_search_fields,
                           search_fields=search_fields,
                           search_results=search_results,
                           current_user=username,
                           # search_nodes=nodes_text,
                           pagination=pagination,
                           page=page,
                           per_page=per_page,
                           cursor=count_me)


@app.route('/argument/<argString>+', methods=['GET', 'POST'])
def get_one_argument(argString):
    if request.method == 'POST':
        return search_for_arg()

    users = mongo.db.users
    username = ""
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        username = login_user.get('name')
    argument = mongo.db.argument
    argString = argString.replace(" ", "|")
    # search = False
    # q = argString
    # if q:
    #     search = True
    # page = request.args.get(get_page_parameter(), type=int, default=1)
    page, per_page, offset = get_page_args()
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    # page, per_page, offset = get_page_args()
    # per_page = 5
    # page = request.args.get(get_page_parameter(), type=int, default=1)
    # offset = int(request.args['offset'])
    # limit = int(request.args['limit'])
    typeOF = type(argString)
    # TODO: Separate into /api/ and /web/
    per_page = 10
    offset = (page - 1) * per_page
    search_results = argument.find(
        {"sadface.nodes.text": {'$regex': ".*" + argString + ".*", "$options": "i"}}).skip(offset).limit(per_page)

    count_me = search_results.count()
    # last_id = search_results[offset]['_id']
    # pagination = Pagination(page=page, total=search_results.count(), search=search, record_name='users')
    pagination = get_pagination(page=page,
                                per_page=per_page,
                                total=count_me,
                                offset=offset,
                                record_name='users',
                                format_total=True,
                                format_number=True,
                                )
    # documents = argument.find({'_id': {'$lte': last_id}}).sort('_id', pymongo.DESCENDING).limit(limit)
    # # TODO: counts how many results were found
    # next_url = '/argument/' + argString.replace("|", "+") + "?limit=" + str(limit) + '&offset=' + str(offset + limit)
    # prev_url = '/argument/' + argString.replace("|", "+") + "?limit=" + str(limit) + '&offset=' + str(offset - limit)
    # (total, processed_text1) = argument.ProcessQuery(search_results, offset, per_page)  # MongoDB query
    nodes_text = []
    output = []
    for q in search_results:
        output.append({
            # "MongoDB ID": q["_id"],
            "Analyst Email": q['sadface']["analyst_email"],
            "Analyst Name": q['sadface']["analyst_name"],
            "Created": q['sadface']["created"],
            "Edges": q['sadface']["edges"],
            "Edited": q['sadface']["edited"],
            "id": q['sadface']["id"],
            # "Metadata": q['sadface']["metadata"],
            "Nodes": q['sadface']["nodes"],
            # "Resources": q['sadface']["resources"],

        })

    # For each doc that matches the search result go through all nodes and return the text which contains the search
    for document in output:
        for node in document['Nodes']:
            if 'text' in node:
                if re.search(r".*" + argString + r".*", node['text'], re.IGNORECASE):
                    wordLimit = 10
                    text = node['text'].split(' ')
                    firstNwords = ' '.join(text[:wordLimit])
                    if len(text) > wordLimit:
                        firstNwords += "..."
                    nodes_text.append(firstNwords)
                    break

    # output = json.dumps(output, sort_keys=True, indent=4, separators=(',', ': '))
    # with_regex = jsonify(with_regex)
    # pagination = Pagination(page=page, per_page=per_page, offset=offset,
    #                         total=count_me, record_name='List')
    typeOF = type(output)
    return render_template('search_results.html', json=output, typeof=typeOF,
                           argString=argString,
                           search_results=search_results,
                           current_user=username,
                           search_nodes=nodes_text,
                           pagination=pagination,
                           page=page,
                           per_page=per_page,
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


# TODO: Check if email is unique figure out how to reset passwords etc
@app.route('/register', methods=['POST', 'GET'])
def register():
    err = None
    if request.method == 'POST':
        if 'argumentString' in request.form:
            if request.form['argumentString']:
                return search_for_arg()
        elif 'username' and 'pass' and 'email' in request.form:
            if not (request.form['username'] and request.form['email'] and request.form['pass']):
                err = 'Please fill in all fields'
                return render_template('register.html', err=err)
            # if not request.form['email']:
            #     err = 'mail'
            #     return render_template('register.html', err=err)
            # if not request.form['pass']:
            #     err = 'pass'
            #     return render_template('register.html', err=err)
            users = mongo.db.users
            existing_user = users.find_one({'name': request.form['username']})
            existing_email = users.find_one({'email': request.form['email']})
            # existing_user = users.find({'name': request.form['username']}, {"id": 1}).limit(1)
            # asd = users.find({"id": parsed_to_json.get("id")}, {"id": 1}).limit(1)
            # existing_user = users.find_one({'name': request.form['username']})

            if existing_user is not None:
                err = "Username already exists"
                return render_template('register.html', err=err)
            elif existing_email is not None:
                err = "Email already exists"
                return render_template('register.html', err=err)
            else:
                hased_pass = generate_password_hash(request.form['pass'], method='sha256')
                public_id = uuid.uuid4().hex
                token = jwt.encode(
                    {'public_id': public_id,
                     # 'exp': datetime.datetime.utcnow()},
                     'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
                    app.config['SECRET_KEY'])
                # hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
                users.insert({'public_id': public_id, 'name': request.form['username'], 'password': hased_pass,
                              'token': token,
                              'email': request.form['email'],
                              'admin': False,
                              })

                email = request.form['email']
                token = s.dumps(email, salt='email-confirm')

                msg = Message('Confirm Email', sender='icobg123@gmail.com', recipients=[email])

                link = url_for('confirm_email', token=token, _external=True)

                msg.body = 'Your link is {}'.format(link)

                mail.send(msg)
                # session['username'] = request.form['username']
                return redirect(url_for('login'))

                # err = "Username already exists"
                # return render_template('register.html', err=err)

    return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if 'username' in session:
        return redirect(url_for('account'))
    if request.method == 'POST':
        if 'argumentString' in request.form:
            if request.form['argumentString']:
                return search_for_arg()
        # if request.form['argumentString']:
        #     return search_for_arg()
        elif 'username' and 'pass' in request.form:
            users = mongo.db.users
            login_user = users.find_one({'name': request.form['username']})

            if login_user:
                if check_password_hash(login_user.get('password'), request.form['pass']):
                    # if pwd_context.verify(request.form['pass'], login_user['password']):
                    session['username'] = request.form['username']
                    # Cretion of the Token
                    if login_user.get('token'):
                        token = login_user.get('token')
                    else:
                        token = jwt.encode(
                            {'public_id': login_user.get('public_id'),
                             # 'exp': datetime.datetime.utcnow()},
                             'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
                            app.config['SECRET_KEY'])

                        users.update_one({"_id": login_user.get('_id')}, {"$set": {"token": token}})
                    session['token'] = token.decode('UTF-8')
                    session['logged_in'] = True
                    make_session_permanent()
                    # session['user_id'] = login_user.get('_id')
                    # return session['username']
                    return redirect(url_for('account'))

            return 'Invalid username/password combination'

    return render_template('log_ing.html')


@app.route('/account', methods=['POST', 'GET'])
# @token_required
def account():
    if request.method == 'POST':
        if request.form['argumentString']:
            return search_for_arg()
    users = mongo.db.users
    if 'username' in session:
        login_user = users.find_one({'name': session['username']})
        token = login_user.get('token')
        user_email = login_user.get('email')
        # user_id = current_user.get('public_id')
        # admin = str(current_user.get('admin'))
        # if not current_user.get('admin'):
        #     admin = "no admin"
        # else:
        #     admin = "Admin"

        if not login_user.get('admin'):
            privileges = user_email + " Email not verified"
        else:
            privileges = "Email verified " + user_email + " , you can use the API token in the API"

        # return 'You are logged in as ' + jsonify(current_user) + " " + token.decode(
        #     'UTF-8') + " Current User "
        # return 'You are logged in as ' + user_id + " " + token.decode(
        #     'UTF-8') + " Current User " + admin
        return render_template('account.html',
                               current_user=login_user.get('name'),
                               privileges=privileges,
                               # token=token
                               token=token.decode('UTF-8')
                               )

    return render_template('log_ing.html')


@app.route('/logout')
# @login_required
def logout():
    # session.pop('logged_in', None)
    # flash('You were logged out.')
    session.clear()
    # if 'logged_in' not in session:
    #     return redirect(url_for('signin'))
    #
    # session.pop('logged_in', None)
    return redirect(url_for('home'))


@app.route('/confirm_email/<token>')
def confirm_email(token):
    users = mongo.db.users
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        search_for_user = users.find_one({'email': email})
        if search_for_user:
            search_for_user['admin'] = True
            users.save(search_for_user)

    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    return redirect(url_for('login'))
    # return '<h1>The token works!</h1>'


def get_css_framework():
    return current_app.config.get('CSS_FRAMEWORK', 'bootstrap4')


def get_link_size():
    return current_app.config.get('LINK_SIZE', 'sm')


def get_alignment():
    return current_app.config.get('LINK_ALIGNMENT', '')


def show_single_page_or_not():
    return current_app.config.get('SHOW_SINGLE_PAGE', False)


def get_pagination(**kwargs):
    kwargs.setdefault('record_name', 'records')
    return Pagination(css_framework=get_css_framework(),
                      link_size=get_link_size(),
                      alignment=get_alignment(),
                      show_single_page=show_single_page_or_not(),
                      **kwargs
                      )


if __name__ == '__main__':
    app.secret_key = '1234'
    app.run(debug=True)
