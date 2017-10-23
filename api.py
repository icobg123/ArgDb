import os

import graphviz
import jsonschema
from bson import regex
from flask import Flask, jsonify, request, abort, render_template, redirect, url_for, \
    send_from_directory, session, make_response
from flask_pymongo import PyMongo
from flask.helpers import flash
from jsonschema import validate
from jsonschema import Draft3Validator
from jsonschema import Draft4Validator
from jsonschema import ErrorTree
# import pygraphviz as pgv
# from pygraphviz import *
from flask import g
# from pygraphviz import *
# import pygraphviz
from flask_mail import Mail, Message
# from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired,
                          URLSafeTimedSerializer)
from flask_httpauth import HTTPBasicAuth
from jsonschema.exceptions import best_match
from bson import json_util
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from passlib.apps import custom_app_context as pwd_context
from bson.json_util import dumps
import sadface
import json
import uuid
import jwt
import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.wsgi import SharedDataMiddleware

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config.from_pyfile('config.cfg')
# auth = HTTPBasicAuth()
app.config['MONGO_DBNAME'] = 'argdbconnect'
app.config[
    'MONGO_URI'] = 'mongodb://argdb:argdbnapier@ds137191.mlab.com:37191/argdbconnect'
mongo = PyMongo(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# TODO: Regex for the JSON schema
# Regex for IDs - (((\d|[a-zA-Z]){4})\-){3}(\d|[a-zA-Z]){4}
# Regex for Email - (^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)
sd = {}
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
# argument_schema
argument_schema_backup = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "id": "http://example.com/example.json",
    "properties": {
        "analyst_email": {
            "default": "siwells@gmail.com",
            "description": "An explanation about the purpose of this instance.",
            "id": "/properties/analyst_email",
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
                        "title": "The id schema",
                        "type": "string"
                    },
                    "source_id": {
                        "default": "49a786ce-9066-4230-8e18-42086882a160",
                        "description": "The Id of the node from which the Edge begins",
                        "id": "/properties/edges/items/properties/source_id",
                        "title": "The source_id schema",
                        "type": "string"
                    },
                    "target_id": {
                        "default": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45",
                        "description": "The Id of the node from at which the Edge ends",
                        "id": "/properties/edges/items/properties/target_id",
                        "minLength": 5,
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
                "id": "/properties/nodes/items",
                "properties": {
                    "id": {
                        "default": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45",
                        "description": "The Id of the node",
                        "id": "/properties/nodes/items/properties/id",
                        "title": "The id schema",
                        "type": "string"
                    },
                    "metadata": {
                        "id": "/properties/nodes/items/properties/metadata",
                        "properties": {
                            "description": "This accepts anything, as long as it's valid JSON.",
                            "title": "Empty Object"
                        },
                        "type": "object"
                    },
                    "sources": {
                        "id": "/properties/nodes/items/properties/sources",
                        "items": {
                            "description": "This accepts anything, as long as it's valid JSON.",
                            "title": "Empty Object"
                        },
                        "type": "array"
                    },
                    "text": {
                        "default": "The 'Hang Back' campaign video should not have been published, and should be withdrawn.",
                        "description": "The text in the node.",
                        "id": "/properties/nodes/items/properties/text",
                        "title": "The text schema",
                        "type": "string"
                    },
                    "type": {
                        "default": "atom",
                        "description": "The Type of the node. Either an atom or a scheme.",
                        "id": "/properties/nodes/items/properties/type",
                        "pattern": "\\b(atom|scheme)\\b",
                        "title": "The type schema",
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
            "id": "/properties/resources",
            "items": {
                "description": "This accepts anything, as long as it's valid JSON.",
                "title": "Empty Object"
            },
            "type": "array"
        }
    },
    "required": [
        "metadata",
        "resources",
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
app.config['SECRET_KEY'] = '1234'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        users = mongo.db.users
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            token_data = jwt.decode(token, app.config['SECRET_KEY'])
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


@app.route('/api/upload', methods=['GET', 'POST'])
@token_required
def upload_file(current_user):
    if not current_user.get('admin'):
        return jsonify({'message': 'Cannot perform that function!'})
    argument = mongo.db.argument
    # schema = open("uploads/schema.json").read()
    # data = open("uploads/correct_format.json").read()
    # Header Data for debugging
    req_headers = request.headers
    if request.method == 'POST':
        # check if the post request has the file part
        if request.files['file'].filename == '':
            err = "Please select a File."
            return jsonify({'message': err},
                           {'schema': argument_schema})
        else:
            file = request.files['file']
            filename = secure_filename(file.filename)

            if filename and allowed_file(file.filename):
                parsed_to_string = file.read().decode("utf-8")
                # To Dict
                parsed_to_json = json.loads(parsed_to_string)
                # parsed_to_json = request.get_json()
                # TODO: the validator checks against the schema and inserts the provided json only if it contains the
                # TODO: required fields and it will upload it to the
                v = Draft4Validator(argument_schema)

                # if Draft3Validator(schema).is_valid([2, 3, 4]):
                # if v.is_valid(parsed_to_json):

                valid = v.is_valid(parsed_to_json)
                parsed_to_json_type = type(parsed_to_json)
                if valid:
                    # search_result = argument.find(
                    #     {"nodes.text": {'$regex': ".*" + argString + ".*", "$options": "i"}})
                    # TODO: make if statement that checks if there is a doc that exists with that id and if so dont upload the doc
                    check_if_exists = argument.find({"sadface.id": parsed_to_json.get("sadface", {}).get('id')},
                                                    {"id": 1}).limit(1)
                    # check_if_exists = dumps(argument.find({"id": parsed_to_json.get("id")}, {"id": 1}).limit(1))

                    check_if_exists_dumps = dumps(check_if_exists)
                    check_if_exists_count = check_if_exists.count()
                    if check_if_exists_count > 0:
                        outcome = "The Document already Exists"
                        # return render_te mplate('homepage.html', doomed=parsed_to_json_type)
                        return json.dumps({'A document with this ID already exists': ({
                            # "Analyst Email": parsed_to_json.get("analyst_email"),
                            # "Analyst Name": parsed_to_json.get("analyst_name"),
                            # "Created": parsed_to_json.get("created"),
                            # "Edges": parsed_to_json.get("edges"),
                            # "Edited": parsed_to_json.get("edited"),
                            "id": parsed_to_json.get("sadface", {}).get('id'),
                            # "id": parsed_to_json.get("id"),
                            # "Metadata": parsed_to_json.get("metadata"),
                            # "Nodes": parsed_to_json.get("nodes"),
                            # "Resources": parsed_to_json.get("resources"),
                            # "found": check_if_exists_dumps

                        })}, sort_keys=False, indent=2), 200, {
                                   'Content-Type': 'application/json'}
                        # return outcome
                    else:
                        outcome = "Successful Upload"
                        sadface.sd = parsed_to_json['sadface']
                        dot_string = sadface.export_dot()
                        graph = graphviz.Source(dot_string, format='svg')
                        # graph = pgv.AGraph(dot_string)
                        # graph.layout(prog='dot')
                        # graph.draw(parsed_to_json['sadface']['id'] + '.png')
                        # sadface.save(parsed_to_json['sadface']['id'], "dot")
                        parsed_to_json['uploader'] = current_user.get('public_id')
                        parsed_to_json['time_of_upload'] = datetime.datetime.now()
                        post_id = argument.insert_one(parsed_to_json).inserted_id
                        return jsonify({'message': outcome})
                else:
                    errors_list = []
                    # asd = 123
                    errors = sorted(v.iter_errors(parsed_to_json), key=lambda e: e.path)
                    # errors = sorted(v.iter_errors(parsed_to_json), key=str)

                    for error in errors:
                        error_dict = {'key': list(error.path), 'error': error.message}
                        errors_list.append(error_dict)

                    # for error in errors:
                    #     errors_list.append(error.message)
                    # for error in errors:
                    #     for suberror in sorted(error.context, key=lambda e: e.schema_path):
                    #         errors_list.append(list(suberror.schema_path) + suberror.message)
                    outcome = "Unsuccessful Upload, invalid Json"

                    # if validate(parsed_to_json, schema):
                    #     post_id = argument.insert_one(parsed_to_json).inserted_id
                    # parsed_to_json_type = json.dumps(parsed_to_json)

                    return json.dumps({'Errors': errors_list}, sort_keys=False, indent=2), 200, {
                        'Content-Type': 'application/json'}
                    # return render_template('upload_results.html',
                    #                      outcome=errors_list)  # 201 to show that the upload was successful
                    # return render_template('upload_results.html', json_parsed=asd, outcome=outcome,
                    #                      validator=v,
                    #                     req_headers=req_headers,
                    #                    string_parsed=parsed_to_string,
                    #                   type=valid)  # 201 to show that the upload was successful
            else:
                err = "Wrong file extension. Please upload a JSON document."
                return err
                # return render_template('upload.html', err=err, argument_schema=argument_schema)

    return jsonify({'message': 'Please POST a JSON document in the following structure!'},
                   {'schema': argument_schema})
    # return render_template('upload.html', argument_schema=argument_schema)


@app.route('/api/edit', methods=['GET', 'POST'])
@token_required
def edit_document(current_user):
    if not current_user.get('admin'):
        return jsonify({'message': 'Cannot perform that function!'})
    argument = mongo.db.argument
    # schema = open("uploads/schema.json").read()
    # data = open("uploads/correct_format.json").read()
    # Header Data for debugging
    req_headers = request.headers
    if request.method == 'POST':
        # check if the post request has the file part
        if request.files['file'].filename == '':
            err = "Please select a File."
            return jsonify({'message': err},
                           {'schema': argument_schema})
        else:
            file = request.files['file']
            filename = secure_filename(file.filename)

            if filename and allowed_file(file.filename):
                parsed_to_string = file.read().decode("utf-8")
                # To Dict
                parsed_to_json = json.loads(parsed_to_string)

                # TODO: the validator checks against the schema and inserts the provided json only if it contains the
                # TODO: required fields and it will upload it to the
                v = Draft4Validator(argument_schema)

                valid = v.is_valid(parsed_to_json)
                parsed_to_json_type = type(parsed_to_json)
                if valid:
                    # TODO: make if statement that checks if there is a doc that exists with that id and if so dont upload the doc
                    check_if_exists = argument.find({"sadface.id": parsed_to_json.get("sadface", {}).get('id')},
                                                    {"id": 1}).limit(1)
                    check_if_exists_uploader = argument.find_one(
                        {'sadface.id': parsed_to_json.get("sadface", {}).get('id')})
                    uploader = check_if_exists_uploader['uploader']
                    check_if_exists_dumps = dumps(check_if_exists)
                    check_if_exists_count = check_if_exists.count()
                    if check_if_exists_count > 0 and current_user.get('public_id') == uploader:
                        # TODO:FIND AND UPDATE THE DOCUMENT

                        outcome = "The following document has been replaced"
                        parsed_to_json['uploader'] = current_user.get('public_id')
                        parsed_to_json['time_of_edit_upload'] = datetime.datetime.now()
                        replaced_doc = argument.replace_one({"sadface.id": parsed_to_json.get("sadface", {}).get('id')},
                                                            parsed_to_json)

                        return json.dumps(
                            {outcome: ({"id": parsed_to_json.get("sadface", {}).get('id'), "uploader": uploader
                                        })}, sort_keys=False, indent=2), 200, {
                                   'Content-Type': 'application/json'}

                    else:
                        outcome = "A document with that ID does not exist or you don't" \
                                  " have permissions to edit this document"

                        return jsonify({'Documents found': check_if_exists_count}, {'message': outcome},
                                       {'id': parsed_to_json.get("sadface", {}).get('id')})
                else:
                    errors_list = []

                    errors = sorted(v.iter_errors(parsed_to_json), key=lambda e: e.path)

                    for error in errors:
                        error_dict = {'key': list(error.path), 'error': error.message}
                        errors_list.append(error_dict)

                    outcome = "Unsuccessful Upload, invalid Json"

                    return json.dumps({'Errors': errors_list}, sort_keys=False, indent=2), 200, {
                        'Content-Type': 'application/json'}

            else:
                err = "Wrong file extension. Please upload a JSON document."
                jsonify({'message': err})

    return jsonify({
        'message': 'In order to edit a document please POST a JSON document in the following structure!'
                   ' With all keys including the ones you wish to override'},
        {'schema': argument_schema})


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

            return redirect(url_for('get_arguments_with_txt', argString=argumentString))

    return render_template('homepage.html', err=err)


#
# @app.route('/argument', methods=['GET'])
# def get_all_arguments():
#     argument = mongo.db.argument
#
#     output = []
#
#     for q in argument.find():
#         output.append({"name": q["name"], "contents": q["contents"]})
#
#     # output = []
#     # for q in argument.find():
#     #     output.append({
#     #         # "MongoDB ID": q["_id"],
#     #         "Analyst Email": q["analyst_email"],
#     #         "Analyst Name": q["analyst_name"],
#     #         "Created": q["created"],
#     #         "Edges": q["edges"],
#     #         "Edited": q["edited"],
#     #         "id": q["id"],
#     #         "Metadata": q["metadata"],
#     #         "Nodes": q["nodes"],
#     #         "Resources": q["resources"],
#     #
#     #     })
#
#     output = json.dumps(output)
#     # jsont = ({'result': output})
#     # r = json.dumps(output)
#     # print(type(r))
#     # loaded_r = json.load(r)
#     return render_template('search_results.html', json=output)


@app.route('/api/argument/<argString>', methods=['GET'])
@token_required
def get_arguments_with_txt(current_user, argString):
    if not current_user.get('admin'):
        return jsonify({'message': 'Cannot perform that function!'})
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

    search_result = argument.find(
        {"nodes.text": {'$regex': ".*" + argString + ".*", "$options": "i"}})
    # with_regex_1 = argument.find(
    #     {"name": {'$regex': ".*" + argString + ".*", '$options': 'i'}})
    # TODO: counts how many results were found

    count_me = search_result.count()
    # q = list(argument.find({'$text:': {'$search': argString}}))

    # if q:
    #     output = {'name': q['name'], 'contents': q['contents']}
    # else:
    #     output = 'No results Found'

    results = []
    for q in search_result:
        results.append({
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

    return json.dumps({'argument': results}, sort_keys=False, indent=2), 200, {'Content-Type': 'application/json'}

    # output = json.dumps(output, sort_keys=True, indent=4, separators=(',', ': '))
    # with_regex = jsonify(with_regex)
    # typeOF = type(output)
    # return render_template('search_results.html', json=output, typeof=typeOF,
    #                        argString=argString,
    #                        with_regex=with_regex,
    #                        cursor=count_me)


@app.route('/api/argumentIDs/<argString>', methods=['GET'])
@token_required
def get_list_argument_id(current_user, argString):
    if not current_user.get('admin'):
        return jsonify({'message': 'Cannot perform that function!'})
    # TODO: returned ids should be categorized depending on which search phrase they contain?
    argument = mongo.db.argument
    argString = argString.replace(" ", "|")
    search_results = argument.find(
        {"sadface.nodes.text": {'$regex': ".*" + argString + ".*", "$options": "i"}})

    argument_ids_list = []
    for argument in search_results:
        argument_ids_list.append({
            "id": argument['sadface']["id"]
        })

    return json.dumps({'argument IDs': argument_ids_list}, sort_keys=False, indent=2), 200, {
        'Content-Type': 'application/json'}




@app.route('/api/argument/by/<ArgId>', methods=['GET'])
@token_required
def get_argument_by_id(current_user, ArgId):
    if not current_user.get('admin'):
        return jsonify({'message': 'Cannot perform that function!'})
    argument = mongo.db.argument
    # ArgId = ArgId.replace(" ", "|")
    search_results = argument.find_one({"sadface.id": {'$regex': ".*" + ArgId + ".*", "$options": "i"}})

    result = search_results.get("sadface", {})

    # return render_template('homepage.html', doomed=result)
    return json.dumps({'argument IDs': ({
        "Analyst Email": result.get("analyst_email"),
        "Analyst Name": result.get("analyst_name"),
        "Created": result.get("created"),
        "Edges": result.get("edges"),
        "Edited": result.get("edited"),
        "id": result.get("id"),
        "Metadata": result.get("metadata"),
        "Nodes": result.get("nodes"),
        "Resources": result.get("resources"),

    })}, sort_keys=False, indent=2), 200, {'Content-Type': 'application/json'}


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


@app.route('/login')
def login():
    authorization = request.authorization
    if not authorization or not authorization.username or not authorization.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    users = mongo.db.users
    user = users.find_one({'name': authorization.username})

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.get('password'), authorization.password):
        payload = {'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1),
                   'iat': datetime.datetime.utcnow(),
                   'public_id': user.get('public_id')}
        if user.get('token'):
            token = user.get('token')
        else:
            # Cretion of the Token
            token = jwt.encode(
                {'public_id': user.get('public_id'),
                 # 'exp': datetime.datetime.utcnow()},
                 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
                app.config['SECRET_KEY'])
        # token = jwt.encode(payload=payload, key=app.config.get('SECRET_KEY'), alg='HS256')
        return jsonify({'token': token.decode('UTF-8')})
        # return jsonify({'token': token})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if request.files['file'].filename == '':
            err = "Please select a File."
            return err
        else:
            file = request.files['file']
            filename = secure_filename(file.filename)

            if filename and allowed_file(file.filename):
                parsed_to_string = file.read().decode("utf-8")
                # To Dict

                parsed_to_json = json.loads(parsed_to_string)
                username = parsed_to_json.get('username')
                password = parsed_to_json.get('password')
                admin = parsed_to_json.get('admin')
                # return password
                if username is None or password is None:
                    abort(400)  # missing arguments
                # return password
                users = mongo.db.users
                existing_user = users.find_one({'name': username})
                # typeofuser = type(existing_user)
                # existing_user = users.find({'name': username}, {"id": 1}).limit(1)
                typeofuser = type(existing_user)

                if existing_user is None:
                    hased_pass = generate_password_hash(password, method='sha256')

                    # hashpass = bcrypt.hashpw(request.form['pass'].encode('utf-8'), bcrypt.gensalt())
                    users.insert(
                        {'public_id': uuid.uuid4().hex, 'name': username, 'password': hased_pass, 'admin': admin})
                    session['username'] = username
                    added_user = users.find_one({'name': username})

                    # return json.dumps({'username':added_user.get('name')})
                    return jsonify({'username': added_user.get('name'), 'admin': admin}), 201, {
                        'Location': url_for('get_user', user_id=added_user.get('public_id'), _external=True)}
                    # return (jsonify({'username': added_user.get('name')}), 201,
                    #         {'Location': 'home'})

                return "User already exists"
                # abort(400)

    return "OK"


@app.route('/api/users/<user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    if not current_user.get('admin'):
        return jsonify({'message': 'Cannot perform that function!'})

    users = mongo.db.users
    user = users.find_one({'public_id': user_id})
    # user = users.find_one({'public_id': uuid.UUID(user_id)}) #last one working
    # user = users.find_one({'_id': ObjectId(user_id)})
    # user = users.find({'_id': user_id}, {"id": 1}).limit(1)
    if not user:
        abort(400)
    return jsonify({'username': user.get('name'), 'admin': user.get('admin'),
                    'public_id': user.get('public_id')})


@app.route('/account')
def index():
    if 'username' in session:
        return 'You are logged in as ' + session['username']

    return render_template('account.html')


if __name__ == '__main__':
    app.secret_key = '1234'
    app.run(debug=True)
