import os

import jsonschema
from bson import regex
from flask import Flask, jsonify, request, render_template, redirect, url_for, \
    send_from_directory
from flask_pymongo import PyMongo
from flask.helpers import flash
from jsonschema import validate
from jsonschema import Draft3Validator
from jsonschema import Draft4Validator
from jsonschema import ErrorTree
from jsonschema.exceptions import best_match
from bson import json_util
from bson.json_util import dumps
import json

from werkzeug.utils import secure_filename
from werkzeug.wsgi import SharedDataMiddleware

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'

app.config['MONGO_DBNAME'] = 'argdbconnect'
app.config[
    'MONGO_URI'] = 'mongodb://argdb:argdbnapier@ds137191.mlab.com:37191/argdbconnect'
mongo = PyMongo(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# TODO: Regex for the JSON schema
# Regex for IDs - (((\d|[a-zA-Z]){4})\-){3}(\d|[a-zA-Z]){4}
# Regex for Email - (^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)
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
                    check_if_exists = argument.find({"id": parsed_to_json.get("id")}, {"id": 1}).limit(1)
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
                            "id": parsed_to_json.get("id"),
                            # "Metadata": parsed_to_json.get("metadata"),
                            # "Nodes": parsed_to_json.get("nodes"),
                            # "Resources": parsed_to_json.get("resources"),
                            # "found": check_if_exists_dumps

                        })}, sort_keys=False, indent=2), 200, {
                                   'Content-Type': 'application/json'}
                        # return outcome
                    else:
                        outcome = "Successful Upload"
                        post_id = argument.insert_one(parsed_to_json).inserted_id
                        return outcome
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
def get_arguments_with_txt(argString):
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
def get_list_argument_id(argString):
    # TODO: returned ids should be categorized depending on which search phrase they contain?
    argument = mongo.db.argument
    argString = argString.replace(" ", "|")
    search_results = argument.find(
        {"nodes.text": {'$regex': ".*" + argString + ".*", "$options": "i"}})

    argument_ids_list = []
    for argument in search_results:
        argument_ids_list.append({
            "id": argument["id"]
        })

    return json.dumps({'argument IDs': argument_ids_list}, sort_keys=False, indent=2), 200, {
        'Content-Type': 'application/json'}


@app.route('/api/argument/by/<ArgId>', methods=['GET'])
def get_argument_by_id(ArgId):
    argument = mongo.db.argument
    # ArgId = ArgId.replace(" ", "|")
    search_results = argument.find_one({"id": {'$regex': ".*" + ArgId + ".*", "$options": "i"}})

    result = search_results.get('id')

    # return render_template('homepage.html', doomed=result)
    return json.dumps({'argument IDs': ({
        "Analyst Email": search_results.get("analyst_email"),
        "Analyst Name": search_results.get("analyst_name"),
        "Created": search_results.get("created"),
        "Edges": search_results.get("edges"),
        "Edited": search_results.get("edited"),
        "id": search_results.get("id"),
        "Metadata": search_results.get("metadata"),
        "Nodes": search_results.get("nodes"),
        "Resources": search_results.get("resources"),

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

if __name__ == '__main__':
    app.run(debug=True)
