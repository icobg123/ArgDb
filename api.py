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
from bson import json_util
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

schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "id": "http://example.com/example.json",
    "properties": {
        "name": {
            "id": "/properties/name",
            "type": "string"
        },
        "contents": {
            "id": "/properties/price",
            "type": "number"
        }

    },
    "required": [
        "name",
        "contents"
    ],
    "additionalProperties": False,
    "type": "object"
}

argument_schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "definitions": {},
    "id": "http://example.com/example.json",
    "properties": {
        "analyst_email": {
            "id": "/properties/analyst_email",
            "type": "string",
            "format": "email",
            "pattern": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        },
        "analyst_name": {
            "id": "/properties/analyst_name",
            "type": "string"
        },
        "created": {
            "id": "/properties/created",
            "type": "string"
        },
        "edges": {
            "id": "/properties/edges",
            "items": {
                "id": "/properties/edges/items",
                "properties": {
                    "id": {
                        "id": "/properties/edges/items/properties/id",
                        "type": "string"
                    },
                    "source": {
                        "id": "/properties/edges/items/properties/source",
                        "type": "string"
                    },
                    "target": {
                        "id": "/properties/edges/items/properties/target",
                        "type": "string"
                    }
                },
                "required": [
                    "source",
                    "id",
                    "target"
                ],
                "type": "object"
            },
            "type": "array"
        },
        "edited": {
            "id": "/properties/edited",
            "type": "string"
        },
        "id": {
            "id": "/properties/id",
            "type": "string"
        },
        "metadata": {
            "id": "/properties/metadata",
            "properties": {
                "hello": {
                    "id": "/properties/metadata/properties/hello",
                    "type": "string"
                },
                "some": {
                    "id": "/properties/metadata/properties/some",
                    "type": "string"
                }
            },
            "required": [
                "some",
                "hello"
            ],
            "type": "object"
        },
        "nodes": {
            "id": "/properties/nodes",
            "items": {
                "id": "/properties/nodes/items",
                "properties": {
                    "canonical_text": {
                        "id": "/properties/nodes/items/properties/canonical_text",
                        "type": "string"
                    },
                    "id": {
                        "id": "/properties/nodes/items/properties/id",
                        "type": "string"
                    },
                    "metadata": {
                        "id": "/properties/nodes/items/properties/metadata",
                        "properties": {},
                        "type": "object"
                    },
                    "sources": {
                        "id": "/properties/nodes/items/properties/sources",
                        "items": {
                            "id": "/properties/nodes/items/properties/sources/items",
                            "properties": {
                                "length": {
                                    "id": "/properties/nodes/items/properties/sources/items/properties/length",
                                    "type": "integer"
                                },
                                "offset": {
                                    "id": "/properties/nodes/items/properties/sources/items/properties/offset",
                                    "type": "integer"
                                },
                                "resource_id": {
                                    "id": "/properties/nodes/items/properties/sources/items/properties/resource_id",
                                    "type": "string"
                                },
                                "text": {
                                    "id": "/properties/nodes/items/properties/sources/items/properties/text",
                                    "type": "string"
                                }
                            },
                            "required": [
                                "text",
                                "length",
                                "resource_id",
                                "offset"
                            ],
                            "type": "object"
                        },
                        "type": "array"
                    },
                    "type": {
                        "id": "/properties/nodes/items/properties/type",
                        "type": "string"
                    }
                },
                "required": [
                    "sources",
                    "type",
                    "id",
                    "canonical_text"
                ],
                "type": "object"
            },
            "type": "array"
        },
        "resources": {
            "id": "/properties/resources",
            "items": {
                "id": "/properties/resources/items",
                "properties": {
                    "content": {
                        "id": "/properties/resources/items/properties/content",
                        "type": "string"
                    },
                    "id": {
                        "id": "/properties/resources/items/properties/id",
                        "type": "string"
                    },
                    "metadata": {
                        "id": "/properties/resources/items/properties/metadata",
                        "properties": {},
                        "type": "object"
                    },
                    "type": {
                        "id": "/properties/resources/items/properties/type",
                        "type": "string"
                    }
                },
                "required": [
                    "content",
                    "type",
                    "id"
                ],
                "type": "object"
            },
            "type": "array"
        }
    },
    "required": [
        "edited",
        "analyst_name",
        "analyst_email",
        "created",
        "edges",
        "nodes",
        "id",
        "resources"
    ],
    "type": "object"
}

#
# argument_schema = {
#     "$schema": "http://json-schema.org/draft-04/schema#",
#     "definitions": {},
#     "id": "http://example.com/example.json",
#     "properties": {
#         "analyst_email": {
#             "id": "/properties/analyst_email",
#             "type": "string",
#             "format": "email",
#             "pattern": "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
#         },
#         "analyst_name": {
#             "id": "/properties/analyst_name",
#             "type": "string"
#         },
#         "created": {
#             "id": "/properties/created",
#             "type": "string"
#         },
#         "edges": {
#             "id": "/properties/edges",
#             "items": {
#                 "id": "/properties/edges/items",
#                 "properties": {
#                     "id": {
#                         "id": "/properties/edges/items/properties/id",
#                         "type": "string"
#                     },
#                     "source_id": {
#                         "id": "/properties/edges/items/properties/source_id",
#                         "type": "string"
#                     },
#                     "target_id": {
#                         "id": "/properties/edges/items/properties/target_id",
#                         "type": "string"
#                     }
#                 },
#                 "type": "object"
#             },
#             "type": "array"
#         },
#         "edited": {
#             "id": "/properties/edited",
#             "type": "string"
#         },
#         "id": {
#             "id": "/properties/id",
#             "type": "string"
#         },
#         "metadata": {
#             "id": "/properties/metadata",
#             "properties": {},
#             "type": "object"
#         },
#         "nodes": {
#             "id": "/properties/nodes",
#             "items": {
#                 "id": "/properties/nodes/items",
#                 "properties": {
#                     "id": {
#                         "id": "/properties/nodes/items/properties/id",
#                         "type": "string"
#                     },
#                     "metadata": {
#                         "id": "/properties/nodes/items/properties/metadata",
#                         "properties": {},
#                         "type": "object"
#                     },
#                     "sources": {
#                         "id": "/properties/nodes/items/properties/sources",
#                         "items": {},
#                         "type": "array"
#                     },
#                     "text": {
#                         "id": "/properties/nodes/items/properties/text",
#                         "type": "string"
#                     },
#                     "type": {
#                         "id": "/properties/nodes/items/properties/type",
#                         "type": "string"
#                     }
#                 },
#                 "type": "object"
#             },
#             "type": "array"
#         },
#         "resources": {
#             "id": "/properties/resources",
#             "items": {},
#             "type": "array"
#         }
#     },
#     "type": "object"
# }
int2 = {
    "edited": "officia tempor",
    "analyst_name": "amet adipisicing esse eiusmod elit",
    "analyst_email": "ut velit",
    "created": "non",
    "edges": [
        {
            "source": "id ",
            "id": "dolor ullamco deserunt esse",
            "target": "in dolore"
        },
        {
            "source": "adip",
            "id": "ullamco ipsum fugiat consequat ad",
            "target": "enim occaecat in"
        },
        {
            "source": "enim",
            "id": "in eiusmod anim tempor dolore",
            "target": "labore"
        },
        {
            "source": "eiusmod",
            "id": "magna pariatur Excepteur dolore",
            "target": "deserunt"
        },
        {
            "source": "nisi anim aliqua elit",
            "id": "irure non labore do nostrud",
            "target": "do Ut laboris laborum"
        }
    ],
    "nodes": [
        {
            "sources": [
                {
                    "text": "veniam",
                    "length": -11186411,
                    "resource_id": "veniam adipisicing",
                    "offset": -16971626
                },
                {
                    "text": "ad elit non nisi est",
                    "length": 90469907,
                    "resource_id": "Duis",
                    "offset": 44587942
                }
            ],
            "type": "laboris sed magna ut",
            "id": "cupidatat aliquip ullamco nostrud et",
            "canonical_text": "anim"
        },
        {
            "sources": [
                {
                    "text": "proident in adi",
                    "length": 41176633,
                    "resource_id": "labore in id laboris quis",
                    "offset": 1844798
                },
                {
                    "text": "Ut consequat in qui",
                    "length": -55595821,
                    "resource_id": "quis sunt veniam consequat exercitation",
                    "offset": -89907679
                },
                {
                    "text": "velit proident dolore officia voluptate",
                    "length": -84120181,
                    "resource_id": "aute Duis Lorem ut te",
                    "offset": -8923056
                },
                {
                    "text": "reprehenderit fugiat ad officia",
                    "length": -99402801,
                    "resource_id": "Duis",
                    "offset": -25331611
                },
                {
                    "text": "id",
                    "length": -5747616,
                    "resource_id": "laborum elit eu dolore ut",
                    "offset": -48696902
                }
            ],
            "type": "consectetur",
            "id": "ea in",
            "canonical_text": "adipisicing irure id laborum nostrud"
        },
        {
            "sources": [
                {
                    "text": "Ut ullamco",
                    "length": -17848891,
                    "resource_id": "esse sunt officia",
                    "offset": 87998584
                },
                {
                    "text": "laboris fugiat reprehenderit aliquip cupidatat",
                    "length": 69018308,
                    "resource_id": "commodo ad",
                    "offset": 36963153
                }
            ],
            "type": "sit sint in veniam ut",
            "id": "tempor ipsum",
            "canonical_text": "dolor esse enim"
        },
        {
            "sources": [
                {
                    "text": "dolor amet et deserunt",
                    "length": -20113476,
                    "resource_id": "anim exercitation magna ",
                    "offset": 95817057
                },
                {
                    "text": "sit ex Duis",
                    "length": 63381715,
                    "resource_id": "reprehenderit",
                    "offset": -60151700
                },
                {
                    "text": "ex con",
                    "length": -6207930,
                    "resource_id": "sint reprehenderit consectet",
                    "offset": 12660727
                },
                {
                    "text": "dolor",
                    "length": 30025073,
                    "resource_id": "aute incididunt aliq",
                    "offset": 27053591
                }
            ],
            "type": "incididu",
            "id": "laborum ad exercitation",
            "canonical_text": "aliquip"
        }
    ],
    "id": "officia",
    "resources": [
        {
            "content": "elit nulla dolor",
            "type": "ipsum mollit veniam labore in",
            "id": "dolore nostrud"
        },
        {
            "content": "sunt",
            "type": "in cillum Excepteur aliqua",
            "id": "sunt"
        },
        {
            "content": "in",
            "type": "qui ",
            "id": "consequat cillum in"
        },
        {
            "content": "ut Duis nulla do",
            "type": "cillum",
            "id": "laborum laboris"
        }
    ],
    "metadata": {
        "some": "veniam aliqua laborum ea do",
        "hello": "quis eiusmod tempor minim do"
    }
}

# schema = {
#     "type": "object",
#     "properties": {
#         "price": {"type": "number"},
#         "name": {"type": "string"},
#     },
# }


# schema = {
#     "type": "object",
#     "properties": {
#         "price": {"type": "number"},
#         "name": {"type": "string"},
#     },
# }
app.config['ALLOWED_EXTENSIONS'] = set(['json'])


# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    argument = mongo.db.argument
    # schema = open("uploads/schema.json").read()
    # data = open("uploads/data.json").read()
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
                if v.is_valid(parsed_to_json):
                    post_id = argument.insert_one(parsed_to_json).inserted_id
                valid = v.is_valid(parsed_to_json)
                parsed_to_json_type = type(parsed_to_json)
                if valid:
                    outcome = "Successful Upload"
                    # return render_template('homepage.html', doomed=parsed_to_json_type)
                    return json.dumps({'argument IDs': ({
                        "Analyst Email": parsed_to_json.get("analyst_email"),
                        "Analyst Name": parsed_to_json.get("analyst_name"),
                        "Created": parsed_to_json.get("created"),
                        "Edges": parsed_to_json.get("edges"),
                        "Edited": parsed_to_json.get("edited"),
                        "id": parsed_to_json.get("id"),
                        "Metadata": parsed_to_json.get("metadata"),
                        "Nodes": parsed_to_json.get("nodes"),
                        "Resources": parsed_to_json.get("resources"),

                    })}, sort_keys=False, indent=2), 200, {
                               'Content-Type': 'application/json'}
                else:
                    errors = []
                    for error in sorted(v.iter_errors(parsed_to_json), key=str):
                        errors.append(error.message)
                    outcome = "Unsuccessful Upload, invalid Json"

                    # if validate(parsed_to_json, schema):
                    #     post_id = argument.insert_one(parsed_to_json).inserted_id
                    # parsed_to_json_type = json.dumps(parsed_to_json)
                    return render_template('upload_results.html', json_parsed=errors, outcome=outcome,
                                           validator=v,
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

            return redirect(url_for('get_arguments_with_txt', argString=argumentString))

    return render_template('homepage.html', err=err)


@app.route('/argument', methods=['GET'])
def get_all_arguments():
    argument = mongo.db.argument

    output = []

    for q in argument.find():
        output.append({"name": q["name"], "contents": q["contents"]})

    # output = []
    # for q in argument.find():
    #     output.append({
    #         # "MongoDB ID": q["_id"],
    #         "Analyst Email": q["analyst_email"],
    #         "Analyst Name": q["analyst_name"],
    #         "Created": q["created"],
    #         "Edges": q["edges"],
    #         "Edited": q["edited"],
    #         "id": q["id"],
    #         "Metadata": q["metadata"],
    #         "Nodes": q["nodes"],
    #         "Resources": q["resources"],
    #
    #     })

    output = json.dumps(output)
    # jsont = ({'result': output})
    # r = json.dumps(output)
    # print(type(r))
    # loaded_r = json.load(r)
    return render_template('search_results.html', json=output)


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

    return json.dumps({'argument': results}), 200, {'Content-Type': 'application/json'}

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
