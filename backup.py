import os

import jsonschema
from bson import regex
from flask import Flask, jsonify, request, render_template, redirect, url_for, \
    send_from_directory
from flask.ext.pymongo import PyMongo
from flask.helpers import flash
from jsonschema import validate
from jsonschema import Draft3Validator
from bson import json_util
import json

from werkzeug.utils import secure_filename
from werkzeug.wsgi import SharedDataMiddleware

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['json'])
app.config['MONGO_DBNAME'] = 'argdbconnect'
app.config[
    'MONGO_URI'] = 'mongodb://argdb:argdbnapier@ds137191.mlab.com:37191/argdbconnect'
mongo = PyMongo(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "price": {"type": "number"},
        "name": {"type": "string"}
    }
}


# schema = {
#     "type": "object",
#     "properties": {
#         "price": {"type": "number"},
#         "name": {"type": "string"},
#     },
# }


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    argument = mongo.db.argument
    # schema = open("uploads/schema.json").read()
    # data = open("uploads/correct_format.json").read()
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        parsed_to_string = file.read().decode("utf-8")
        parsed_to_json = json.loads(parsed_to_string)
        response = json.dumps(parsed_to_json, sort_keys=True, indent=4,
                              separators=(',', ': '))
        jsontype = type(parsed_to_json)
        
        # real_json = jsonify(json_parsed)
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # if Draft3Validator(schema).is_valid(parsed_to_json) is False:
            #     post_id = argument.insert_one(parsed_to_json).inserted_id
            # valid = Draft3Validator(schema).validate(parsed_to_json)
            if Draft3Validator(schema).is_valid(parsed_to_json):
                post_id = argument.insert_one(parsed_to_json).inserted_id
            valid = Draft3Validator(schema).is_valid(parsed_to_json)
            # if validate(parsed_to_json, schema):
            #     post_id = argument.insert_one(parsed_to_json).inserted_id
            return render_template('upload_results.html', json_parsed=parsed_to_json,
                                   type=valid)
            # return redirect(url_for('uploaded_file',filename=filename))

    return render_template('upload.html')


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
        if not request.form['arg_str']:
            err = 'Please provide your Arg '
        # elif not request.form['region']:
        #     err = 'Please set your region'
        else:
            arg_str = request.form['arg_str']

            return redirect(url_for('get_one_argument', arg_str=arg_str))

    return render_template('homepage.html', err=err)


@app.route('/argument', methods=['GET'])
def get_all_arguments():
    argument = mongo.db.argument

    output = []

    for q in argument.find():
        output.append({'name': q['name'], 'contents': q['contents']})

    # jsont = ({'result': output})
    # r = json.dumps(output)
    # print(type(r))
    # loaded_r = json.load(r)
    return render_template('search_results.html', json=output)


@app.route('/argument/text/<arg_str>', methods=['GET'])
def get_one_argument(arg_str):
    argument = mongo.db.argument
    arg_str = arg_str.replace(" ", "|")
    typeOF = type(arg_str)

    # search_wordss = []
    #
    # for search_words in arg_str:
    #     search_wordss.append('/' + search_words + '/')
    # q = argument.find_one({'name': name})

    # mongo.db.argument.ensure_index([('name': 'text')], 'name' = 'search_index')

    argument.create_index([('name', 'text')])
    # qs = argument.find({"name": {'$regex': arg_str, '$options': 'i'}})
    # qs = argument.find({"name": {'$in': arg_str}})

    qss = argument.find({"$text": {"$search": arg_str}}).count()

    with_regex = argument.find(
        {"name": {'$regex': ".*" + arg_str + ".*", '$options': 'i'}})
    # with_regex_1 = argument.find(
    #     {"name": {'$regex': ".*" + arg_str + ".*", '$options': 'i'}})
    count_me = with_regex.count()
    # q = list(argument.find({'$text:': {'$search': arg_str}}))

    # if q:
    #     output = {'name': q['name'], 'contents': q['contents']}
    # else:
    #     output = 'No results Found'

    output = []
    for q in with_regex:
        output.append({'name': q['name'], 'contents': q['contents']})

    return render_template('search_results.html', json=output, typeof=typeOF, arg_str=count_me,
                           cursor=qss)


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


if __name__ == '__main__':
    app.run(debug=True)
