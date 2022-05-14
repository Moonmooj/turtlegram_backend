import json
import hashlib
from pymongo import MongoClient
from flask import Flask, jsonify, request
from flask_cors import CORS

client = MongoClient(
    'mongodb+srv://test:sparta@cluster0.sca5z.mongodb.net/Cluster0?retryWrites=true&w=majority')
db = client.Turtle

app = Flask(__name__)
cors = CORS(app, resources={r"*": {'origins': '*'}})


@app.route('/')
def hello_world():
    return jsonify({'message': 'success'})


@app.route('/signup', methods=['POST'])
def sign_up():
    data = json.loads(request.data)
    email = data.get('email')
    password = data.get('password')
    pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    doc = {
        'email': email,
        'password': pw_hash
    }
    db.users.insert_one(doc)
    return jsonify({'message': 'success'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
