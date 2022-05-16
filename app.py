from pymongo import MongoClient
import hashlib
import json
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})

client = MongoClient('localhost', 27017)
db = client.dbturtle


@app.route("/")
def hello_world():
    return jsonify({'message': 'success'})


@app.route("/signup", methods=["POST"])
def sign_up():
    print(request)
    print(request.form)
    print(request.data)
    data = json.loads(request.data)
    print(data)

    password = data['password']
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    doc = {
        'email': data['email'],
        'password': password_hash
    }
    db.user.insert_one(doc)
    return jsonify({'message': 'successdfd'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
