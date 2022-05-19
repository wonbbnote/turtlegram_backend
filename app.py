from functools import wraps
from os import abort
from bson import ObjectId
from pymongo import MongoClient
import hashlib
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt

SECRET_KEY = 'turtle'

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})

client = MongoClient('localhost', 27017)
db = client.dbturtle


# 4강 데코레이트 함수
def authorize(f):  # 함수인자로 받기
    @wraps(f)  # 한가지 함수를 여러가지 함수에 적용시키면 발생하는 에러 해결
    def decorated_function():  # 데코레이트 함수 정의
        if not 'Authorization' in request.headers:
            abort(401)
            # 헤더에 authorization이 있는지 확인하고 토큰이 없다면 401로 에러
            # import하기
        token = request.headers['Authorization']
        try:
            user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            # 토큰 decode
        except:
            abort(401)
            # decode안되면 에러
        return f(user)  # 얻어진 user값 함수안에 넣어 돌리기
    return decorated_function  # 데코레이트 함수 리턴


@app.route("/")
@authorize  # 데코레이트 함수 넣고
def hello_world(user):  # 인자값 user넣기
    print(user)  # payload 출력
    return jsonify({'message': 'success'})
# 포스트맨으로 확인해보기 -> authorization에 값넣고 돌려봐!


@app.route("/signup", methods=["POST"])
def sign_up():
    print(request)
    print(request.form)
    print(request.data)
    data = json.loads(request.data)
    print(data)

    password = data['password']  # password = data.get('password', None)
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    exists = bool(db.user.find_one({"email": data['email']}))
    if not exists:
        doc = {
            'email': data['email'],  # data.get('email')
            'password': password_hash
        }
        db.user.insert_one(doc)
        return jsonify({'message': 'success'})
    else:
        print("중복되었습니다.")
        return jsonify({'message': 'fail'})


@app.route("/login", methods=["POST"])
def sign_in():
    print(request)
    data = json.loads(request.data)
    print(data)

    email = data.get("email")
    password = data.get("password")
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(hashed_pw)

    result = db.user.find_one({"email": email, "password": hashed_pw})
    print(result)

    if result is None:
        return jsonify({'message': '아이디나 비밀번호가 옳지 않습니다'}), 401

    payload = {
        "id": str(result["_id"]),
        "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')
    print(token)
    return jsonify({'message': 'login', 'token': token})


@app.route("/getuserinfo", methods=["GET"])
@authorize
def get_user_info(user):  # 데코레이트 함수 쓰면 user정의할 필요 없음
    # print("1.", request.headers) #header hidden
    # token = request.headers.get("Authorization")
    # print("2.", token)
    # user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    # print("3.", user)
    result = db.user.find_one({'_id': ObjectId(user["id"])})
    print("4.", result)
    return jsonify({"message": "success", "email": result['email']})


# 게시글 작성 api
@app.route("/article", methods=["POST"])
@authorize
def post_article(user):
    data = json.loads(request.data)
    print(data)
    db_user = db.user.find_one({'_id': ObjectId(user.get("id"))})
    now = datetime.now().strftime("%H:%M:%S")
    doc = {
        "title": data.get("title", None),
        "content": data.get("content", None),
        "user": user['id'],
        "user_email": db_user['email'],
        "time": now
    }
    print(doc)
    db.article.insert_one(doc)
    return jsonify({"message": "success"})


# 게시물 불러오는 API
@app.route("/article", methods=['GET'])
def get_article():
    articles = list(db.article.find())
    print(articles)
    for article in articles:  # article을 돌리면서
        print(article.get('title'))
        article['_id'] = str(article["_id"])  # objectId string으로

    return jsonify({"message": "success", "articles": articles})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
