"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret"

jwt = JWTManager(app)

api = Blueprint('api', __name__)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():
    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }
    return jsonify(response_body), 200

@api.route('/login', methods=['POST'])
def login():
     username = request.json.get("username", None)
     password = request.json.get("password", None)
     print(username, password)
     secret_key = "OU812"
     #access_token = create_access_token(identity=username)
     return jsonify(access_token=secret_key)

@api.route('/private', methods=['POST'])
def getprivate():
    secret_key = "OU812"
    Authorization = request.headers.get("Authorization")
    if Authorization == "":
        return jsonify("you are not logged in")
    elif Authorization == secret_key:
        return jsonify("you are logged in")  
