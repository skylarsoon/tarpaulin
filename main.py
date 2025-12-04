from flask import Flask, request, jsonify
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

BUSINESSES = 'businesses'

# Update the values of the following 3 variables
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DOMAIN = os.getenv("DOMAIN")

ATTRIBUTE_MISSING = { "Error" : "The request body is missing at least one of the required attributes"}
ERROR_NOT_FOUND = { "Error" : "No business with this business_id exists"}
JWT_INVALID = {"Error" : "Unauthorized user."}
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
    

def verify_jwt_usable(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return None
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return None
    if unverified_header["alg"] == "HS256":
        return None
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTClaimsError:
            return None
        except Exception:
            return None

        return payload
    else:
        return None


@app.route('/')
def index():
    return "Please navigate to /businesses to use this API"\
    
    # Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if "username" not in content or "password" not in content:
        return {'Error' : 'Body is missing a required attribute.'}
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers).json()

    if "id_token" not in r:
        return {"Error" : "Invalid credentials."}, 401

    return {'token': r["id_token"]}, 200

def validate_permissions(roles, sub):
    # gets user 
    query = client.query(kind="users")
    query.add_filter('sub', '=', sub)
    user = list(query.fetch())[0]

    # checks if right role
    if user["role"] not in roles:
        return False
    else:
        return True

@app.route('/users', methods=['GET'])
def get_users():
    payload = verify_jwt(request)

    if not payload:
        return JWT_INVALID, 401
    
    # check permissions
    if validate_permissions(["admin"], payload["sub"]) == False:
        return {"Error" : "The JWT is valid but doesn't belong to an admin."}, 403
    
    # now role is validated, so we can get all users.

    query = client.query(kind="users")
    users = list(query.fetch())
    for u in users:
        u['id'] = u.key.id
    
    return users

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    payload = verify_jwt(request)

    if not payload:
        return ERROR_401, 401
    
    query = client.query(kind="users")
    query.add_filter('sub', '=', payload["sub"])
    requestor = list(query.fetch())

    # check permissions
    if validate_permissions(["admin"], payload["sub"]) == False and user_id != requestor.key.id:
        return ERROR_403, 403
    
    key = client.key('users', user_id)
    # query = client.query(kind="users")
    # query.add_filter('key', '=', user_id)
    user = client.get(key)

    if not user:
        return ERROR_403, 403
    
    return user


    

    


    
# #  Create a business
# @app.route('/' + BUSINESSES, methods=['POST'])
# def add_business():
#     if request.method == 'POST':
#         content = request.get_json()
#         new_key = client.key(BUSINESSES)

#         if 'inspection_score' not in content or 'name' not in content or 'street_address' not in content or 'city' not in content or 'state' not in content or 'zip_code' not in content:
#             return ATTRIBUTE_MISSING , 400
        
#         payload = verify_jwt(request)

#         new_business = datastore.Entity(key=new_key)
#         new_business.update({
#             'name': content['name'],
#             'owner_id': payload['sub'],
#             'street_address': content['street_address'],
#             'city': content['city'],
#             'state': content['state'],
#             'zip_code': content['zip_code'],
#             'inspection_score': content['inspection_score']
#         })

#         client.put(new_business)
#         new_business['id'] = new_business.key.id
#         new_business['self'] = 'https://' + request.host + '/' + BUSINESSES + '/' + str(new_business.key.id)
#         return (new_business, 201)
#     else:
#         return jsonify(error='Method not recogonized')
    
# # Get a business
# @app.route('/' + BUSINESSES + '/<int:id>', methods=['GET'])
# def get_business(id):
#     business_key = client.key(BUSINESSES, id)
#     business = client.get(key=business_key)

#     payload = verify_jwt(request)

#     if business is None:
#         return ERROR_NOT_FOUND , 404
#     else:
#         if payload['sub'] != business['owner_id']:
#             return JWT_INVALID, 401
#         business['id'] = business.key.id
#         business['self'] = 'https://' + request.host + '/' + BUSINESSES + '/' + str(business.key.id)
#         return business


# # List all business
# @app.route('/' + BUSINESSES, methods=['GET'])
# def get_businesses():
#     payload = verify_jwt_usable(request)

#     if not payload:
#         query = client.query(kind=BUSINESSES)
#         results = list(query.fetch())
#         for r in results:
#             r['id'] = r.key.id
#             r['self'] = 'https://' + request.host + '/' + BUSINESSES + '/' + str(r.key.id)
#             del r['inspection_score']
#     else:
#         query = client.query(kind=BUSINESSES)
#         owner_id = payload['sub']
#         query.add_filter('owner_id', '=', owner_id)
#         results = list(query.fetch())
#         for r in results:
#             r['self'] = 'https://' + request.host + '/' + BUSINESSES + '/' + str(r.key.id)
#             r['id'] = r.key.id

#     return results

# # Delete a business
# @app.route('/' + BUSINESSES + '/<int:id>', methods=['DELETE'])
# def delete_business(id):
#     payload = verify_jwt(request)

#     # if not payload:
#     #     return JWT_INVALID, 401

#     business_key = client.key(BUSINESSES, id)

#     business = client.get(business_key)

#     if business is None:
#         return ERROR_NOT_FOUND , 403
#     else:
#         if business['owner_id'] == payload['sub']:
#             client.delete(business_key)
#             return ('', 204)
#         else:
#             return (ERROR_NOT_FOUND, 403)


# # Decode the JWT supplied in the Authorization header
# @app.route('/decode', methods=['GET'])
# def decode_jwt():

#     payload = verify_jwt(request)
#     return payload          
        

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

