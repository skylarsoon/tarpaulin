from flask import Flask, request, jsonify, send_file
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
from google.cloud import storage
import io

load_dotenv()

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

COURSES = "courses"

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

AVATAR_BUCKET = "hw6-soonsk-avatars"

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
    requestor = list(query.fetch())[0]

    # check permissions
    if validate_permissions(["admin"], payload["sub"]) == False and user_id != requestor.key.id:
        return ERROR_403, 403
    
    # get user
    key = client.key('users', user_id)
    user = client.get(key)

    if not user:
        return ERROR_403, 403
    
    # get avatar
    file_name = str(user_id) + ".png"
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)

    #check if the file exists in GC storage
    file_exists = storage.Blob(bucket=bucket, name=file_name).exists(storage_client)

    if file_exists:
        user['avatar_url'] = 'https://' + request.host + '/' + 'users' + '/' + str(user_id) + '/' + 'avatar'

    return user


@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def update_avatar(user_id):
    #check for file in request
    if 'file' not in request.files:
        return ERROR_400, 400
    
    file_obj = request.files['file']
    
    payload = verify_jwt(request)
    if not payload:
        return ERROR_401, 401
    
    #get requestor
    query = client.query(kind="users")
    query.add_filter('sub', '=', payload["sub"])
    requestor = list(query.fetch())[0]

    # check if the valid user is making the request
    if user_id != requestor.key.id:
        return ERROR_403, 403
    
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)

    file_obj.filename = str(user_id) + ".png"
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)

    url = 'https://' + request.host + '/' + 'users' + '/' + str(user_id) + '/' + 'avatar'
    return {"avatar_url" : url}
    

    
@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    payload = verify_jwt(request)
    if not payload:
        return ERROR_401, 401
    
    #get requestor
    query = client.query(kind="users")
    query.add_filter('sub', '=', payload["sub"])
    requestor = list(query.fetch())[0]

    # check if the valid user is making the request
    if user_id != requestor.key.id:
        return ERROR_403, 403

    file_name = str(user_id) + ".png"
    
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)

    #check if the file exists in GC storage
    file_exists = storage.Blob(bucket=bucket, name=file_name).exists(storage_client)
    if not file_exists:
        return ERROR_404, 404
    # Create a blob with the given file name
    blob = bucket.blob(file_name)
    # Create a file object in memory using Python io package
    file_obj = io.BytesIO()
    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(file_obj)
    # Position the file_obj to its beginning
    file_obj.seek(0)


    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/x-png', download_name=file_name)

    
@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    payload = verify_jwt(request)
    if not payload:
        return ERROR_401, 401
    
    # get requestor
    query = client.query(kind="users")
    query.add_filter('sub', '=', payload["sub"])
    requestor = list(query.fetch())[0]

    # check if the valid user is making the request
    if user_id != requestor.key.id:
        return ERROR_403, 403
    file_name = str(user_id) + ".png"

    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)

    # check if file exists
    file_exists = storage.Blob(bucket=bucket, name=file_name).exists(storage_client)
    if not file_exists:
        return ERROR_404, 404
    
    blob = bucket.blob(file_name)
    # Delete the file from Cloud Storage
    blob.delete()
    return '',204

@app.route('/courses', methods=['POST'])
def add_course():
    payload = verify_jwt(request)
    if not payload:
        return ERROR_401, 401

    #if not an admin
    if validate_permissions(["admin"], payload["sub"]) == False:
        return ERROR_403, 403
    
    #if missing an attribute
    data = request.json
    if 'subject' not in data or 'number' not in data or 'title' not in data or 'term' not in data or 'instructor_id' not in data:
        return ERROR_400, 400
    
    # get user
    key = client.key('users', data['instructor_id'])
    user = client.get(key)

    if not user or user['role'] != "instructor":
        return ERROR_400, 400
    
    new_key = client.key(COURSES)
    
    new_course = datastore.Entity(key=new_key)
    new_course.update({
        'subject': data['subject'],
        'number': data['number'],
        'title': data['title'],
        'term': data['term'],
        'instructor_id': data['instructor_id']
    })

    client.put(new_course)
    new_course['id'] = new_course.key.id

    return new_course, 201

@app.route('/courses', methods=['GET'])
def get_all_courses():
    offset = request.args.get('offset', 0, type=int) # parameter name, default value
    limit = request.args.get('limit', 3, type=int) 

    query = client.query(kind=COURSES)
    query.order = ['subject']
    l_iterator = query.fetch(limit=limit, offset=offset)
    pages = l_iterator.pages
    results = list(next(pages))

    for r in results:
        r['id'] = r.key.id
        r['self'] = 'https://' + request.host + '/' + COURSES + '/' + str(r.key.id)


    return { "courses": results,  "next": 'https://' + request.host + '/' + COURSES + '?' + "offset=" + str(offset + limit) + "&limit=" + str(limit)}

    
@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    # get user
    key = client.key('courses', course_id)
    course = client.get(key)
    if not course:
        return ERROR_404, 404
    course['id'] = course_id
    course['self'] = 'https://' + request.host + '/' + COURSES + '/' + str(course_id)
    if 'enrollment' in course:
        del course['enrollment']
    return course

@app.route('/courses/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    payload = verify_jwt(request)
    if not payload:
        return ERROR_401, 401

    #if not an admin
    if validate_permissions(["admin"], payload["sub"]) == False:
        return ERROR_403, 403

    key = client.key('courses', course_id)
    course = client.get(key)

    # validate instructor_id
    if 'instructor_id' in request.json:
        instructor_key = client.key('users', request.json['instructor_id'])
        instructor = client.get(instructor_key)
        if not instructor:
            return ERROR_400, 400

    # make updates
    for mod in request.json:
        course[mod] = request.json[mod]
    
    client.put(course)
    course['id'] = course.key.id
    course['self'] = 'https://' + request.host + '/' + COURSES + '/' + str(course_id)
    if 'enrollment' in course:
        del course['enrollment']
    
    return course


@app.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    payload = verify_jwt(request)

    if not payload:
        return JWT_INVALID, 401
    
    #if not an admin
    if validate_permissions(["admin"], payload["sub"]) == False:
        return ERROR_403, 403

    course_key = client.key(COURSES, course_id)

    course = client.get(course_key)

    if course is None:
        return ERROR_403 , 403
    
    client.delete(course_key)
    return ('', 204)

@app.route('/courses/<int:course_id>/students', methods=['PATCH'])
def update_enrollment(course_id):
    payload = verify_jwt(request)

    if not payload:
        return JWT_INVALID, 401
    
    #if not an admin or instructor
    if validate_permissions(["admin", "instructor"], payload["sub"]) == False:
        return ERROR_403, 403
    
    content = request.json
    course_key = client.key(COURSES, course_id)
    course = client.get(course_key)
    student_query = client.query(kind='users')
    student_query.add_filter('role', '=', 'student')
    students_list = list(student_query.fetch())
    student_ids = []
    # get student ids to check if the removal or insertion is for a student
    for s in students_list:
        student_ids.append(s.key.id)

    print(student_ids)

    if 'enrollment' not in course:
        course['enrollment'] = []

    for s in content["add"]:
        if s in content["remove"] or s not in student_ids:
            return {"Error": "Enrollment data is invalid"}, 409
        if s in course['enrollment']:
            continue
        course['enrollment'].append(s)

    for s in content["remove"]:
        if s not in student_ids:
            return {"Error": "Enrollment data is invalid"}, 409
        if s not in course["enrollment"]:
            continue
        print("removing....", s)
        course['enrollment'].remove(s)
        
    client.put(course)
    
    return ('', 200)
            

@app.route('/course/<int:course_id>/students', methods=['GET'])
def get_enrolled_students(course_id):
    payload = verify_jwt(request)

    if not payload:
        return JWT_INVALID, 401
    
    # get requestor
    query = client.query(kind="users")
    query.add_filter('sub', '=', payload["sub"])
    requestor = list(query.fetch())[0]

    #if not an admin or instructor
    if validate_permissions(["admin", "instructor"], payload["sub"]) == False:
        return ERROR_403, 403
    
    course_key = client.key(COURSES, course_id)
    course = client.get(course_key)

    if requestor['role'] == 'instructor':
        if course['instructor'] != requestor.key.id:
            return ERROR_403, 403
    
    if 'enrollment' in course:
        return course['enrollment']
    
    return []
    

    




    

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

