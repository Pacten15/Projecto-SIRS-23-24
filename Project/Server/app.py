import sys
import json
from datetime import datetime

import psycopg2
from sshtunnel import SSHTunnelForwarder

sys.path.append('..')
try:
    import BombAppetit as BA
except ImportError:
    print("Import failed. Install dependencies with: pip3 install -r requirements.txt")
    sys.exit(1)

from flask import Flask
from flask import request


app = Flask(__name__)

tunnel =  SSHTunnelForwarder(
        ("192.168.0.100", 22),
        ssh_username="kali",
        ssh_password="kali",
        remote_bind_address=('192.168.0.100', 5432))

tunnel.start()

database = psycopg2.connect(host=tunnel.local_bind_host, port = tunnel.local_bind_port,  database="sirs_bombappetit", user="sirs_dbadmin", password="sirs_dbpassword")
CREATE_TABLES = """
                CREATE TABLE IF NOT EXISTS ba_restaurants (
                        id              SERIAL PRIMARY KEY,
                        data            JSONB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ba_users (
                        name            TEXT PRIMARY KEY,
                        public_key      TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ba_vouchers (
                        code            TEXT PRIMARY KEY,
                        description     TEXT NOT NULL,
                        restaurant_id   SERIAL REFERENCES ba_restaurants (id),
                        user_name       TEXT REFERENCES ba_users (name)
                );
                CREATE TABLE IF NOT EXISTS ba_reviews (
                        review          JSONB NOT NULL,
                        restaurant_id   SERIAL REFERENCES ba_restaurants (id),
                        user_name       TEXT REFERENCES ba_users (name),
                        UNIQUE (restaurant_id, user_name)
                );"""
with database, database.cursor() as db:
    db.execute(CREATE_TABLES)

cached_users = {}
seen_nonces_by_time = {}

key_path = 'keys/private_server_key.pem'
server_private_key, server_public_key = BA.load_keypair(key_path)
if server_private_key is None or server_public_key is None:
    print(f"Could not load server keypair from '{key_path}'")
    sys.exit(1)

def get_seen_nonces():
    ''' Returns a set of the seen nonces.'''
    seen_nonces = set()
    for second in seen_nonces_by_time:
        seen_nonces.update(seen_nonces_by_time[second])
    return seen_nonces

def update_seen_nonces(nonce):
    ''' Adds a nonce to the seen nonces for the current second.
        Also, removes nonces older than a minute.'''
    current_second = int(datetime.utcnow().timestamp())
    if current_second not in seen_nonces_by_time:
        seen_nonces_by_time[current_second] = set({nonce})

    to_delete = []
    for second in seen_nonces_by_time:
        if second < current_second - 60:
            to_delete.append(second)
    for second in to_delete:
        seen_nonces_by_time.pop(second)

def is_register_operation(message):
    if not ('public_key' in message and 'operation' in message and message['operation'] == 'create'):
        return False
    cached_users[message['user_name']] = message['public_key']
    return True

def read_json_request(json_request):
    ''' Reads and validates JSON message.
        Returns message and user name if valid, else None and error message.'''
    if 'content' not in json_request or 'signature' not in json_request:
        return None, "Invalid request: missing content or signature"

    message = json.loads(json_request.get('content')).get('json')
    if 'user_name' not in message:
        return None, "Invalid request: missing user_name"
    user_name = message['user_name']

    if user_name not in cached_users:
        with database, database.cursor() as db:
            db.execute("SELECT public_key FROM ba_users WHERE name = (%s);", (user_name,))
            result = db.fetchone()
            if result is None and not is_register_operation(message):
                # could change to check if message has a public key and use that, for the register endpoint
                return None, "Invalid request: unknown user"
            elif result is not None:
                cached_users[user_name] = result[0]
    
    user_public_key = BA.str_to_key(cached_users[user_name])

    try:
        json_message, nonce = BA.decrypt_json(json_request, user_public_key, server_private_key, seen_nonces=get_seen_nonces())
        if json_message is None:
            return None, f"Invalid request: {nonce}"
        update_seen_nonces(nonce)
    except ValueError as e:
        return None, f"Invalid request: {e}"

    return json_message, user_name

def send_json_response(json_response, status_code, user_name=None, sections_to_encrypt=None):
    ''' Creates proper JSON response.
        Only use user_name if you want to encrypt the response.
        Only use sections_to_encrypt if you want mixed encryption.'''    
    if user_name is not None:
        user_public_key = BA.str_to_key(cached_users[user_name])
    else:
        # no user name, no public key, no encryption
        user_public_key = None

    return BA.encrypt_json(json_response, server_private_key, user_public_key, sections_to_encrypt=sections_to_encrypt), status_code


# ----- RESTAURANTS -----

@app.post("/api/restaurants")
def api_restaurant():
    message, user_name = read_json_request( request.get_json() )

    if message is None:
        return send_json_response({"error": user_name}, 400)

    if 'operation' not in message or message['operation'] not in ('create', 'list', 'read', 'update', 'delete'):
        return send_json_response({"error": "Invalid operation"}, 400)
    
    # ----- CREATE -----

    if message['operation'] == 'create':
        if user_name != "admin":
            return send_json_response({"error": "Only admin can add restaurants"}, 403)

        if 'data' not in message:
            return send_json_response({"error": "Missing data"}, 400)

        with database, database.cursor() as db:
            db.execute("INSERT INTO ba_restaurants (data) VALUES (%s) RETURNING id;", (json.dumps(message['data']),))
            restaurant_id = db.fetchone()[0]

        return send_json_response({"id": restaurant_id}, 201)

    # ----- LIST -----

    if message['operation'] == 'list':
        with database, database.cursor() as db:
            db.execute("SELECT id, data FROM ba_restaurants;")
            restaurants = db.fetchall()

        return send_json_response({"restaurants": [{"id": id, "data": data}
                                                   for id, data in restaurants]}, 200)

    # ----- READ -----
    
    if message['operation'] == 'read':
        if 'id' not in message:
            return send_json_response({"error": "Missing id"}, 400)

        with database, database.cursor() as db:
            db.execute("SELECT data FROM ba_restaurants WHERE id = (%s);", (message['id'],))
            result = db.fetchone()

        if result is None:
            return send_json_response({"error": "Restaurant not found"}, 404)
        
        restaurant = result[0]
        
        # get vouchers for restaurant and add to response
        with database, database.cursor() as db:
            db.execute("SELECT code, description FROM ba_vouchers WHERE restaurant_id = (%s) AND user_name = (%s);",
                       (message['id'], user_name))
            vouchers = db.fetchall()
        print(vouchers)
        restaurant['mealVouchers'] = list({"code": code, "description": description} for code, description in vouchers)

        # get reviews for restaurant and add to response
        with database, database.cursor() as db:
            db.execute("SELECT review FROM ba_reviews WHERE restaurant_id = (%s);", (message['id'],))
            reviews = db.fetchall()
        print(reviews)
        restaurant['reviews'] = list({"review": review[0]} for review in reviews)
        print(restaurant)
        return send_json_response(restaurant, 200, user_name, sections_to_encrypt=['mealVouchers'])

    # ----- UPDATE -----

    if message['operation'] == 'update':
        if user_name != "admin":
            return send_json_response({"error": "Only admin can update restaurants"}, 403)

        if 'id' not in message or 'data' not in message:
            return send_json_response({"error": "Missing id or data"}, 400)

        with database, database.cursor() as db:
            db.execute("UPDATE ba_restaurants SET data = (%s) WHERE id = (%s);",
                       (json.dumps(message['data']), message['id']))

        return send_json_response({}, 200)

    # ----- DELETE -----

    if message['operation'] == 'delete':
        if user_name != "admin":
            return send_json_response({"error": "Only admin can delete restaurants"}, 403)

        if 'id' not in message:
            return send_json_response({"error": "Missing id"}, 400)

        with database, database.cursor() as db:
            db.execute("DELETE FROM ba_vouchers WHERE restaurant_id = (%s);", (message['id'],))
            db.execute("DELETE FROM ba_reviews WHERE restaurant_id = (%s);", (message['id'],))
            db.execute("DELETE FROM ba_restaurants WHERE id = (%s);", (message['id'],))

        return send_json_response({}, 200)


# ----- USERS -----

@app.post("/api/users")
def api_users():
    message, user_name = read_json_request( request.get_json() )

    if message is None:
        return send_json_response({"error": user_name}, 400)

    if 'operation' not in message or message['operation'] not in ('create', 'list', 'read', 'update', 'delete','login'):
        return send_json_response({"error": "Invalid operation"}, 400)

    # ----- CREATE -----

    if message['operation'] == 'create':
        if 'user_name' not in message or 'public_key' not in message:
            return send_json_response({"error": "Missing user_name or public_key"}, 400)

        with database, database.cursor() as db:
            db.execute("INSERT INTO ba_users (name, public_key) VALUES (%s, %s);",
                       (message['user_name'], message['public_key']))

        return send_json_response({}, 201)

    # ----- LIST -----

    if message['operation'] == 'list':
        with database, database.cursor() as db:
            db.execute("SELECT name, public_key FROM ba_users;")
            users = db.fetchall()

        return send_json_response({"users": [{"name": name, "public_key": public_key} for name, public_key in users]}, 200)

    # ----- READ -----
    
    if message['operation'] == 'read':
        if 'user_name_to_read' not in message:
            return send_json_response({"error": "Missing user_name_to_read"}, 400)

        with database, database.cursor() as db:
            db.execute("SELECT public_key FROM ba_users WHERE name = (%s);", (message['user_name_to_read'],))
            result = db.fetchone()

        if result is None:
            return send_json_response({"error": "User not found"}, 404)

        return send_json_response({"public_key": result[0]}, 200)

    # ------ LOGIN -----
    if message['operation'] == 'login':
        if 'user_name' not in message or 'public_key' not in message:
            return send_json_response({"error": "Missing user_name or public_key"}, 400)

        with database, database.cursor() as db:
            db.execute("SELECT public_key FROM ba_users WHERE name = (%s);", (message['user_name'],))
            result = db.fetchone()

        if result is None:
            return send_json_response({"error": "User not found"}, 404)

        if result[0] != message['public_key']:
            return send_json_response({"error": "Invalid public key"}, 403)

        return send_json_response({}, 200)

    # ----- UPDATE -----

    if message['operation'] == 'update':
        if 'user_name' not in message or 'public_key' not in message:
            return send_json_response({"error": "Missing user_name or public_key"}, 400)

        with database, database.cursor() as db:
            db.execute("UPDATE ba_users SET public_key = (%s) WHERE name = (%s);",
                       (message['public_key'], message['user_name']))
        cached_users[message['user_name']] = message['public_key']
        
        return send_json_response({}, 200)

    # ----- DELETE -----

    if message['operation'] == 'delete':

        if 'user_name' not in message:
            return send_json_response({"error": "Missing user_name"}, 400)
        elif message['user_name'] == "admin":
            if message['user_name_to_delete'] == "admin":
                return send_json_response({"error": "Cannot delete admin"}, 403)
        elif message['user_name'] != "admin" and message['user_name_to_delete'] != message['user_name']:
            return send_json_response({"error": "Cannot delete other users as a user"}, 403)
    
        cached_users.pop(message['user_name_to_delete'], None)

        with database, database.cursor() as db:
            db.execute("DELETE FROM ba_vouchers WHERE user_name = (%s);", (message['user_name_to_delete'],))
            db.execute("DELETE FROM ba_reviews WHERE user_name = (%s);", (message['user_name_to_delete'],))
            db.execute("DELETE FROM ba_users WHERE name = (%s);", (message['user_name_to_delete'],))

        return send_json_response({}, 200)


# ----- VOUCHERS -----

@app.post("/api/vouchers")
def api_vouchers():
    message, user_name = read_json_request( request.get_json() )

    if message is None:
        return send_json_response({"error": user_name}, 400)

    if 'operation' not in message or message['operation'] not in ('create', 'list', 'update', 'delete'):
        return send_json_response({"error": "Invalid operation"}, 400)

    # ----- CREATE -----

    if message['operation'] == 'create':
        if user_name != "admin":
            return send_json_response({"error": "Only admin can add vouchers"}, 403)

        if 'user_name_voucher' not in message or 'code' not in message or 'description' not in message or 'restaurant_id' not in message:
            return send_json_response({"error": "Missing code, description or restaurant_id"}, 400)
        
        with database, database.cursor() as db:
            db.execute("INSERT INTO ba_vouchers (code, description, restaurant_id, user_name) VALUES (%s, %s, %s, %s);",
                       (message['code'], message['description'], message['restaurant_id'], message['user_name_voucher']))
        return send_json_response({}, 201)

    # ----- LIST -----

    if message['operation'] == 'list':
        with database, database.cursor() as db:
            db.execute("SELECT code, description, restaurant_id FROM ba_vouchers WHERE user_name = (%s);", (user_name,))
            vouchers = db.fetchall()

        return send_json_response({"vouchers": [{"code": code, "description": description, "restaurant_id": restaurant_id} for code, description, restaurant_id in vouchers]}, 200, user_name, sections_to_encrypt=['vouchers'])

    # ----- UPDATE -----

    if message['operation'] == 'update':
        if 'new_user' not in message:
            return send_json_response({"error": "Missing new_user"}, 400)
        elif 'code' not in message:
            return send_json_response({"error": "Missing code"}, 400)

        with database, database.cursor() as db:
            db.execute("UPDATE ba_vouchers SET user_name = (%s) WHERE user_name = (%s) AND code = (%s);",
                       (message['new_user'], user_name, message['code']))

        return send_json_response({}, 200)

    # ----- DELETE -----

    if message['operation'] == 'delete':
        if 'code' not in message:
            return send_json_response({"error": "Missing code"}, 400)

        with database, database.cursor() as db:
            db.execute("DELETE FROM ba_vouchers WHERE code = (%s) AND user_name = (%s);",
                       (message['code'], user_name))

        return send_json_response({}, 200)


# ----- REVIEWS -----

@app.post("/api/reviews")
def api_reviews():
    message, user_name = read_json_request( request.get_json() )

    if message is None:
        return send_json_response({"error": user_name}, 400)

    if 'operation' not in message or message['operation'] not in ('create', 'list', 'update', 'delete'):
        return send_json_response({"error": "Invalid operation"}, 400)

    # ----- CREATE -----

    if message['operation'] == 'create':
        if 'review' not in message or 'restaurant_id' not in message:
            return send_json_response({"error": "Missing review or restaurant_id"}, 400)

        with database, database.cursor() as db:
            db.execute("INSERT INTO ba_reviews (review, restaurant_id, user_name) VALUES (%s, %s, %s);",
                       (json.dumps(message['review']), message['restaurant_id'], user_name))

        return send_json_response({}, 201)

    # ----- LIST -----

    if message['operation'] == 'list':
        with database, database.cursor() as db:
            db.execute("SELECT review, restaurant_id FROM ba_reviews WHERE user_name = (%s);", (user_name,))
            reviews = db.fetchall()

        return send_json_response({"reviews": [{"review": review, "restaurant_id": restaurant_id} for review, restaurant_id in reviews]}, 200)

    # ----- UPDATE -----

    if message['operation'] == 'update':
        if 'review' not in message:
            return send_json_response({"error": "Missing review"}, 400)
        if 'restaurant_id' not in message:
            return send_json_response({"error": "Missing restaurant_id"}, 400)

        with database, database.cursor() as db:
            db.execute("UPDATE ba_reviews SET review = (%s) WHERE user_name = (%s) AND restaurant_id = (%s);",
                       (json.dumps(message['review']), user_name, message['restaurant_id']))

        return send_json_response({}, 200)

    # ----- DELETE -----

    if message['operation'] == 'delete':
        if 'restaurant_id' not in message:
            return send_json_response({"error": "Missing restaurant_id"}, 400)

        with database, database.cursor() as db:
            db.execute("DELETE FROM ba_reviews WHERE restaurant_id = (%s) AND user_name = (%s);",
                       (message['restaurant_id'], user_name))

        return send_json_response({}, 200)

if __name__ == '__main__':
    # Enable server-side authentication
    app.run(host='192.168.1.254', port=443, ssl_context=('keys/certificate_server.pem', 'keys/private_server_key.pem'))
