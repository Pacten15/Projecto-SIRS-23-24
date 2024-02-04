import os
import sys
import json
import requests
from datetime import datetime

import warnings
from urllib3.exceptions import SubjectAltNameWarning
warnings.filterwarnings('ignore', category=SubjectAltNameWarning)

sys.path.append("..")
try:
    import BombAppetit as BA
except ImportError:
    print("Import failed. Install dependencies with: pip3 install -r requirements.txt")
    sys.exit(1)

seen_nonces_by_time = {}

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


def read_json_file(file_path):
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
            return data
        except FileNotFoundError:
            print("File not found.")
            return None
        except json.JSONDecodeError:
            print("Invalid JSON format.")
            return None

def https_post_requests(url, data, certificate_client_path, key_path, certificate_server_path):
        try:
            response = requests.post(url, json=data, cert=(certificate_client_path, key_path), verify=certificate_server_path)
            data = response.json()
            status_code = response.status_code
            return [data, status_code]
        except requests.exceptions.HTTPError as errh:
            print ("Http Error:",errh)
        except requests.exceptions.ConnectionError as errc:
            print ("Error Connecting:",errc)
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
        except requests.exceptions.RequestException as err:
            print ("Something went wrong with the request:",err)

class ClientInterface:
    def __init__(self, base_url, username, certificate_server_path, certificate_client_path, key_path, server_public_key_path):
        self.base_url = base_url
        self.username = ''.join(username)
        self.certificate_client_path = certificate_client_path
        self.key_path = key_path
        self.certificate_server_path = certificate_server_path
        self.privkey = None
        self.pubkey = None
        self.server_pubkey = BA.load_public_key(server_public_key_path)
        self.user_keys = {}

    # --- USER ---

    def register_user(self):
        # Create key pair
        keys = BA.create_key_pair(2048, 'keys/' + self.username + '.pubkey', 'keys/' + self.username + '.privkey')
        public_key = keys[0]
        # Create user data dictionary
        user_data = {
            'user_name': self.username,
            'public_key': public_key.decode(),
            'operation': 'create' 
        }

        #Load key pair
        keys = BA.load_key_pair('keys/' + self.username + '.pubkey', 'keys/' + self.username + '.privkey')
        self.pubkey = keys[0]
        self.privkey = keys[1]

        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(user_data, private_key, None)
        response = https_post_requests(self.base_url + '/users', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 201:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("User created successfully.")
        elif response[1] == 400:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def login_user(self):
        keys = BA.load_key_pair('keys/' + self.username + '.pubkey', 'keys/' + self.username + '.privkey')
        self.pubkey = keys[0]
        self.privkey = keys[1]
        login_data = {
            'user_name': self.username,
            'public_key': self.pubkey.decode(),
            'operation': 'login'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(login_data, private_key, None)
        response = https_post_requests(self.base_url + '/users', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("User logged in successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def update_user(self):
        keys = BA.create_key_pair(2048, 'keys/' + self.username + '.pubkey', 'keys/' + self.username + '.privkey')
        public_key = keys[0]
        private_key = keys[1]
        update_json = {
            'user_name': self.username,
            'public_key': public_key.decode(),
            'operation': 'update'
        }

        private_key_old = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(update_json, private_key_old, None) 
        response= https_post_requests(self.base_url + '/users', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key_old, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            self.privkey = private_key
            self.pubkey = public_key
            print("User updated successfully.")
        elif response[1] == 400:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key_old, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def read_user(self, username):
        read_json = {
            'user_name': self.username,
            'user_name_to_read': username,
            'operation': 'read'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(read_json, private_key, None)
        response = https_post_requests(self.base_url + '/users', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            public_key = json_object.get('public_key')
            print("User: " + username + "\nPublic key: " + public_key + "\n")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def list_all_users(self):
        list_users= {
            'user_name': self.username,
            'operation': 'list'
        }

        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(list_users, private_key, None)
        response = https_post_requests(self.base_url + '/users', data, self.certificate_client_path, self.key_path, self.certificate_server_path)

        if response[1] == 200:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)

            users = json_object.get('users')
            for user in users:
                print("User: " + user.get('name') + "\nPublic key: " + user.get('public_key') + "\n")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            error_message = json_object.get('error')
            print(error_message)


    def delete_user(self, username):
        delete_json = {
            'user_name': self.username,
            'user_name_to_delete': username,
            'operation': 'delete'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(delete_json, private_key, None)
        response = https_post_requests(self.base_url + '/users', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            os.remove('keys/' + username + '.pubkey')
            os.remove('keys/' + username + '.privkey')
            print("User deleted successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)

    # --- RESTAURANT ---

    def create_restaurant(self, restaurantInfoPath):
        restaurantInfo = read_json_file(restaurantInfoPath)
        create_json = {
            'user_name': self.username,
            'data': restaurantInfo,
            'operation': 'create'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(create_json, private_key, None)
        response = https_post_requests(self.base_url + '/restaurants', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 201:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Restaurant created successfully with id " + str(json_object.get('id')) + " .")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)

    def get_all_user_keys(self):
        list_users= {
            'user_name': self.username,
            'operation': 'list'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(list_users, private_key, None)
        response = https_post_requests(self.base_url + '/users', data, self.certificate_client_path, self.key_path, self.certificate_server_path)

        if response[1] == 200:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)

            users = json_object.get('users')
            for user in users:
                self.user_keys[user.get('name')] = user.get('public_key')

    def read_restaurant(self, restaurantId):
        read_json = {
            'user_name': self.username,
            'id': restaurantId,
            'operation': 'read'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(read_json, private_key, None)
        response = https_post_requests(self.base_url + '/restaurants', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            restaurantInfo, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)

            reviews = restaurantInfo.pop('reviews')

            print("Restaurant id: " + str(restaurantId) + "\nRestaurant data: ")
            print(json.dumps(restaurantInfo, indent=4, ensure_ascii=False))

            if len(reviews) > 0:
                print("\nReviews: ")
                self.get_all_user_keys()
                for review in reviews:
                    content = json.loads(review['review'].get('content')).get('json')
                    username = content.get('user_name')
                    user_key = self.user_keys.get(username)
                    user_key = BA.str_to_key(user_key)
                    rev, _ = BA.decrypt_json(review['review'], user_key, None, freshness_check=False)
                    print(rev)
                print()
                    
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def list_restaurants(self):
        list_json = {
            'user_name': self.username,
            'operation': 'list'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(list_json, private_key, None)
        response = https_post_requests(self.base_url + '/restaurants', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)

            restaurants = json_object.get('restaurants')
            if restaurants is None:
                print("No restaurants found.")
                return
            for restaurant in restaurants:
                print("\nRestaurant_id : " + str(restaurant.get('id')) + "\n\nRestaurant_data: \n")
                print(restaurant.get('data'))


    def delete_restaurant(self, restaurantInfoId):
        delete_json = {
            'user_name': self.username,
            'id': restaurantInfoId,
            'operation': 'delete'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(delete_json, private_key, None)
        response = https_post_requests(self.base_url + '/restaurants', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Restaurant deleted successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def update_restaurant(self, restaurantInfoId, restaurantInfoPath):
        restaurantInfo = read_json_file(restaurantInfoPath)
        update_json = {
            'user_name': self.username, 
            'id': restaurantInfoId, 
            'data': restaurantInfo,
            'operation': 'update'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(update_json, private_key, None)
        response = https_post_requests(self.base_url + '/restaurants', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Restaurant updated successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)

    # --- VOUCHER ---

    def create_voucher(self, username, restaurantId, voucherCode, description):
        data = {
            'user_name': self.username,
            'user_name_voucher': username,
            'restaurant_id': restaurantId,
            'code': voucherCode,
            'description': description,
            'operation': 'create'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())
        data = BA.encrypt_json(data, private_key, server_public_key, sections_to_encrypt=['code', 'description'])

        response = https_post_requests(self.base_url + '/vouchers', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 201:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Voucher created successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def list_vouchers(self):
        list_json = {
            'user_name': self.username,
            'operation': 'list'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        data = BA.encrypt_json(list_json, private_key, None)
        response = https_post_requests(self.base_url + '/vouchers', data, self.certificate_client_path, self.key_path, self.certificate_server_path)

        response_data = response[0]

        server_public_key = BA.str_to_key(self.server_pubkey.decode())
        content, nonce = BA.decrypt_json(response_data, server_public_key, private_key, seen_nonces=get_seen_nonces())
        update_seen_nonces(nonce)
        vouchers = content.get('vouchers')

        if vouchers is None:
            print("No vouchers found.")
            return

        print("\nThe user " + self.username + " has the following vouchers:")
        for voucher in vouchers:
            print("\nCode: " + voucher['code'] + "| Description: " + voucher['description'] + "| Restaurant id: " + str(voucher['restaurant_id']) + "\n")


    def transfer_voucher(self, newUser, voucherCode):
        transfer_json = {
            'user_name': self.username,
            'new_user': newUser,
            'code': voucherCode,
            'operation': 'update'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(transfer_json, private_key, server_public_key, sections_to_encrypt=['code'])
        response = https_post_requests(self.base_url + '/vouchers', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Voucher transferred successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def use_voucher(self, code):
        use_json = {
            'user_name': self.username,
            'code': code,
            'operation': 'delete'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())
        
        data = BA.encrypt_json(use_json, private_key, server_public_key, sections_to_encrypt=['code'])
        response = https_post_requests(self.base_url + '/vouchers', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Voucher used successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)

    # --- REVIEW ---

    def write_review(self, restaurantId, score, comment):
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())
        review = {
            'user_name': self.username,
            'score': score,
            'comment': comment
        }
        review = BA.encrypt_json(review, private_key, None)
        write_json = {
            'user_name': self.username,
            'restaurant_id': restaurantId,
            'review': review,
            'operation': 'create'
        }
        data = BA.encrypt_json(write_json, private_key, None)
        response = https_post_requests(self.base_url + '/reviews', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 201:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Review created successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def read_own_reviews(self):
        read_json = {
            'user_name': self.username,
            'operation': 'list'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(read_json, private_key, None)
        response = https_post_requests(self.base_url + '/reviews', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            
            reviews = json_object.get('reviews')
            if reviews is None:
                print("No reviews found.")
                return
            for review in reviews:
                rev, _ = BA.decrypt_json(review['review'], None, private_key, freshness_check=False)
                score = rev.get('score')
                comment = rev.get('comment')
                print("\nReview_Score: " + score + "| Review_Comment: " + comment + "| Restaurant: " + str(review['restaurant_id']) + "\n")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def update_review(self, restaurantId, score, comment):
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())
        review = {
            'user_name': self.username,
            'score': score,
            'comment': comment
        }
        review = BA.encrypt_json(review, private_key, None)
        update_json = {
            'user_name': self.username,
            'restaurant_id': restaurantId,
            'review': review,
            'operation': 'update'
        }
        
        data = BA.encrypt_json(update_json, private_key, None)
        response = https_post_requests(self.base_url + '/reviews', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Review updated successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)


    def delete_review(self, restaurantId):
        delete_json = {
            'user_name': self.username,
            'restaurant_id': restaurantId,
            'operation': 'delete'
        }
        private_key = BA.str_to_key(self.privkey.decode())
        server_public_key = BA.str_to_key(self.server_pubkey.decode())

        data = BA.encrypt_json(delete_json, private_key, None)
        response = https_post_requests(self.base_url + '/reviews', data, self.certificate_client_path, self.key_path, self.certificate_server_path)
        if response[1] == 200:
            _, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            print("Review deleted successfully.")
        else:
            json_object, nonce = BA.decrypt_json(response[0], server_public_key, private_key, seen_nonces=get_seen_nonces())
            update_seen_nonces(nonce)
            error_message = json_object.get('error')
            print(error_message)    

    # --- INTERFACE ---

    def help_command_client(self):
        print("Available commands:")
        print("1.  delete self")
        print("2.  update self keys")
        print("3.  read_user")
        print("4.  list users")
        print("5.  list restaurants")
        print("6.  read restaurant")
        print("7.  list vouchers")
        print("8.  transfer voucher")
        print("9.  redeem voucher")
        print("10.  write review")
        print("11. read own reviews")
        print("12. update review")
        print("13. delete review")
        print("14. exit")


    def help_command_admin(self):
        print("Available commands:")
        print("1.   list users")
        print("2.   delete user")
        print("3.   update admin keys")
        print("4.   create restaurant")
        print("5.   list restaurants")
        print("6.   read restaurant")
        print("7.   update restaurant")
        print("8.   delete restaurant")
        print("9.   create voucher")
        print("10.  exit")


    def clientMenu(self):
        while(True):
            self.help_command_client()

            choice = input("Enter your choice: ")

            if choice == "1":
                self.delete_user(self.username)
                break

            elif choice == "2":
                self.update_user()

            elif choice == "3":
                usernameToRead = input("Enter the username to read: ")
                usernameToRead = ''.join(usernameToRead)
                self.read_user(usernameToRead)
            
            elif choice == "4":
                self.list_all_users()

            elif choice == "5":
                self.list_restaurants()
            
            elif choice == "6":
                restaurantId = input("Enter the restaurant id: ")
                self.read_restaurant(restaurantId)
            
            elif choice == "7":
                self.list_vouchers()
            
            elif choice == "8":
                newUser = input("Enter the new user: ")
                voucherCode = input("Enter the voucher code: ")
                voucherCode = ''.join(voucherCode)
                self.transfer_voucher(newUser, voucherCode)
            
            elif choice == "9":
                voucherCode = input("Enter the voucher code: ")
                self.use_voucher(voucherCode)
            
            elif choice == "10":
                restaurantId = input("Enter the restaurant id: ")
                score = input("Enter the score: ")
                comment = input("Enter the comment: ")
                comment = ''.join(comment)
                self.write_review(restaurantId, score, comment)
            
            elif choice == "11":
                self.read_own_reviews()
            
            elif choice == "12":
                reviewId = input("Enter the restaurant id: ")
                score = input("Enter the score: ")
                comment = input("Enter the comment: ")
                comment = ''.join(comment)
                self.update_review(reviewId, score, comment)

            elif choice == "13":
                reviewId = input("Enter the restaurant id: ")
                self.delete_review(reviewId)

            elif choice == "14":
                break
            else:
                print("Invalid choice. Please try again.")


    def adminMenu(self):
        while(True):

            self.help_command_admin()

            choice = input("Enter your choice: ")

            if choice == "1":
                self.list_all_users()

            elif choice == "2":
                usernameToDelete = input("Enter the username to delete: ")
                usernameToDelete = ''.join(usernameToDelete)
                self.delete_user(usernameToDelete)
            
            elif choice == "3":
                self.update_user()
            
            elif choice == "4":
                restaurantInfoPath = input("Enter the path to the restaurant info file: ")
                restaurantInfoPath = ''.join(restaurantInfoPath)
                self.create_restaurant(restaurantInfoPath)
            
            elif choice == "5":
                self.list_restaurants()
            
            elif choice == "6":
                restaurantId = input("Enter the restaurant id: ")
                self.read_restaurant(restaurantId)
            
            elif choice == "7":
                restaurantId = input("Enter the restaurant id: ")
                restaurantInfoPath = input("Enter the path to the restaurant info file: ")
                restaurantInfoPath = ''.join(restaurantInfoPath)
                self.update_restaurant(restaurantId, restaurantInfoPath)

            elif choice == "8":
                restaurantId = input("Enter the restaurant id: ")
                self.delete_restaurant(restaurantId)
            
            elif choice == "9":
                username = input("Enter the username: ")
                username = ''.join(username)
                restaurantId = input("Enter the restaurant id: ")
                voucherCode = input("Enter the voucher code: ")
                voucherCode = ''.join(voucherCode)
                description = input("Enter the voucher description: ")
                description = ''.join(description)
                self.create_voucher(username, restaurantId, voucherCode, description)

            elif choice == "10":
                break

            else:
                print("Invalid choice. Please try again.")


    def registerLogic(self):
        self.register_user()
        if(self.username == "admin"):
            self.adminMenu()
        else:
            self.clientMenu()


    def loginLogic(self):
        if(os.path.isfile('keys/' + self.username + '.pubkey') and os.path.isfile('keys/' + self.username + '.privkey')):
            self.login_user()
            if(self.username == "admin"):
                self.adminMenu()
            else:
                self.clientMenu()
        else:
            print("User not registered. Please register first.")
            self.InterfaceMenu()


    def InterfaceMenu(self):
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            self.loginLogic()
        elif choice == "2":
            self.registerLogic()
        elif choice == "3":
            exit()
        else:
            print("Invalid choice. Please try again.")
            self.InterfaceMenu()



if __name__ == "__main__":
    base_url = "https://192.168.1.254:443/api"  # Replace with your actual base URL
    # Specify the path to your certificate file
    certificate_server_path = "certificate/certificate_server.pem"
    certificate_client_path = "certificate/cert.pem"
    key_path = "certificate/key.pem"
    server_public_key_path = "keys/public_server_key.key"

    username = input("Enter your username: ")
    client = ClientInterface(base_url, username, certificate_server_path, certificate_client_path, key_path, server_public_key_path)
    client.InterfaceMenu()
