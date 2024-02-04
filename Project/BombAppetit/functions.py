
import sys
import json
from datetime import datetime
from base64 import b64encode, b64decode

from Crypto.Cipher       import AES, PKCS1_v1_5
from Crypto.Hash         import SHA256
from Crypto.PublicKey    import RSA
from Crypto.Random       import get_random_bytes
from Crypto.Signature    import pkcs1_15
from Crypto.Util.Padding import pad, unpad


def create_key_pair(key_size, public_key_path, private_key_path):
    ''' Creates a RSA key pair of the given key_size in bytes and writes the public key and private key to separate files. '''
    try:
        key = RSA.generate(key_size)
    except ValueError:
        print(f"ERROR: Invalid key size '{key_size}'.", file=sys.stderr)
        exit(1)
    
    # Write public key to file
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(key.publickey().export_key())

    # Write private key to file
    with open(private_key_path, 'wb') as private_key_file:
        private_key_file.write(key.export_key())
    
    return [key.publickey().export_key(), key.export_key()]

def load_key_pair(public_key_path, private_key_path):
    ''' Loads a RSA key pair from the given public key and private key files. '''
    # Load public key
    with open(public_key_path, 'rb') as public_key_file:
        public_key = RSA.import_key(public_key_file.read())

    # Load private key
    with open(private_key_path, 'rb') as private_key_file:
        private_key = RSA.import_key(private_key_file.read())

    return [public_key.export_key(), private_key.export_key()]

def load_public_key(public_key_path):
    ''' Loads a RSA public key from the given public key file. '''
    # Load public key
    with open(public_key_path, 'rb') as public_key_file:
        public_key = RSA.import_key(public_key_file.read())

    return public_key.export_key()


# --- New functions ---

# -- output of encrypt_json() and input of decrypt_json() --
#
# encrypted_document = {
#     'content':       str of {    
#                          'json':                  json_object,
#                          'timestamp':             seconds in float with microsecond precision,
#                          'nonce':                 str,
#                          'encrypted_sections':    list,
#                          'fully_encrypted':       bool
#                      },
#     'encrypted_key': base64(rsa_encrypt(AES_key + AES_IV)),
#     'signature':     base64(rsa_sign(sha256(content))),
# }
#

def encrypt_json(json_object, src_private_key, dst_public_key, sections_to_encrypt=None):
    ''' Encrypts content using generated AES key, AES key will be encrypted
        with dst_public_key for confidentiality, the contents will be hashed,
        for integrity, and signed using src_private_key, for authenticity.
        
        sections_to_encrypt is a list of strings, each string is a key name of
        the JSON that should be encrypted. If sections_to_encrypt is None,
        the entire JSON will be encrypted, unless dst_public_key is None.'''
    # Generate AES key and encrypt contents
    gen_key = get_random_bytes(32) # 32 for AES-256
    gen_cipher = AES.new(gen_key, AES.MODE_CBC)

    json_mutable = json_object.copy()

    if sections_to_encrypt is None and dst_public_key is not None:
        # -- encrypt entire json --
        json_bytes = json.dumps(json_mutable).encode('utf-8')
        ciphertext = gen_cipher.encrypt(pad(json_bytes, AES.block_size))
        json_mutable = b64encode(ciphertext).decode('utf-8')
    elif sections_to_encrypt is not None and len(sections_to_encrypt):
        # -- encrypt only the specified sections --
        for section in sections_to_encrypt:
            # remove the section from the json
            content = json_mutable.get(section, None)
            if content is None:
                print(f"WARNING: section '{section}' not found in JSON")
                continue

            # encrypt the section
            json_bytes = json.dumps(content).encode('utf-8')
            ciphertext = gen_cipher.encrypt(pad(json_bytes, AES.block_size))
            encrypted_content = b64encode(ciphertext).decode('utf-8')

            # replace the section in the json
            json_mutable[section] = encrypted_content

    json_bytes = json.dumps({
        'json': json_mutable,
        'timestamp': datetime.utcnow().timestamp(),
        'nonce': get_random_bytes(16).hex(),
        'encrypted_sections': sections_to_encrypt if sections_to_encrypt is not None else [],
        'fully_encrypted': sections_to_encrypt is None and dst_public_key is not None,
    })

    if dst_public_key is not None:
        # Encrypt AES key and IV with public RSA key
        rsa_cipher = PKCS1_v1_5.new(dst_public_key)
        ciphertext = rsa_cipher.encrypt(gen_key + gen_cipher.iv) # this concatenates the bytes
        encrypted_key = b64encode(ciphertext).decode('utf-8')

    # Create contents digest and sign
    hashed = SHA256.new(json_bytes.encode('utf-8'))
    signer = pkcs1_15.new(src_private_key)
    ciphertext = signer.sign(hashed)
    encrypted_hash = b64encode(ciphertext).decode('utf-8')

    if dst_public_key is None:
        return { 'content':       json_bytes,
                 'signature':     encrypted_hash, }

    return     { 'content':       json_bytes,
                 'encrypted_key': encrypted_key,
                 'signature':     encrypted_hash, }

def decrypt_json(encrypted_document, src_public_key, dst_private_key, seen_nonces=None, freshness_check=True):
    ''' Decrypts encrypted_document using AES, AES key is found by decrypting
        with dst_private_key, the signature is checked using src_public_key,
        and the decrypted contents are returned directly.'''
    content       = encrypted_document.get('content')
    encrypted_key = encrypted_document.get('encrypted_key')
    if seen_nonces is None:
        seen_nonces = set()

    root_json = json.loads(content)
    if freshness_check:
        if root_json['nonce'] in seen_nonces:
            return None, "freshness check failed, nonce has been seen before"

        now = datetime.utcnow().timestamp() - 60 # 60 second leeway
        if root_json['timestamp'] < now:
            return None, "freshness check failed, timestamp is too old"

    if encrypted_key is not None:
        # Decrypt AES key and IV with private RSA key
        sentinel = get_random_bytes(32 + 16)
        rsa_cipher = PKCS1_v1_5.new(dst_private_key)
        ciphertext = b64decode(encrypted_key.encode())
        gen_key_iv = rsa_cipher.decrypt(ciphertext, sentinel, expected_pt_len=32 + 16)
        assert gen_key_iv != sentinel

        gen_key = gen_key_iv[:32]
        gen_iv  = gen_key_iv[32:32+16]
        gen_cipher = AES.new(gen_key, AES.MODE_CBC, gen_iv)

    if root_json['fully_encrypted']:
        # -- decrypt entire json --
        decoded_content = b64decode(root_json['json'].encode('utf-8'))
        raw_content = unpad(gen_cipher.decrypt(decoded_content), AES.block_size)
        json_mutable = json.loads(raw_content)
    else:
        # -- decrypt only the specified sections --
        json_mutable = root_json['json']
        for section in root_json['encrypted_sections']:
            # remove the section from the json
            decoded_content = json_mutable.get(section, None)
            if decoded_content is None:
                print(f"WARNING: section '{section}' not found in JSON")
                continue
            decoded_content = b64decode(decoded_content.encode('utf-8'))

            # decrypt the section
            raw_content = unpad(gen_cipher.decrypt(decoded_content), AES.block_size)

            # replace the section in the json
            json_mutable[section] = json.loads(raw_content)

    if src_public_key is not None:
        # This will raise an exception if the signature is invalid
        test_json_hash(encrypted_document, src_public_key)

    return json_mutable, root_json['nonce']

def test_json_hash(encrypted_document, src_public_key):
    ''' Tests the hash/signature of a JSON object. Ignores freshness.'''
    content = encrypted_document.get('content')
    signature = encrypted_document.get('signature')

    # Test raw_content with the signed digest
    hashed = SHA256.new(content.encode('utf-8'))
    signer = pkcs1_15.new(src_public_key)
    signature = b64decode(signature.encode())
    signer.verify(hashed, signature)


def create_keypair(key_size=2048):
    ''' Generates a new RSA keypair and returns it as a tuple of public and
        private keys.'''
    private_key = RSA.generate(key_size)
    public_key  = private_key.publickey()

    return private_key, public_key

def load_keypair(filename):
    ''' Loads a keypair from a file and returns it as a tuple of public and
        private keys.'''
    try:
        with open(filename, 'r') as f:
            key = RSA.import_key(f.read())
        
        if key.has_private():
            return key, key.publickey()
        else:
            return None, key
    except FileNotFoundError:
        return None, None

def save_key(filename, key):
    ''' Saves a key to a file.'''
    with open(filename, 'w') as f:
        f.write(key.export_key().decode('utf-8'))

def str_to_key(key_str):
    ''' Converts a string to a public key.'''
    return RSA.import_key(key_str)
