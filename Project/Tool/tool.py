import sys
import json
import argparse

sys.path.append('..')
try:
    import BombAppetit as BA
except ImportError:
    print("Import failed. Install dependencies with: pip3 install -r requirements.txt")
    sys.exit(1)

parser = argparse.ArgumentParser(description='BombAppetit library front-end demo.')
parser.add_argument('action', choices=['generate', 'protect', 'unprotect', 'check'], help='Action to perform')

# generate has one argument: outfile
# protect has five arguments: infile, src_key, dst_key, outfile, sections_to_encrypt
#    dst_key is optional, if not provided it means no encryption
#    sections_to_encrypt is a comma-separated list of sections to encrypt
# unprotect has four arguments: infile, src_key, dst_key, outfile
#    dst_key is optional if infile is not encrypted
# check has three arguments: infile, src_key, dst_key
#    dst_key is optional if infile is not encrypted

parser.add_argument('infile', help='Input file')
parser.add_argument('src_key', nargs='?', help='Source key file')
parser.add_argument('dst_key', nargs='?', help='Destination key file')
parser.add_argument('outfile', nargs='?', help='Output file')
parser.add_argument('sections_to_encrypt', nargs='?', help='Sections to encrypt')

args = parser.parse_args()

if args.action == 'generate':
    # generate key pair, store in 'private_' and 'public_' prefixed output files
    private_key, public_key = BA.create_keypair(4096)

    BA.save_key('private_' + args.infile, private_key)
    BA.save_key('public_' + args.infile, public_key)
    exit(0)

if args.action == 'protect':
    # load json from infile
    with open(args.infile, 'r') as f:
        json_object = json.load(f)

    # load source key
    with open(args.src_key, 'rb') as f:
        src_key = BA.str_to_key(f.read())

    # load destination key
    with open(args.dst_key, 'rb') as f:
        dst_key = BA.str_to_key(f.read())
    
    sections_to_encrypt = None
    if args.sections_to_encrypt is not None:
        sections_to_encrypt = json.loads(args.sections_to_encrypt)

    # encrypt json
    encrypted_json = BA.encrypt_json(json_object, src_key, dst_key, sections_to_encrypt)

    # write encrypted json to outfile
    with open(args.outfile, 'w') as f:
        json.dump(encrypted_json, f)
    exit(0)

def get_nonces():
    try:
        with open('seen_nonces.json', 'r') as f:
            seen_nonces = set( json.load(f) )
    except FileNotFoundError:
        seen_nonces = set()
    return seen_nonces

def set_nonces(seen_nonces):
    with open('seen_nonces.json', 'w') as f:
        json.dump(list(seen_nonces), f)

if args.action == 'unprotect':
    # load encrypted json from infile
    with open(args.infile, 'r') as f:
        encrypted_json = json.load(f)

    # load source key
    with open(args.src_key, 'rb') as f:
        src_key = BA.str_to_key(f.read())

    # load destination key
    with open(args.dst_key, 'rb') as f:
        dst_key = BA.str_to_key(f.read())

    # decrypt json
    nonces = get_nonces()
    json_object, nonce = BA.decrypt_json(encrypted_json, src_key, dst_key, seen_nonces=nonces)
    if json_object is None:
        print(f"ERROR: Document is invalid, reason: {nonce}")
        exit(1)
    nonces.add(nonce)
    set_nonces(nonces)

    # write decrypted json to outfile
    with open(args.outfile, 'w') as f:
        json.dump(json_object, f)
    exit(0)

if args.action == 'check':
    # load encrypted json from infile
    with open(args.infile, 'r') as f:
        encrypted_json = json.load(f)

    # load source key
    with open(args.src_key, 'rb') as f:
        src_key = BA.str_to_key(f.read())

    # load destination key
    with open(args.dst_key, 'rb') as f:
        dst_key = BA.str_to_key(f.read())

    # check json
    try:
        nonces = get_nonces()
        j, n = BA.decrypt_json(encrypted_json, src_key, dst_key, seen_nonces=nonces)
        if j is None:
            print(f"ERROR: Document is invalid, reason: {n}")
            exit(1)

    except Exception as e:
        print(f"ERROR: Document is invalid, reason: {e}")
        exit(1)

    print(f"Document is valid, nonce: {nonces}")
    exit(0)
