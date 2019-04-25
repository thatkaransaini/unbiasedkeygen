def xor_strings(s, t):
    return ''.join(chr(ord(a)^ord(b)) for a, b in zip(s, t))

def generate_AES_key(bytes):
    try:
        from Crypto import Random
        return Random.get_random_bytes(bytes)
    except ImportError:
        print('PyCrypto is not installed.')


def verify_cmt(digest, key):
    from Crypto.Hash import SHA256
    h = SHA256.new()
    h.update(key)
    if digest == h.hexdigest():
        return True
    return False


def gen_keys(key1,key2):
    import Crypto.Cipher.AES
    import Crypto.Util.Counter
    ctr = Crypto.Util.Counter.new(128)
    key = xor_strings(key1,key2)
    msg = key[len(key)/2:]
    for x in range(0,100):
        cipher = Crypto.Cipher.AES.new(key[:len(key1)/2], Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        key = cipher.encrypt(msg).encode('hex')
        print key

def send_Digest(digest,seed):
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host = "127.0.0.1"
        port = 10316
        s.bind((host,port))
        d = s.recvfrom(1024)
        print " Hash received from Party One"
        reply = digest
        party_one_hash = d[0]
        s.sendto(reply , d[1])
        print " Hash sent to Party One"
        d = s.recvfrom(1024)
        party_one_key = d[0]
        reply = seed
        print " Seed sent to Party One"
        s.sendto(reply, d[1])
        print " Verifing Commitment"
        if verify_cmt(party_one_hash,party_one_key):
                print " Commitment Verified"
                print " Generating 100 keys"
                gen_keys(seed,party_one_key)
        else:
            print " Malicious Intent by Party One"
    except ImportError:
        print "Importing Failed"

if __name__== "__main__":
    x = generate_AES_key(32)
    try:
        from Crypto.Hash import SHA256
        h = SHA256.new()
        h.update(x)
        send_Digest(h.hexdigest(),x)
    except ImportError:
        print "PyCrypto is not installed"