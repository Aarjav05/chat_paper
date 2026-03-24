from crypto_utils import *
import base64

def test_rsa():
    priv, pub = generate_rsa_key_pair()
    pem = public_key_to_pem(pub)
    pub2 = pem_to_public_key(pem)
    
    msg = "Hello, this is a test message. " * 10  # Long message (~310 chars)
    enc, orig_sz, enc_sz = encrypt_rsa(pub2, msg)
    dec = decrypt_rsa(priv, enc)
    
    assert dec == msg, "RSA decryption failed!"
    print(f"RSA Test Passed! Orig size: {orig_sz}, Enc size: {enc_sz}")

def test_aes():
    key = os.urandom(32)
    msg = "AES Test Message. " * 5
    enc, orig_sz, enc_sz = encrypt_aes(key, msg)
    dec = decrypt_aes(key, enc)
    
    assert dec == msg, "AES decryption failed!"
    print(f"AES Test Passed! Orig size: {orig_sz}, Enc size: {enc_sz}")
    
if __name__ == "__main__":
    test_rsa()
    test_aes()
