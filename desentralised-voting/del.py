from Cryptodome.PublicKey import RSA

key = RSA.generate(2048)
with open('mykey.pem','wb') as f:
    f.write(key.export_key('PEM'))
with open('mykey.pem','r') as f:
    key = RSA.import_key(f.read())
    print(key)
