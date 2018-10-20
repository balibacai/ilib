# generate private/public key pairs
```
yum -y install openssl

# generate private key
openssl genrsa -out rsaprivatekey.pem 1024

# generate public key
openssl rsa -in rsaprivatekey.pem -out rsapublickey.pem -pubout

```