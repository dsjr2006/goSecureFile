####goSecureFile

*Work in Progress

*I make no claims to cryptographic security or verification and must warn that usage is at your own risk.

CLI for encrypting and decrypting items, default method is the layered encryption scheme TripleSec by KeyBase.io
>TripleSec is a simple, triple-paranoid, symmetric encryption library for a whole bunch of languages. 
>It encrypts data with Salsa 20, AES, and Twofish, so that a someday compromise of one or two of the ciphers will not expose the secret.
>Of course, encryption is only part of the story. TripleSec also: derives keys with scrypt to defend against password-cracking and rainbow tables; 
>authenticates with HMAC to protect against adaptive chosen-ciphertext attacks
[https://keybase.io/triplesec/](https://keybase.io/triplesec/)