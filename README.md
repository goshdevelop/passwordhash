# passwordhash
The package provides simple functions to generate and check password hash. Passwordhash implements algorithm of hashing like werkzeug.security with sha256 and salt. The package may be useful if you have a user base with hashes that were made by werkzeug.security generate_password_hash function and you need to use these hashes by golang application.
