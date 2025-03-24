# JWKS-Project-2

This project uses SQLiteLinks to an external site., a single-file database, to enhance your JWKS server. SQLite is not a database server, but a serverless database that relies on drivers/libraries in your program to create, read, update, and delete database rows. To utilize SQLite, you'll be modifying your previous project to:

Create/open a SQLite DB file at start. Write your private keys to that file. Modify the POST:/auth and GET:/.well-known/jwks.json endpoints to use the database. By integrating SQLite and emphasizing secure database interactions, this project not only enhances our server's functionality but crucially focuses on preventing malicious SQL query manipulation, ensuring our authentication processes remain resilient and trustworthy.
