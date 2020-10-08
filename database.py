import os, mysql.connector, sys, secrets, hashlib
from dotenv import load_dotenv
load_dotenv()

db = mysql.connector.connect(
    host = os.getenv('DB_HOST'),
    user = os.getenv('DB_USER'),
    password = os.getenv('DB_PASSWORD'),
    database = os.getenv('DB_DATABASE')
)

c = db.cursor()

user_sql = '''CREATE TABLE IF NOT EXISTS users (
    id SERIAL UNIQUE,
    username VARCHAR(254) NOT NULL UNIQUE DEFAULT '',
    salt VARCHAR(254) NOT NULL DEFAULT '',
    hash VARCHAR(254) NOT NULL DEFAULT '',
    PRIMARY KEY (id));
    '''

session_sql = '''CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL UNIQUE,
    session_id VARCHAR(254) NOT NULL UNIQUE DEFAULT '',
    expires_after TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER REFERENCES users(id),
    PRIMARY KEY (session_id));
    '''

c.execute(user_sql)
c.execute(session_sql)
db.commit()


'''
Save new user is username and password is given.
'''
if len(sys.argv) > 1:
    salt = secrets.token_hex(32)

    h = hashlib.sha512()
    h.update(str.encode(salt))
    h.update(str.encode(sys.argv[2]))
    user_hash = h.hexdigest()
    sql = "INSERT INTO users (username, salt, hash) \
        VALUES ('{}', '{}', '{}');".format(sys.argv[1], salt, user_hash)
    c.execute(sql)
    db.commit()