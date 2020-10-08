import os, mysql.connector, secrets, hashlib
from flask import Flask, session, redirect, url_for, request, render_template
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY')
app.session_cookie_name = os.getenv('SESSION_NAME')

db = mysql.connector.connect(
    host = os.getenv('DB_HOST'),
    user = os.getenv('DB_USER'),
    password = os.getenv('DB_PASSWORD'),
    database = os.getenv('DB_DATABASE')
)

c = db.cursor()

@app.route('/')
def index():
    return render_template('base.html', sid='sid' in session)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        result = user_login(username, password)
        if result is None:
            return render_template('base.html',
                h='Wrong',
                m='Username or password is wrong.')
        session['sid'] = result[0]
        session['user_id'] = result[1]
        return redirect('edit')
    if 'sid' in session:
        return redirect('edit')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('sid', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/edit')
def edit():
    if 'sid' in session and 'user_id' in session:
        sql = 'SELECT username FROM users WHERE id={};'.format(session['user_id'])
        c.execute(sql)
        r = c.fetchone()
        return render_template('base.html', sid=True, h='Logged in as {}'.format(r[0]))
    return redirect('login')

@app.errorhandler(404)
def not_found(error):
    return render_template('base.html',
                h='404', m='Site not found.', sid='sid' in session), 404

@app.before_request
def remove_expired_sessions():
    sql = 'DELETE FROM sessions \
           WHERE expires_after < NOW();'
    c.execute(sql)
    db.commit()
    if 'sid' in session:
        sql = "SELECT session_id, user_id \
               FROM sessions WHERE session_id='{}';".format(session['sid'])
        c.execute(sql)
        data = c.fetchone()
        if data is None:
            session.pop('sid', None)
            session.pop('user_id', None)
            return
        session['sid'] = data[0]
        session['user_id'] = data[1]

@app.after_request
def update_sessions(response):
    if 'sid' in session:
        sql = "UPDATE sessions \
               SET expires_after = DATE_ADD(NOW(), INTERVAL 1 HOUR) \
               WHERE session_id='{}';".format(session['sid'])
        c.execute(sql)
        db.commit()
    return response

'''
Return authenticated session if username in database and given plain passwords hash is equal database saved one.
'''
def user_login(username, password):
    c.execute('SELECT id FROM users WHERE username=%(u)s;', { 'u': username })
    user_id = c.fetchone()
    if user_id is None:
        return None
    if auth(user_id[0], password):
        return create_authenticated_session(user_id[0])
    return None

'''
Compares given plain password with saved hash and return the result.
'''
def auth(user_id, password):
    c.execute('SELECT salt, hash \
               FROM users WHERE id=%(u)s;', { 'u': user_id })
    r = c.fetchone()
    if r is None:
        return False
    salt = r[0]
    hash_db = r[1]

    h = hashlib.sha512()
    h.update(str.encode(salt))
    h.update(str.encode(password))
    hash_user = h.hexdigest()
    return secrets.compare_digest(hash_db, hash_user)


'''
Creates authenticated session.
'''
def create_authenticated_session(user_id):
    sid = secrets.token_hex(32)
    sql = "INSERT INTO sessions (session_id, expires_after, user_id) \
           VALUES ('{}', DATE_ADD(NOW(), INTERVAL 1 HOUR), '{}');".format(sid, user_id)
    c.execute(sql)
    db.commit()
    return sid, user_id