"""Insta485 index (main) view."""

import uuid
import hashlib
import pathlib
import os
import arrow
import flask
import insta485


def query_db(query, args=(), one=False):
    """Stupid docstring error."""
    cur = insta485.model.get_db().execute(query, args)
    row_value = cur.fetchall()
    cur.close()
    return (row_value[0] if row_value else None) if one else row_value


@insta485.app.route('/uploads/<path:name>')
def get_image(name):
    """Stupid docstring error."""
    if 'username' not in flask.session:
        flask.abort(403, "user not logged in accessing files")
    return flask.send_from_directory(
        insta485.app.config['UPLOAD_FOLDER'], name)


@insta485.app.route('/', methods=['GET'])
def show_index():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    flw = query_db("select username2 from following" +
                   " where username1 = ?", (flask.session.get('username'),))
    q_string_p = "select * from posts where owner = ?"\
                 " or owner in (select username2 "
    q_string_p += "from following where username1 = ?)"\
                  " order by postid DESC"
    pst = query_db(
        q_string_p,
        (flask.session.get('username'), flask.session.get('username')))
    comments = {}
    likes = {}
    users = {}
    time_stamp = {}
    has_liked = {}
    for post in pst:
        postid = post['postid']
        comments[postid] = query_db(
            'select * from comments where postid = ?', (postid,))
        likes[postid] = len(
            query_db('select * from likes where postid = ?', (postid,)))
        users[postid] = query_db(
            'select * from users where username = ?', (post['owner'],))
        temp = arrow.get(post['created'])
        time_stamp[postid] = temp.humanize()
    posts_liked_list = query_db(
        "select postid from likes where owner = ?",
        (flask.session.get('username'),))
    for i in posts_liked_list:
        for j in i.values():
            has_liked[j] = True
    context = {
        "username": flask.session.get('username'),
        "users": users,
        "following": flw,
        "posts": pst,
        "comments": comments,
        "likes": likes,
        "time_stamp": time_stamp,
        "has_liked": has_liked
    }
    return flask.render_template('index.html', **context)


@insta485.app.route('/comments/', methods=['POST'])
def comment_operation():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    connection = insta485.model.get_db()
    cur = connection.cursor()
    operation = flask.request.form['operation']
    username = flask.session['username']
    form_target = flask.request.args.get('target')
    if not form_target:
        form_target = '/'
    if operation == 'create':
        postid = flask.request.form['postid']
        text = flask.request.form['text']
        if text == '':
            return flask.abort(400, 'empty comment')
        cur.execute(
            "INSERT INTO comments(owner, postid, text) values(?, ?, ?)",
            (username, postid, text))
    elif operation == 'delete':
        commentid = flask.request.form['commentid']
        res = cur.execute(
            'SELECT owner FROM comments WHERE commentid = ? AND owner = ? ',
            (commentid, username))
        if not res.fetchone():
            return flask.abort(403, 'you cant delete a comment you dont own')
        cur.execute("DELETE FROM comments WHERE commentid=? ",
                    (commentid, ))
    return flask.redirect(form_target)


@insta485.app.route('/likes/', methods=['POST'])
def like_change():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    form_target = flask.request.args.get('target')
    if not form_target:
        form_target = '/'
    username = flask.session['username']
    postid = flask.request.form['postid']
    connection = insta485.model.get_db()
    cur = connection.cursor()
    operation = flask.request.form['operation']
    if operation == 'like':
        res = cur.execute(
            "SELECT * FROM likes WHERE owner = ? AND postid = ? ",
            (username, postid))
        if res.fetchone():
            return flask.abort(409, 'Cant like a post youve already liked')
        print(username, postid)
        cur.execute("INSERT INTO likes(owner, postid) values(?, ?)",
                    (username, postid))
    elif operation == 'unlike':
        res = cur.execute(
            "SELECT * FROM likes WHERE owner = ? AND postid = ? ",
            (username, postid))
        if not res.fetchone():
            return flask.abort(409, 'Cant unlike a post you havent liked')
        cur.execute("DELETE FROM likes WHERE owner=? and postid=?",
                    (username, postid))
    return flask.redirect(form_target)


@insta485.app.route('/accounts/login/', methods=['GET'])
def login_prompt():
    """Stupid docstring error."""
    if 'username' in flask.session:
        return flask.redirect(flask.url_for('show_index'))
    return '''
    <a href="/">INSTA485</a>
    <form action="/accounts/?target=/" method="post"
    enctype="multipart/form-data">
    <input type="text" name="username" required/>
    <input type="password" name="password" required/>
    <input type="submit" value="login"/>
    <input type="hidden" name="operation" value="login"/>
    </form>
    <p>Don't have an account? <a href="/accounts/create/">Sign up</a></p>
    '''


def accounts_login():
    """Stupid docstring error."""
    username = flask.request.form['username']
    pword = flask.request.form['password']
    connection = insta485.model.get_db()
    if not username or not pword:
        flask.abort(400, "Empty field")
        # Get string from db w sha512, salt, hash
    cursor = connection.cursor()
    cursor.execute(
        "SELECT password "
        "FROM users "
        "WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    # Return error if username is not present
    if result is None:
        flask.abort(403, "username not present")
    # Split full string into algorithm (0), salt(1), hash(2)
    split_list = result['password'].split('$', 2)
    # Spec code for hashing input
    algorithm = split_list[0]
    salt = split_list[1]
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + pword
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    # Check if password from db = input
    print(result['password'])
    if result['password'] != password_db_string:
        flask.abort(403, "wrong password")
    else:
        flask.session['username'] = username


def accounts_create():
    """Stupid docstring error."""
    fileobj = flask.request.files['file']
    # filen = fileobj.filename
    # usern = flask.request.form['username']
    # fulln = flask.request.form['fullname']
    # email = flask.request.form['email']
    pword = flask.request.form['password']
    if not fileobj.filename or not flask.request.form['username']:
        flask.abort(400)
    if not flask.request.form['fullname']:
        flask.abort(400)
    if not flask.request.form['email'] or not pword:
        flask.abort(400)
    connection = insta485.model.get_db()
    cur = connection.cursor()
    # Return error if user already existed
    cur.execute(
        "SELECT * "
        "FROM users "
        "WHERE username = ?",
        (flask.request.form['username'], )
    )
    result = cur.fetchone()
    if result:
        flask.abort(409)
        # Hash password and insert
    algorithm = 'sha512'
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + pword
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    # Compute uuid
    stem = uuid.uuid4().hex
    suffix = pathlib.Path(fileobj.filename).suffix.lower()
    uuid_basename = f"{stem}{suffix}"
    # Save to disk
    path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
    fileobj.save(path)
    connection.execute(
        "INSERT INTO users(username, fullname, email, filename, password)"
        " values (?, ?, ?, ?, ?)",
        (flask.request.form['username'], flask.request.form['fullname'],
            flask.request.form['email'], uuid_basename, password_db_string)
        )
    flask.session['username'] = flask.request.form['username']


def accounts_delete():
    """Stupid docstring error."""
    connection = insta485.model.get_db()
    if 'username' not in flask.session:
        flask.abort(403, "User trying to delete without being logged in")
    # Retrieve username for query
    username = flask.session['username']
    # Get old filepath and delete file
    cur_find = connection.cursor()
    cur_find.execute(
        "SELECT filename "
        "FROM users "
        "WHERE username = ?",
        (username,)
    )
    delete_this = cur_find.fetchone()['filename']
    old_path = insta485.app.config["UPLOAD_FOLDER"]/delete_this
    # this deletes its profile image
    os.remove(old_path)
    # must delete all images associated with user
    res = cur_find.execute(
        "SELECT filename FROM posts WHERE owner = ? ",
        (username, )
    )
    for file in res.fetchall():
        old_path = insta485.app.config["UPLOAD_FOLDER"]/file['filename']
        os.remove(old_path)
        # Once file is deleted, delete user from table
    cur = connection.cursor()
    cur.execute(
        "DELETE FROM users "
        "WHERE username = ?",
        (username,)
    )
    flask.session.pop('username', None)


def account_edit():
    """Stupid docstring error."""
    connection = insta485.model.get_db()
    if 'username' not in flask.session:
        flask.abort(403, "User trying to edit without being logged in")
    username = flask.session['username']
    fullname = flask.request.form['fullname']
    email = flask.request.form['email']
    photo_file = flask.request.files['file']
    if not fullname or not email:
        flask.abort(400, "fullname or email missing")
        # Branch based on if file is present
    if not photo_file:
        cur = connection.cursor()
        cur.execute(
            "UPDATE users "
            "SET "
            "fullname = ?, "
            "email = ?"
            "WHERE username = ?",
            (fullname, email, username)
        )
    else:
        # Get old filepath and delete file
        cur_find = connection.cursor()
        cur_find.execute(
            "SELECT filename "
            "FROM users "
            "WHERE username = ?",
            (username,)
        )
        delete_this = cur_find.fetchone()['filename']
        old_path = insta485.app.config["UPLOAD_FOLDER"]/delete_this
        os.remove(old_path)
        # Get new uuid
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(photo_file.filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"
        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        photo_file.save(path)
        # Update user
        cur = connection.cursor()
        cur.execute(
            "UPDATE users "
            "SET "
            "fullname = ?, "
            "email = ?, "
            "filename = ?"
            "WHERE username = ?",
            (fullname, email, uuid_basename, username)
        )


@insta485.app.route('/accounts/', methods=['POST'])
def login_check():
    """Stupid docstring error."""
    # Get target to redirect to
    form_target = flask.request.args.get('target')
    if not form_target:
        form_target = '/'
    # Connect to database
    connection = insta485.model.get_db()
    # Branch based on operation type
    if flask.request.form['operation'] == 'login':
        accounts_login()
    elif flask.request.form['operation'] == 'create':
        accounts_create()
    elif flask.request.form['operation'] == 'delete':
        accounts_delete()
    elif flask.request.form['operation'] == 'edit_account':
        account_edit()
    elif flask.request.form['operation'] == 'update_password':
        if 'username' not in flask.session:
            flask.abort(403, "User updating password without logging in")
        else:
            username = flask.session['username']
            pword = flask.request.form['password']
            new_password1 = flask.request.form['new_password1']
            new_password2 = flask.request.form['new_password2']
            if not pword or not new_password1 or not new_password2:
                flask.abort(400, 'empty passwords fields')
            cursor = connection.cursor()
            cursor.execute(
                "SELECT password "
                "FROM users "
                "WHERE username = ?",
                (username, )
            )
            result = cursor.fetchone()
            split_list = result['password'].split('$', 2)
            # Spec code for hashing input
            algorithm = split_list[0]
            salt = split_list[1]
            hash_obj = hashlib.new(algorithm)
            password_salted = salt + pword
            hash_obj.update(password_salted.encode('utf-8'))
            password_hash = hash_obj.hexdigest()
            password_db_string = "$".join([algorithm, salt, password_hash])
            # Check if password from db = input
            if result['password'] != password_db_string:
                flask.abort(403, "wrong password")
            if new_password1 != new_password2:
                flask.abort(401, "passwords don't match when updating")
            algorithm = 'sha512'
            salt = uuid.uuid4().hex
            hash_obj = hashlib.new(algorithm)
            password_salted = salt + new_password1
            hash_obj.update(password_salted.encode('utf-8'))
            password_hash = hash_obj.hexdigest()
            password_db_string = "$".join([algorithm, salt, password_hash])
            cursor.execute(
                "UPDATE users SET password = ? WHERE username = ? ",
                (password_db_string, username)
            )
    return flask.redirect(form_target)


@insta485.app.route('/accounts/logout/', methods=['POST'])
def log_out():
    """Stupid docstring error."""
    if 'username' in flask.session:
        flask.session.clear()
        return flask.redirect(flask.url_for('login_prompt'))
    return flask.redirect(flask.url_for('login_prompt'))


@insta485.app.route('/accounts/create/', methods=['GET'])
def register():
    """Stupid docstring error."""
    if 'username' in flask.session:
        return flask.redirect(flask.url_for('edit'))
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>insta485</title>
    </head>
    <body>
        <a href="/">INSTA485</a>
        <form action="/accounts/?target=/"
        method="post" enctype="multipart/form-data">
        <input type="file" name="file" required/>
        <input type="text" name="fullname"
        placeholder="full name" required/>
        <input type="text" name="username"
        placeholder="user name" required/>
        <input type="text" name="email"
        placeholder="email" required/>
        <input type="password" name="password"
        placeholder="password" required/>
        <input type="submit" name="signup" value="sign up"/>
        <input type="hidden" name="operation" value="create"/>
        </form><a href="/accounts/login/">Login</a>
    </body>
    """


@insta485.app.route('/accounts/edit/', methods=['GET'])
def edit():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        flask.abort(403, "user not logged in")
    username = flask.session['username']
    # Connect to database, query user
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT * "
        "FROM users "
        "WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    img = flask.url_for('get_image', name=result['filename'])
    return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>insta485</title>
        </head>
        <body>
            <a href="/">INSTA485</a>
            <br>
            <a href="/explore/">explore | </a>
            <a href="/users/''' + flask.session['username'] + '''/">\
            ''' + flask.session['username'] + '''
            </a>
            <br> <br>
            <img src="''' + img + ''' " alt="">
            <p>''' + result['fullname'] + '''</p>
            <form action="/accounts/?target=/accounts/edit"
            method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept="image/*"/>
            <input type="text" name="fullname"
            value=" ''' + result['fullname'] + '''" required/>
            <input type="text" name="email"
            value="''' + result['email'] + '''" required/>
            <input type="submit" name="update" value="submit"/>
            <input type="hidden" name="operation" value="edit_account"/>
            </form>
            <a href="/accounts/password/"><p>Change password</p></a>
            <a href="/accounts/delete/"><p>Delete account</p></a>
        </body>
        '''


@insta485.app.route('/accounts/password/', methods=['GET'])
def password():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.abort(403, "Accessing password without logging in")
    username = flask.session['username']
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>insta485</title>
    </head>
    <body>
        <a href="/">INSTA485</a>
        <a href="/explore/">explore | </a>
        <a href="/users/''' + username + '''/">\
        ''' + username + '''
        </a>
        <form action="/accounts/" method="post"
        enctype="multipart/form-data">
        <input type="password" name="password"
        placeholder="Old Password" required/>
        <input type="password" name="new_password1"
        placeholder="New Password" required/>
        <input type="password" name="new_password2"
        placeholder="New Password, again" required/>
        <input type="submit" name="update_password" value="submit"/>
        <input type="hidden" name="operation" value="update_password"/>
        </form>
        <a href="/accounts/edit/">Back to edit account</a>
    </body>
    '''


@insta485.app.route('/accounts/delete/', methods=['GET'])
def delete_user():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.abort(403, "You can't delete an account if you aren't \
                           logged in")
    return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>insta485</title>
        </head>
        <body>
            <a href="/">INSTA485</a>
            <a href="/explore/">explore | </a>
            <a href="/users/''' + flask.session['username'] + '''/">\
            ''' + flask.session['username'] + '''
            </a>
            <p>''' + flask.session['username'] + '''</p>
            <form action="/accounts/?target=/accounts/create/"
            method="post" enctype="multipart/form-data">
            <input type="submit" name="delete" value="confirm delete account"/>
            <input type="hidden" name="operation" value="delete"/>
            </form>
        </body>
    '''


@insta485.app.route('/users/<user_url_slug>/', methods=['GET'])
def get_user(user_url_slug):
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    user = query_db('select * from users where username = ?', (user_url_slug,))
    user = user[0]
    logged_user = ''
    is_logged = True
    logged_user = flask.session['username']
    logged_is_user = False
    if user_url_slug == logged_user:
        logged_is_user = True
    res = cursor.execute(
        "SELECT * FROM users WHERE username = ? ",
        (user_url_slug,)
    )
    if not res.fetchone():
        flask.abort(404, 'user does not exist')
    res = cursor.execute(
        "SELECT fullname FROM users WHERE username = ?",
        (user_url_slug,)
    )
    full_name = res.fetchone()['fullname']
    res = cursor.execute(
        "SELECT * FROM following WHERE username1 = ?",
        (user_url_slug,)
    )
    following = len(res.fetchall())
    res = cursor.execute(
        "SELECT * FROM following WHERE username2 = ?",
        (user_url_slug,)
    )
    followers = len(res.fetchall())
    res = cursor.execute(
        "SELECT * FROM posts WHERE owner = ?",
        (user_url_slug,)
    )
    posts = res.fetchall()
    total_posts = len(posts)
    res = cursor.execute(
        "SELECT * FROM following WHERE username1 = ? AND username2 = ? ",
        (logged_user, user_url_slug)
    )
    following_user = len(res.fetchall())
    context = {
        "username": user_url_slug,
        "user": user,
        "fullname": full_name,
        "following": following,
        "followers": followers,
        "total_posts": total_posts,
        "posts": posts,
        "logged_in": is_logged,
        "logged_is_user": logged_is_user,
        "following_user": following_user,
        "logname": logged_user,
    }
    return flask.render_template('user.html', **context)


@insta485.app.route('/explore/', methods=['GET'])
def explore():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    logged_user = flask.session['username']
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    res = cursor.execute(
        "SELECT * FROM users WHERE username NOT IN (SELECT"
        " username2 FROM following WHERE username1 = ?) AND username != ?",
        (logged_user, logged_user)
    )
    not_following = res.fetchall()
    context = {
        'not_following': not_following,
        'get_image': get_image,
        'path': (insta485.app.config['UPLOAD_FOLDER']),
        'url_for': flask.url_for,
        'logname': logged_user
    }
    return flask.render_template('explore.html', **context)


@insta485.app.route('/posts/<postid_url_slug>/', methods=['GET'])
def get_posts(postid_url_slug):
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    liked = False
    res = cursor.execute(
        "SELECT * FROM likes WHERE postid = ? AND owner = ? ",
        (postid_url_slug, flask.session['username'])
    )
    if res.fetchone():
        liked = True
    res = cursor.execute(
        "SELECT * FROM posts WHERE postid = ? ",
        (postid_url_slug, )
    )
    post = res.fetchone()
    if not post:
        return flask.abort(404, 'post id doesnt exist')
    owner = post['owner']
    filename = post['filename']
    created = post['created']

    res = cursor.execute(
        "SELECT * FROM comments WHERE postid = ? ",
        (postid_url_slug, )
    )
    comments = res.fetchall()
    if not comments:
        comments = []
    res = cursor.execute(
        "SELECT filename FROM users WHERE username = ? ",
        (owner, )
    )

    img_url = res.fetchone()['filename']
    res = cursor.execute(
        "SELECT * FROM likes WHERE postid = ? ",
        (postid_url_slug, )
    )
    likes = res.fetchall()
    if not likes:
        likes = 0
    else:
        likes = len(likes)
    is_logged_user = False
    if flask.session['username'] == owner:
        is_logged_user = True
    temp = arrow.get(created)
    context = {
        'logname': flask.session['username'],
        'owner': owner,
        'filename': filename,
        'comments': comments,
        'img_url': img_url,
        'likes': likes,
        'timeago': temp.humanize(),
        'postid': postid_url_slug,
        'logged': is_logged_user,
        'liked': liked
    }
    return flask.render_template('post.html', **context)


@insta485.app.route('/posts/', methods=['POST'])
def post_check():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    user = flask.session['username']
    form_target = flask.request.args.get('target')
    if not form_target:
        form_target = "/users/" + user + "/"
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    operation = flask.request.form['operation']
    if operation == 'create':
        fileobj = flask.request.files['file']
        filename = fileobj.filename
        if not fileobj or not filename:
            return flask.abort(400, 'no file uploaded')
        # Compute uuid
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"
        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        fileobj.save(path)
        # Insert into db
        cursor.execute(
            "INSERT INTO posts(filename, owner) values(?, ?)",
            (uuid_basename, user))
    if operation == 'delete':
        postid = flask.request.form['postid']
        res = cursor.execute(
            "SELECT filename FROM posts WHERE postid = ? ",
            (postid, )
        )
        post_to_delete = res.fetchone()['filename']
        res = cursor.execute(
            "SELECT owner FROM posts WHERE filename = ? ",
            (post_to_delete, )
        )
        if user != res.fetchone()['owner']:
            return flask.abort(403, 'cannot delete post, not owner')
        old_path = insta485.app.config["UPLOAD_FOLDER"]/post_to_delete
        os.remove(old_path)
        cursor.execute(
            "DELETE FROM posts WHERE postid = ? ",
            (postid, )
        )
    return flask.redirect(form_target)


@insta485.app.route('/users/<user_url_slug>/followers/', methods=['GET'])
def get_followers(user_url_slug):
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    user = user_url_slug
    logged_user = flask.session['username']
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    res = cursor.execute(
        "SELECT * FROM users WHERE username = ? ",
        (user, )
    )
    if not res.fetchone():
        return flask.abort(404, 'user does not exist in database')
    res = cursor.execute(
        "SELECT * FROM users WHERE username IN "
        "(SELECT username1 FROM following WHERE username2 = ? )",
        (user, )
    )
    followers = res.fetchall()
    res = cursor.execute(
        "SELECT username2 FROM following WHERE username1 = ? ",
        (logged_user, )
    )
    for person in res.fetchall():
        for per in followers:
            if person['username2'] == per['username']:
                per['logged_follower'] = True
    context = {
        'followers': followers,
        'logname': logged_user
    }
    return flask.render_template('followers.html', **context)


@insta485.app.route('/users/<user_url_slug>/following/', methods=['GET'])
def get_following(user_url_slug):
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    user = user_url_slug
    logged_user = flask.session['username']
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    res = cursor.execute(
        "SELECT * FROM users WHERE username = ? ",
        (user, )
    )
    if not res.fetchone():
        return flask.abort(404, 'user does not exist in database')
    res = cursor.execute(
        "SELECT * FROM users WHERE username IN "
        "(SELECT username2 FROM following WHERE username1 = ? )",
        (user, )
    )
    followers = res.fetchall()
    res = cursor.execute(
        "SELECT username2 FROM following WHERE username1 = ? ",
        (logged_user, )
    )
    for person in res.fetchall():
        for per in followers:
            if person['username2'] == per['username']:
                per['logged_follower'] = True
    context = {
        'followers': followers,
        'logname': logged_user
    }
    return flask.render_template('following.html', **context)


@insta485.app.route('/following/', methods=['POST'])
def following_request():
    """Stupid docstring error."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('login_prompt'))
    logged_user = flask.session['username']
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    operation = flask.request.form['operation']
    username = flask.request.form['username']
    form_target = flask.request.args.get('target')
    if not form_target:
        form_target = '/'
    if operation == 'follow':
        # make user logname follow user username
        res = cursor.execute(
            "SELECT * FROM following WHERE username1 = ? AND username2 = ? ",
            (logged_user, username)
        )
        if res.fetchone():
            flask.abort(409, 'cannot follow a user you already follow')
        cursor.execute(
            "INSERT INTO following(username1, username2) values(?, ?)",
            (logged_user, username))
    elif operation == 'unfollow':
        # make user logname unfollows user username
        res = cursor.execute(
            "SELECT * FROM following WHERE username1 = ? AND username2 = ? ",
            (logged_user, username)
        )
        if not res.fetchone():
            flask.abort(409, 'cannot follow a user you already follow')
        cursor.execute(
            "DELETE FROM following WHERE username1 = ? AND username2 = ? ",
            (logged_user, username))
    return flask.redirect(form_target)
