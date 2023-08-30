"""REST API for posts."""
import hashlib
import flask
import insta485


@insta485.app.route('/api/v1/', methods=['GET'])
def get_services():
    """Stupid docstring error."""
    context = {
        "comments": "/api/v1/comments/",
        "likes": "/api/v1/likes/",
        "posts": "/api/v1/posts/",
        "url": "/api/v1/"
    }
    return flask.jsonify(**context), 200


@insta485.app.route('/api/v1/posts/', methods=['GET'])
def get_newest_posts():
    """Stupid docstring error."""
    if is_logged():
        # Get most recent postid
        connection = insta485.model.get_db()
        cursor = connection.cursor()
        cursor.execute(
          "SELECT postid "
          "FROM posts "
          "ORDER BY postid DESC "
          "Limit 1"
        )
        recent_postid = cursor.fetchone()['postid']
        postid_lte = flask.request.args.get(
                                            "postid_lte",
                                            default=recent_postid,
                                            type=int)
        size = flask.request.args.get("size", default=10, type=int)
        page = flask.request.args.get("page", default=0, type=int)
        if size < 0:
            return flask.jsonify(
                {"message": "Bad Request", "status_code": 400}
                ), 400
        if page < 0:
            return flask.jsonify(
                {"message": "Bad Request", "status_code": 400}
                ), 400
        if postid_lte < 1:
            return flask.jsonify(
                {"message": "Bad Request", "status_code": 400}
                ), 400
        # Find all users actually followed
        logged_user = flask.session['username']
        cursor.execute(
            "SELECT * "
            "FROM posts "
            "WHERE postid <= ? "
            "AND (owner = ? "
            "OR owner IN "
            "(SELECT username2 from following where username1 = ? )) "
            "ORDER BY postid DESC "
            "LIMIT ? "
            "OFFSET ?",
            (postid_lte, logged_user, logged_user, size, page*size)
        )
        post_results = cursor.fetchall()
        post_list = []
        for row in post_results:
            post_info = {
                "postid": row['postid'],
                "url": "/api/v1/posts/" + str(row['postid']) + "/"
            }
            post_list.append(post_info)
        row_count = len(post_results)
        if row_count < size:
            next_page = ""
        else:
            page += 1
            next_page = "/api/v1/posts/?size=" + str(size)\
                + "&page=" + str(page) + "&postid_lte=" + str(postid_lte)
        if flask.request.query_string:
            j = f'{flask.request.path}?{flask.request.query_string.decode()}'
        else:
            j = flask.request.path
        final_json = {
            "next": next_page,
            "results": post_list,
            "url": j
        }
        return flask.jsonify(**final_json), 200
    return flask.jsonify({"message": "Forbidden", "status_code": 403}), 403


def is_logged():
    """Stupid docstring error."""
    if 'username' in flask.session:
        return True
    if 'username' not in flask.session\
            and flask.request.authorization is not None:
        http_username = flask.request.authorization['username']
        http_password = flask.request.authorization['password']
    if 'username' not in flask.session\
            and flask.request.authorization is None:
        return False
    # Retrieve password from db based on http auth
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT password "
        "FROM users "
        "WHERE username = ?",
        (http_username, )
    )
    result = cursor.fetchone()
    # Split result into alg, salt, hash
    split_list = result['password'].split('$', 2)
    algorithm = split_list[0]
    salt = split_list[1]
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + http_password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    # Check if either session or http auth works
    if password_hash == split_list[2]:
        flask.session['username'] = http_username
        return True
    return False


def get_new_comments(comments):
    """Stupid docstring error."""
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    new_comments = []
    for comment in comments:
        res = cursor.execute(
            "SELECT owner FROM comments WHERE commentid = ? ",
            (comment['commentid'], )
        )
        is_logged_user = False
        user = ''
        if 'username' in flask.session:
            user = flask.session['username']
        elif 'username' in flask.request.authorization:
            user = flask.request.authorization['username']
        if res.fetchone()['owner'] == user:
            is_logged_user = True
        comment_url = f"/api/v1/comments/{comment['commentid']}/"
        new_comments.append(
            {
                "commentid": comment['commentid'],
                "lognameOwnsThis": is_logged_user,
                "owner": comment['owner'],
                "ownerShowUrl": f"/users/{comment['owner']}/",
                "text": comment['text'],
                "url": comment_url
            }
        )
    return new_comments


def get_likes(postid):
    """Stupid docstring error."""
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    res = cursor.execute(
        "SELECT owner FROM likes WHERE postid = ? ",
        (postid, )
    )
    user = ''
    if 'username' in flask.session:
        user = flask.session['username']
    elif 'username' in flask.request.authorization:
        user = flask.request.authorization['username']
    log_name_likes_this = False
    for user_name in res.fetchall():
        if user_name['owner'] == user:
            log_name_likes_this = True
            break
    res = cursor.execute(
        "SELECT * FROM likes WHERE postid = ? ",
        (postid, )
    )
    num_likes = res.fetchall()
    like_url = None
    if log_name_likes_this:
        for like in num_likes:
            if like['owner'] == user:
                like_url = f"/api/v1/likes/{like['likeid']}/"
    likes_len = len(num_likes)
    likes = {
        "lognameLikesThis": log_name_likes_this,
        "numLikes": likes_len,
        "url": like_url
    }
    return likes


@insta485.app.route('/api/v1/posts/<int:postid>/', methods=['GET'])
def get_post(postid):
    """Stupid docstring error."""
    if not is_logged():
        return flask.jsonify({"message": "Forbidden", "status_code": 403}), 403
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    # Check if postid is even in range
    cursor.execute(
        "SELECT postid "
        "FROM posts "
        "ORDER BY postid DESC "
        "Limit 1"
    )
    if postid > cursor.fetchone()['postid'] or postid < 1:
        return flask.jsonify({"message": "Not Found", "status_code": 404}), 404
    res = cursor.execute(
        "SELECT * FROM comments WHERE postid = ? ",
        (postid, )
    )
    comments = res.fetchall()
    context = {}
    comments_url = f'/api/v1/comments/?postid={postid}'
    res = cursor.execute(
        "SELECT * FROM posts WHERE postid = ? ",
        (postid, )
        )
    post = res.fetchone()
    if not post:
        return flask.jsonify(
            {"message": "Not Found", "status_code": 404}
        ), 404
    created = post['created']
    owner = post['owner']
    post_img_url = f"/uploads/{post['filename']}"
    res = cursor.execute(
        "SELECT filename FROM users WHERE username = ? ",
        (owner, )
    )
    owner_img_url = f"/uploads/{res.fetchone()['filename']}"
    owner_show_url = f'/users/{owner}/'
    post_show_url = f'/posts/{postid}/'
    url = f'/api/v1/posts/{postid}/'
    context = {
        "comments": get_new_comments(comments),
        "comments_url": comments_url,
        "created": created,
        "imgUrl": post_img_url,
        "likes": get_likes(postid),
        "owner": owner,
        "ownerImgUrl": owner_img_url,
        "ownerShowUrl": owner_show_url,
        "postShowUrl": post_show_url,
        "postid": postid,
        "url": url
    }

    return flask.jsonify(**context)


@insta485.app.route('/api/v1/likes/', methods=['POST'])
def post_likes():
    """Stupid docstring error."""
    if not is_logged():
        return flask.jsonify({"message": "Forbidden", "status_code": 403}), 403
    postid = flask.request.args.get("postid", type=int)
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    user = ''
    if 'username' in flask.session:
        user = flask.session['username']
    elif 'username' in flask.request.authorization:
        user = flask.request.authorization['username']
    cursor.execute(
        "SELECT likeid "
        "FROM likes "
        "WHERE owner is ? AND postid = ?",
        (user, postid)
    )
    likeid_existance = cursor.fetchone()
    status_code = 200
    if not likeid_existance:
        cursor.execute(
            "INSERT INTO likes (owner, postid)"
            "VALUES (?, ?)",
            (user, postid)
        )
        status_code = 201
    likeid = cursor.execute(
        "SELECT likeid "
        "FROM likes "
        "WHERE owner is ? "
        "AND postid is ?",
        (user, postid)
    )
    likeid = likeid.fetchone()
    json_url = "/api/v1/likes/" + str(likeid["likeid"]) + "/"
    json_return = {
        "likeid": likeid["likeid"],
        "url": json_url
    }
    return flask.jsonify(**json_return), status_code


@insta485.app.route('/api/v1/comments/', methods=['POST'])
def post_comments():
    """Stupid docstring error."""
    if not is_logged():
        return flask.jsonify({"message": "Forbidden", "status_code": 403}), 403
    user = ''
    if 'username' in flask.session:
        user = flask.session['username']
    elif 'username' in flask.request.authorization:
        user = flask.request.authorization['username']
    post_id = flask.request.args.get("postid", type=int)
    text = flask.request.json.get("text", None)
    if text == '':
        return flask.jsonify({}), 400
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO comments(owner, postid, text) values(?, ?, ?)",
        (user, post_id, text)
    )
    res = cursor.execute(
        "SELECT last_insert_rowid() FROM comments"
    )
    commentid = res.fetchone()
    commentid = commentid['last_insert_rowid()']
    owner_show_url = f'/users/{user}/'
    url = f'/api/v1/comments/{commentid}/'
    log_name_owns_this = True
    context = {
        "commentid": commentid,
        "lognameOwnsThis": log_name_owns_this,
        "owner": user,
        "ownerShowUrl": owner_show_url,
        "text": text,
        "url": url
    }
    return flask.jsonify(**context), 201


@insta485.app.route('/api/v1/comments/<commentid>/', methods=['DELETE'])
def delete_comment(commentid):
    """Stupid docstring error."""
    if not is_logged():
        return flask.jsonify({"message": "Forbidden", "status_code": 403}), 403
    commentid = int(commentid)
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT *"
        "FROM comments "
        "WHERE commentid = ?",
        (commentid,)
    )
    results = cursor.fetchone()
    # Check if comment exists
    if results is None:
        return flask.jsonify({"message": "Not found", "status_code": 404}), 404
    # If comment exists, make sure user owns it
    if 'username' in flask.session:
        user = flask.session['username']
    elif 'username' in flask.request.authorization:
        user = flask.request.authorization['username']
    if results['owner'] != user:
        return flask.jsonify(
            {"message": "Forbidden", "status_code": 403}
        ), 403
    cursor.execute(
        "DELETE "
        "FROM comments "
        "WHERE commentid = ?",
        (commentid,)
    )
    return flask.jsonify({}), 204


@insta485.app.route('/api/v1/likes/<likeid>/', methods=['DELETE'])
def delete_like(likeid):
    """Stupid docstring error."""
    if not is_logged():
        return flask.jsonify({"message": "Forbidden", "status_code": 403}), 403
    likeid = int(likeid)
    connection = insta485.model.get_db()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT *"
        "FROM likes "
        "WHERE likeid = ?",
        (likeid,)
    )
    result = cursor.fetchone()
    if result is None:
        return flask.jsonify({"message": "Not found", "status_code": 404}), 404

    # Get username
    if 'username' in flask.session:
        user = flask.session['username']
    elif 'username' in flask.request.authorization:
        user = flask.request.authorization['username']
    # If user doesn't own likeid it errors
    if result['owner'] != user:
        return flask.jsonify(
            {"message": "Forbidden", "status_code": 403}
            ), 403
    cursor.execute(
        "DELETE "
        "FROM likes "
        "WHERE likeid = ?",
        (likeid,)
    )
    return flask.jsonify({}), 204
