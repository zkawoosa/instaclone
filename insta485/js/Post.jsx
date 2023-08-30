import React, { useState, useEffect } from "react";
import PropTypes from "prop-types";
import moment from "moment";
import Comment from "./Comment";
// The parameter of this function is an object with a string called url inside it.
// url is a prop for the Post component.

export default function Post({ url, id }) {
  /* Display image and post owner of a single post */
  const [imgUrl, setImgUrl] = useState("");
  const [owner, setOwner] = useState("");
  const [ownerImgUrl, setOwnerImgUrl] = useState("");
  const [comments, setComments] = useState([]);
  const [created, setCreated] = useState("");
  const [likes, setLikes] = useState({});
  const [postShowUrl, setPostShowUrl] = useState("");
  const [newComment, setNewComment] = useState("");
  const [liked, setLiked] = useState(false);
  const [fetched, setFetched] = useState(false);
  useEffect(() => {
    // Declare a boolean flag that we can use to cancel the API request.
    let ignoreStaleRequest = false;

    // Call REST API to get the post's information
    fetch(url, { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw Error(response.statusText);
        return response.json();
      })
      .then((data) => {
        // If ignoreStaleRequest was set to true, we want to ignore the results of the
        // the request. Otherwise, update the state to trigger a new render.
        if (!ignoreStaleRequest) {
          setImgUrl(data.imgUrl);
          setOwner(data.owner);
          setComments((prevComments) => [...prevComments, ...data.comments]);
          setCreated(data.created);
          setOwnerImgUrl(data.ownerImgUrl);
          setPostShowUrl(data.postShowUrl);
          setLikes({ ...data.likes });
          if (data.likes.lognameLikesThis) {
            setLiked(true);
          } else {
            setLiked(false);
          }
          // setNumLikes(data.likes.numLikes);
          setFetched(true);
        }
      })
      .catch((error) => console.log(error));
    return () => {
      // This is a cleanup function that runs whenever the Post component
      // unmounts or re-renders. If a Post is about to unmount or re-render, we
      // should avoid updating state.
      ignoreStaleRequest = true;
    };
  }, [url]);

  function handleComment(e) {
    e.preventDefault();
    try {
      fetch(`/api/v1/comments/?postid=${id}`, {
        method: "POST",
        body: JSON.stringify({
          text: newComment,
        }),
        headers: {
          "Content-type": "application/json; charset=UTF-8",
          Accept: "application/json",
        },
      })
        .then((res) => {
          if (!res.ok) {
            throw new Error(`HTTP STATUS: ${res.status}`);
          }
          return res.json();
        })
        .then((data) => {
          setComments([...comments, data]);
          setNewComment("");
        });
    } catch (err) {
      console.log(err);
    }
  }

  function handleLike(e) {
    e.preventDefault();
    console.log(likes);
    console.log(liked, "LIKE OR NOT LIKED");
    if (!liked) {
      try {
        fetch(`/api/v1/likes/?postid=${id}`, {
          method: "POST",
          headers: {
            "Content-type": "application/json; charset=UTF-8",
            Accept: "application/json",
          },
        })
          .then((res) => {
            if (!res.ok) {
              throw new Error(`HTTP STATUS: ${res.status}`);
            }
            // if (res.status === 200) {
            //   setLiked(true);
            //   throw new Error("Like already exists" + res.status);
            // }
            return res.json();
          })
          .then((data) => {
            setLikes({
              ...likes,
              numLikes: likes.numLikes + 1,
              url: data.url,
              lognameLikesThis: true,
            });
          });

        setLiked(!liked);
      } catch (err) {
        console.log(err);
      }
    } else {
      console.log("UNLIKING. URL:", likes.url);
      try {
        fetch(`${likes.url}`, {
          method: "DELETE",
          headers: {
            "Content-type": "application/json; charset=UTF-8",
            Accept: "application/json",
          },
        }).then((res) => {
          if (!res.ok) {
            throw new Error(`HTTP STATUS: ${res.status}`);
          }
          setLikes({
            ...likes,
            numLikes: likes.numLikes - 1,
            lognameLikesThis: false,
          });
        });
        setLiked(!liked);
      } catch (err) {
        console.log(err);
      }
    }
  }

  function imageLikeHandler() {
    if (!liked) {
      try {
        fetch(`/api/v1/likes/?postid=${id}`, {
          method: "POST",
          headers: {
            "Content-type": "application/json; charset=UTF-8",
            Accept: "application/json",
          },
        })
          .then((res) => {
            if (!res.ok) {
              throw new Error(`HTTP STATUS: ${res.status}`);
            }
            // if (res.status === 200) {
            //   setLiked(true);
            //   throw new Error("Like already exists" + res.status);
            // }
            return res.json();
          })
          .then((data) => {
            console.log(data);
            setLikes({
              ...likes,
              numLikes: likes.numLikes + 1,
              url: data.url,
              lognameLikesThis: true,
            });
            setLiked(!liked);
          });
      } catch (err) {
        console.log(err);
      }
    }
  }

  return (
    <div>
      {fetched && (
        <div className="post">
          <a href={`/users/${owner}/`}>
            <img src={`${ownerImgUrl}`} alt="user_photo" />
          </a>
          <a href={`/users/${owner}/`}>{owner}</a>
          <a href={`${postShowUrl}`}>{moment(created).fromNow()}</a>
          <img
            src={`${imgUrl}`}
            alt="post_img"
            onDoubleClick={imageLikeHandler}
          />
          {likes.numLikes === 1 ? <p>1 like</p> : <p>{likes.numLikes} likes</p>}
          <div>
            {comments.map((c) => (
              <Comment
                key={c.commentid}
                commentid={c.commentid}
                lognameOwnsThis={c.lognameOwnsThis}
                owner={c.owner}
                text={c.text}
                setComments={setComments}
              />
            ))}

            <form
              className="comment-form"
              // action="/comments/?target=/posts/{id}/"
              // method="post"
              // enctype="multipart/form-data"
              onSubmit={handleComment}
            >
              <input type="hidden" name="operation" value="create" />
              <input type="hidden" name="postid" value={id} />
              <input
                type="text"
                name="text"
                placeholder="Comment"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
              />
            </form>
            <button
              type="submit"
              className="like-unlike-button"
              onClick={handleLike}
            >
              {liked ? "Unlike" : "Like"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

Post.propTypes = {
  url: PropTypes.string.isRequired,
  id: PropTypes.number.isRequired,
};
