import React from "react";
import PropTypes from "prop-types";

export default function Comment({
  commentid,
  lognameOwnsThis,
  owner,
  text,
  setComments,
}) {
  const handleDelete = (e) => {
    e.preventDefault();
    try {
      fetch(`/api/v1/comments/${commentid}`, {
        method: "DELETE",
        headers: {
          "Content-type": "application/json; charset=UTF-8",
          Accept: "application/json",
        },
      }).then((res) => {
        if (!res.ok) {
          throw new Error(`HTTP STATUS: ${res.status}`);
        }
        setComments((oldComments) =>
          oldComments.filter((comment) => comment.commentid !== commentid)
        );
      });
      // .then((data) => {
      //   // console.log(JSON.stringify(data));

      // });
    } catch (err) {
      console.log(err);
    }
  };

  return (
    <div>
      <a href={`/users/${owner}/`}>{owner}</a>
      <span className="comment-text">{text}</span>
      {lognameOwnsThis && (
        <button
          type="submit"
          className="delete-comment-button"
          onClick={handleDelete}
        >
          Delete comment
        </button>
      )}
    </div>
  );
}

Comment.propTypes = {
  commentid: PropTypes.number.isRequired,
  lognameOwnsThis: PropTypes.bool.isRequired,
  owner: PropTypes.string.isRequired,
  text: PropTypes.string.isRequired,
  setComments: PropTypes.func.isRequired,
};
