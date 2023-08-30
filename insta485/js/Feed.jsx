import React, { useState, useEffect } from "react";
import PropTypes from "prop-types";
import InfiniteScroll from "react-infinite-scroll-component";
import Post from "./Post";

// The parameter of this function is an object with a string called url inside it.
// url is a prop for the Post component.
export default function Feed({ url }) {
  /* Display image and post owner of a single post */

  const [posts, setPosts] = useState([]);
  const [nextPage, setNextPage] = useState("");
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
        const newPosts = data.results;
        if (!ignoreStaleRequest) {
          setPosts((prevPosts) => [...prevPosts, ...newPosts]);
          setNextPage(data.next);
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
  const getMorePosts = () => {
    fetch(`${nextPage}`, { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw Error(response.statusText);
        return response.json();
      })
      .then((data) => {
        const newPosts = data.results;
        setPosts([...posts, ...newPosts]);
        setNextPage(data.next);
      })
      .catch((error) => console.log(error));
  };

  return (
    <div style={{ height: 1000 }}>
      <InfiniteScroll
        dataLength={posts.length}
        next={getMorePosts}
        hasMore
        loader={<h3>Loading</h3>}
      >
        <div>
          {posts.map((p) => (
            <Post url={p.url} id={p.postid} key={p.postid} />
          ))}
        </div>
      </InfiniteScroll>
    </div>
  );
}

Feed.propTypes = {
  url: PropTypes.string.isRequired,
};
