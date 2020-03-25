// A tiny node server to aid manual testing of presentEndSessionRequest.
// Start like
//
// > node endSessionServer.js 3000
//
// Then you can send your end session request as a GET to
//
// http://localhost:3000?state=your-state-here&post_logout_redirect_uri=http%3A%2F%2Fexample.com
//
// Or use "http://localhost:3000" as your configuration.endSessionEndpoint in your
// cordova.plugins.oidc.basic.presentEndSessionRequest call.

/* globals process */

const http = require("http");
const { URL, URLSearchParams } = require("url");

const QUERY_KEY_STATE = "state";
const QUERY_KEY_POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";

const port = process.argv[2] ? Math.parseInt(process.argv[2], 10) : 3000;

const server = http.createServer((req, res) => {
    try {
        if (req.method === "GET") {
            const url = new URL(req.url, "http://dummy");
            if (url.pathname === "/") {
                const
                    state = url.searchParams.get(QUERY_KEY_STATE),
                    postLogoutRedirectUri = url.searchParams.get(QUERY_KEY_POST_LOGOUT_REDIRECT_URI);

                if (postLogoutRedirectUri) {
                    const queryOut = new URLSearchParams();
                    if (state) queryOut.set(QUERY_KEY_STATE, state);
                    const redirectUrl = new URL(postLogoutRedirectUri);
                    redirectUrl.search = queryOut.toString();
                    res.writeHead(302, { "Location": redirectUrl.toString() });
                    res.end();
                } else {
                    res.writeHead(200, { "Content-Type": "text/plain" });
                    res.end(`To do something useful, include the ${QUERY_KEY_POST_LOGOUT_REDIRECT_URI} query key in your end session request, e.g. http://localhost:${port}?post_logout_redirect_uri=http%3A%2F%2Fexample.com&state=my_state`);
                }
            } else {
                res.writeHead(404, { "Content-Type": "text/plain" });
                res.end(`Send you end session request to server root, e.g. http://localhost:${port}?post_logout_redirect_uri=http%3A%2F%2Fexample.com&state=my_state`);
            }
        } else {
            res.writeHead(405, { "Content-Type": "text/plain" });
            res.end("Send your end session request as a GET request.");
        }
    } catch (e) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end(`Unexpected error:\n${e.stack}`);
    }
});

server.listen(port);
console.log(`Listening for end session requests on port ${port}...`);
