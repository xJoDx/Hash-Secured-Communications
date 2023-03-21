package com.example.requestsender;

import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.Response;
import com.android.volley.toolbox.HttpHeaderParser;

import java.io.UnsupportedEncodingException;
import java.util.Map;

/* CLASS: secureRequests extends Request<secureRequests.secureResponse>
 * ATTRIBUTES:
 *      - Response.Listener<secureRequests.secureResponse> customListener: basic Listener handling responses and errors
 *      - Host host: the host the request will be sent to
 *
 * AIM: The main goal of this class is to be able to parse the network response to separate the headers from the rest of
 *      the request, as well as retrieve the host the request was sent to.
 */
public class secureRequests extends Request<secureRequests.secureResponse> {
    private Response.Listener<secureRequests.secureResponse> customListener;
    private Host host;

    /* CONSTRUCTOR
     * This constructor allows to build a regular request while saving the Host instance used to create
     * the request
     */
    public secureRequests(int method, Host host, Response.Listener<secureRequests.secureResponse> secureResponseListener, Response.ErrorListener secureErrorListener) {
        super(method, host.getRemoteAddress(), secureErrorListener); //Build a classic request
        this.customListener = secureResponseListener;
        this.host = host;
    }

    /* FUNCTION: deliverResponse(secureResponse response)
     * RETURNS: void
     * PARAMETERS:
     *      - secureResponse response: the custom response to handle
     *
     * AIM: Handle the response given by the webserver
     */
    @Override
    protected void deliverResponse(secureResponse response){
        this.customListener.onResponse(response);
    }

    /* FUNCTION: parseNetworkResponse(NetworkResponse response)
     * RETURNS: Response<secureResponse>
     * PARAMETERS:
     *      - NetworkResponse response: raw response from the webserver
     *
     * AIM: Transform the regular response from the webserver into a secureResponse, which consists
     * in a enriched response allowing an easy access to the headers, as well as a reference to the
     * host the request was sent to (thus the host which sent the response)
     *
     * PROCESS:
     *      1. Try to get the headers if there is any
     *      2. Create a secureResponse instance containing the headers, the parsed version of the response
     *         as well as a reference to the original host
     *      3. Return the response
     */
    @Override
    protected Response<secureResponse> parseNetworkResponse(NetworkResponse response){
        String parsedSecureResponse;
        try{
            parsedSecureResponse = new String(response.data, HttpHeaderParser.parseCharset(response.headers)); //STEP 1
        } catch (UnsupportedEncodingException e){
            parsedSecureResponse = new String(response.data);
        }

        secureResponse secResp = new secureResponse(response.headers, parsedSecureResponse, host); //STEP 2

        return Response.success(secResp, HttpHeaderParser.parseCacheHeaders(response)); //STEP 3
    }

    /* CLASS: secureResponse
     * ATTRIBUTES:
     *      - Map<String, String> headers: Headers of the response
     *      - String response: Body of the response
     *      - Host originHost: Host the original request was sent to, which created the response
     *
     * AIM: Allow the application to handle the responses of the webserver and access key information
     * easily
     */
    public static class secureResponse{
        private Map<String, String> headers;
        private String response;
        private Host originHost;

        /* CONSTRUCTOR
         * Basic constructor that initializes the instance's attributes
         */
        public secureResponse(Map<String, String> remote_headers, String body, Host originHost){
            this.headers = remote_headers;
            this.response = body;
            this.originHost = originHost;
        }

        public Map<String, String> getHeaders() {return this.headers;} //Headers property
        public String getResponseBody() {return this.response; } //Response body property
        public Host getOriginHost() { return this.originHost; } //Original host property
    }
}
