package com.microsoft.identity.client.fadiHTTP;

import android.os.AsyncTask;

import androidx.annotation.NonNull;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class DeviceCodeFlowTest extends AsyncTask<String, Void, String> {
    private String url;
    private CodeFlowCallback callback;
    private HashMap<String, String> authParams; // Holds client_id and scopes
    private int auth_res_code = -1; // Code returned after the auth request segment
    private HashMap<String, String> tokenParams = new HashMap<>(); // Holds parameters from deviceAuth step
    private int token_res_code = -1; // Code returned after the token segment

    public DeviceCodeFlowTest(@NonNull String url, @NonNull HashMap<String, String> params, CodeFlowCallback callback) {
        this.url = url;
        this.authParams = params;
        this.callback = callback;
    }

    @Override
    protected String doInBackground(String... params){
        try {
            // Part 1: Device Authorization Request
            String authResponse = deviceAuthRequest(this.url, this.authParams);

            // If the auth request segment fails, return the response body and declare failure before token segment is called.
            if (auth_res_code != HttpURLConnection.HTTP_OK){
                return authResponse;
            }

            // Use response from auth request segment to prepare for token acquisition.
            populateFromResponse(authResponse);

            // Display verification Uri and user code to the user
            callback.userReceived(tokenParams.get("verification_uri"), tokenParams.get("user_code"));

            // Part 2: Device Token Acquisition
            return deviceTokenRequest(this.url, this.tokenParams);
        }
        catch (IOException | InterruptedException e) {
            return e.toString();
        }
    }

    /**
     * First segment of the Device Code Flow protocol. Uses the /devicecode endpoint and acquire information relevant to
     * the user authentication process.
     * @param url Url to be used
     * @param params Includes client_id and the desired scopes
     * @return The response body returned by the request, either contains the relevant information or an error message
     * @throws IOException In case of HTTP related exceptions
     */
    private String deviceAuthRequest(@NonNull String url, @NonNull HashMap<String, String> params) throws IOException {
        String deviceCodeURL = url + "/devicecode";

        URL urlBody = new URL(deviceCodeURL);
        HttpURLConnection con = (HttpURLConnection) urlBody.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        con.setConnectTimeout(5000);
        con.setReadTimeout(5000);

        con.setDoOutput(true);
        DataOutputStream out = new DataOutputStream(con.getOutputStream());
        String convertedParams = createAuthRequestBody(params);
        out.writeBytes(convertedParams);
        out.flush();
        out.close();

        auth_res_code = con.getResponseCode();
        BufferedReader streamReader;

        if (auth_res_code > 299) {
            streamReader = new BufferedReader(new InputStreamReader(con.getErrorStream()));
        }
        else {
            streamReader = new BufferedReader(new InputStreamReader(con.getInputStream()));
        }

        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = streamReader.readLine()) != null)
            content.append(inputLine);

        streamReader.close();
        con.disconnect();

        return content.toString();
    }

    /**
     * Used to convert the auth request parameters into a properly formatted string to include in the request.
     * @param params client_id and scopes
     * @return formatted string
     * @throws UnsupportedEncodingException Encoding related exception
     */
    private String createAuthRequestBody(@NonNull HashMap<String, String> params) throws UnsupportedEncodingException {
        StringBuilder encodedResult = new StringBuilder();

        // Encode client_id
        encodedResult.append(URLEncoder.encode("client_id", "UTF-8"));
        encodedResult.append("=");
        encodedResult.append(URLEncoder.encode(params.get("client_id"), "UTF-8"));
        encodedResult.append("&");

        // Encode scope
        String[] scope = params.get("scope").split(", ");
        encodedResult.append(URLEncoder.encode("scope", "UTF-8"));
        encodedResult.append("=");
        for (String s : scope) {
            encodedResult.append(URLEncoder.encode(s, "UTF-8"));
            encodedResult.append(URLEncoder.encode(" ", "UTF-8"));
        }
        encodedResult.setLength(encodedResult.length() - 1);

        return encodedResult.toString();
    }

    /**
     * Used to parse the response body from the auth request segment and populate parameters for the token segment.
     * @param response Response returned from the auth request segment
     */
    private void populateFromResponse(@NonNull String response){
        // Parse response and populate tokenParams
        HashMap<String, String> map = new Gson().fromJson(response, new TypeToken<HashMap<String, String>>() {}.getType());

        // Populate our HashMap with the parsed response
        for(Map.Entry<String, String> entry : map.entrySet()){
            tokenParams.put(entry.getKey(), entry.getValue());
        }

        // Add client_id to token segment's parameters, will be needed
        tokenParams.put("client_id", authParams.get("client_id"));
    }

    /**
     * Second segment of the Device Code Flow protocol. Uses the /token endpoint to acquire an access token after
     * periodically checking if the user has been authenticated.
     * @param url Url to be used
     * @param params Parameters from auth request, includes:
     *              device_code, user_code, verification_uri, expires_in, interval, and message
     * @return an authentication token
     * @throws IOException In case of HTTP related exceptions
     */
    private String deviceTokenRequest(@NonNull String url, @NonNull HashMap<String, String> params) throws IOException, InterruptedException {
        String deviceCodeURL = url + "/token";

        // Convert to miliseconds
        // expires_in may not be needed, would get a response reflecting an expired token
        // int expires_in = Integer.parseInt(params.get("expires_in")) * 1000;
        int interval = Integer.parseInt(params.get("interval")) * 1000;
        String convertedParams = createTokenRequestBody(params);

        String response = "";
        HashMap<String, Object> parsedResponse;
        String error = "";

        while (token_res_code == -1 || (error != null && error.equals("authorization_pending"))) {
            response = checkForToken(deviceCodeURL, convertedParams);

            parsedResponse = new Gson().
                    fromJson(response, new TypeToken<HashMap<String, Object>>() {}.getType());
            error = (String) parsedResponse.get("error");

            if (error != null && error.equals("authorization_pending")) {
                Thread.sleep(interval);
            }
        }

        return response;
    }

    /**
     * Used to convert the auth request parameters into a properly formatted string to include in the request.
     * @param params contains client_id and device_code
     * @return formatted string
     * @throws UnsupportedEncodingException Encoding related exception
     */
    private String createTokenRequestBody(@NonNull HashMap<String, String> params) throws UnsupportedEncodingException {
        StringBuilder encodedResult = new StringBuilder();

        // Encode grant_type
        encodedResult.append(URLEncoder.encode("grant_type", "UTF-8"));
        encodedResult.append("=");
        encodedResult.append(URLEncoder.encode("urn:ietf:params:oauth:grant-type:device_code", "UTF-8"));
        encodedResult.append("&");

        // Encode client_id
        encodedResult.append(URLEncoder.encode("client_id", "UTF-8"));
        encodedResult.append("=");
        encodedResult.append(URLEncoder.encode(params.get("client_id"), "UTF-8"));
        encodedResult.append("&");

        // Encode device_code
        encodedResult.append(URLEncoder.encode("device_code", "UTF-8"));
        encodedResult.append("=");
        encodedResult.append(URLEncoder.encode(params.get("device_code"), "UTF-8"));

        return encodedResult.toString();
    }

    /**
     * This helper method is used to send a single request to the token endpoint
     * @param url Request address
     * @param cParams Request body
     * @throws IOException HTTP related exception
     */
    private String checkForToken(@NonNull String url, @NonNull String cParams) throws IOException {
        URL urlBody = new URL(url);
        HttpURLConnection con = (HttpURLConnection) urlBody.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        con.setConnectTimeout(10000);
        con.setReadTimeout(10000);

        con.setDoOutput(true);
        DataOutputStream out = new DataOutputStream(con.getOutputStream());
        out.writeBytes(cParams);
        out.flush();
        out.close();

        token_res_code = con.getResponseCode();
        BufferedReader streamReader;

        if (token_res_code > 299) {
            streamReader = new BufferedReader(new InputStreamReader(con.getErrorStream()));
        }
        else {
            streamReader = new BufferedReader(new InputStreamReader(con.getInputStream()));
        }

        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = streamReader.readLine()) != null)
            content.append(inputLine);

        streamReader.close();
        con.disconnect();

        return content.toString();
    }

    protected void onPostExecute(String response) {
        if (auth_res_code==HttpURLConnection.HTTP_OK && token_res_code==HttpURLConnection.HTTP_OK){
            HashMap<String, String> parsedResponse = new Gson().
                    fromJson(response, new TypeToken<HashMap<String, String>>() {}.getType());

            HashMap<String, String> responseMap = new HashMap<>();
            responseMap.put("access_token", parsedResponse.get("access_token"));
            responseMap.put("refresh_token", parsedResponse.get("refresh_token"));

            callback.tokenReceived(responseMap);
        }
        else {
            HashMap<String, Object> parsedResponse = new Gson().
                    fromJson(response, new TypeToken<HashMap<String, Object>>() {}.getType());

            StringBuilder error = new StringBuilder();
            error.append((String) parsedResponse.get("error"));
            error.append(": ");
            error.append((String) parsedResponse.get("error_description"));

            callback.processFailed(auth_res_code, token_res_code, error.toString());
        }
    }
}
