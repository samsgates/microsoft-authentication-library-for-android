package com.microsoft.identity.client.fadiHTTP;

import androidx.annotation.NonNull;

import java.util.HashMap;

public interface CodeFlowCallback {
    void tokenReceived(HashMap<String, String> tokenMap);
    void userReceived(@NonNull String vUri, @NonNull String user_code);
    void processFailed(int authCode, int tokenCode, @NonNull String output);
}
