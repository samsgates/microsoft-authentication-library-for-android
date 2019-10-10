package com.microsoft.identity.client.robolectric.tests.network;

/**
 * Run all tests in the {@link AcquireTokenNetworkTest} class using B2C
 */
public class AcquireTokenNetworkB2CTest extends AcquireTokenNetworkTest {

    public AcquireTokenNetworkB2CTest() {
        this.mAuthorityType = B2C_AUTHORITY_TYPE_STRING;
        this.mScopes = B2C_SCOPES;
    }
}
