package com.microsoft.identity.client.msal.automationapp.utils;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;
import android.content.Intent;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.uiautomator.UiDevice;

import com.microsoft.identity.internal.testutils.TestUtils;

import org.junit.Assert;

import java.io.IOException;

import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;
import static com.microsoft.identity.common.adal.internal.AuthenticationConstants.Broker.BROKER_ACCOUNT_TYPE;

public class CommonUtils {

    public final static long TIMEOUT = 1000 * 60;

    public static void launchApp(final String packageName) {
        final Context context = ApplicationProvider.getApplicationContext();
        Intent intent = context.getPackageManager().getLaunchIntentForPackage(packageName);  //sets the intent to start your app
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);  //clear out any previous task, i.e., make sure it starts on the initial screen
        context.startActivity(intent);
    }

    public static void removeApp(final String packageName) {
        UiDevice mDevice = UiDevice.getInstance(getInstrumentation());
        try {
            String output = mDevice.executeShellCommand("pm uninstall " + packageName);
        } catch (IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    public static void clearApp(final String packageName) {
        UiDevice mDevice = UiDevice.getInstance(getInstrumentation());
        try {
            String output = mDevice.executeShellCommand("pm clear " + packageName);
        } catch (IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    public static void disableFirstRun(final String packageName) {
        UiDevice mDevice = UiDevice.getInstance(getInstrumentation());
        try {
            String output = mDevice.executeShellCommand("\'echo \"chrome --disable-fre --no-default-browser-check --no-first-run\" > /data/local/tmp/chrome-command-line\'");
        } catch (IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    public static void installApp(final String packageName) {
        UiDevice mDevice = UiDevice.getInstance(getInstrumentation());
        try {
            String output = mDevice.executeShellCommand("pm clear " + packageName);
        } catch (IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    public static String getResourceId(final String appPackageName, final String internalResourceId) {
        return appPackageName + ":id/" + internalResourceId;
    }

    static boolean isStringPackageName(final String hint) {
        return hint.contains("."); // best guess
    }

    public static boolean removeAccountFromAccountManager(final String upn) {
        final Context context = TestUtils.getContext();
        final AccountManager accountManager = AccountManager.get(context);
        final Account[] workAccounts = accountManager.getAccountsByType(BROKER_ACCOUNT_TYPE);
        for (final Account account : workAccounts) {
            if (account.name.equalsIgnoreCase(upn)) {
                return accountManager.removeAccountExplicitly(account);
            }
        }

        return false;
    }
}