package com.microsoft.identity.client;

import android.app.Activity;
import android.util.Pair;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

import java.util.List;

public class CalculateInputParameters extends TokenParameters {

    private Activity mActivity;
    private int num1;
    private int num2;
    private char operation;
    //private AuthenticationCallback mCallback;

    protected CalculateInputParameters(@NonNull Builder builder) {
        super(builder);
        mActivity = builder.mActivity;
        num1 = builder.num1;
        num2 = builder.num2;
        operation = builder.operation;
        //mCallback = builder.mCallback;
    }

    public Activity getActivity() {
        return mActivity;
    }
    public int getNum1() { return num1;}
    public int getNum2() { return num2;}
    public char getOperation() { return operation;}

    public static class Builder extends TokenParameters.Builder<CalculateInputParameters.Builder> {

        private Activity mActivity;
        private int num1;
        private int num2;
        private char operation;
        //private AuthenticationCallback mCallback;

        public CalculateInputParameters.Builder startAuthorizationFromActivity(final Activity activity) {
            mActivity = activity;
            return self();
        }

        public CalculateInputParameters.Builder withNum1(int num) {
            num1 = num;
            return self();
        }

        public CalculateInputParameters.Builder withNum2(int num) {
            num2 = num;
            return self();
        }

        public CalculateInputParameters.Builder withOperation(char op) {
            operation = op;
            return self();
        }

//        public CalculateInputParameters.Builder withCallback(final AuthenticationCallback authenticationCallback) {
//            mCallback = authenticationCallback;
//            return self();
//        }

        @Override
        public CalculateInputParameters.Builder self() {
            return this;
        }

        public CalculateInputParameters build() {
            return new CalculateInputParameters(this);
        }
    }
}
