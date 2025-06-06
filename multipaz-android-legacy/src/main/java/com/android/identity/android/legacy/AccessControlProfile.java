/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity.android.legacy;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.errorprone.annotations.CanIgnoreReturnValue;

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * A class used to specify access controls.
 */
public class AccessControlProfile {
    @NonNull AccessControlProfileId mAccessControlProfileId = new AccessControlProfileId(0);
    @Nullable X509Certificate mReaderCertificate = null;
    boolean mUserAuthenticationRequired = true;
    long mUserAuthenticationTimeoutMillis = 0;

    AccessControlProfile() {
    }

    @NonNull
    AccessControlProfileId getAccessControlProfileId() {
        return mAccessControlProfileId;
    }

    /**
     * Returns the authentication timeout, in milliseconds.
     */
    long getUserAuthenticationTimeout() {
        return mUserAuthenticationTimeoutMillis;
    }

    boolean isUserAuthenticationRequired() {
        return mUserAuthenticationRequired;
    }

    @Nullable
    X509Certificate getReaderCertificate() {
        return mReaderCertificate;
    }

    /**
     * A builder for {@link AccessControlProfile}.
     */
    public static final class Builder {
        private final AccessControlProfile mProfile;

        /**
         * Each access control profile has numeric identifier that must be unique within the
         * context of a Credential and may be used to reference the profile.
         *
         * <p>By default, the resulting {@link AccessControlProfile} will require user
         * authentication with a timeout of zero, thus requiring the holder to authenticate for
         * every presentation where data elements using this access control profile is used.</p>
         *
         * @param accessControlProfileId the access control profile identifier.
         */
        public Builder(@NonNull AccessControlProfileId accessControlProfileId) {
            mProfile = new AccessControlProfile();
            mProfile.mAccessControlProfileId = accessControlProfileId;
        }

        /**
         * Set whether user authentication is required.
         *
         * <p>This should be used sparingly since disabling user authentication on just a single
         * data element can easily create a
         * <a href="https://en.wikipedia.org/wiki/Relay_attack">Relay Attack</a> if the device
         * on which the credential is stored is compromised.</p>
         *
         * <p>The default behavior of a {@link AccessControlProfile} created from a builder
         * is to require user authentication.</p>
         *
         * @param userAuthenticationRequired Set to true if user authentication is required,
         *                                   false otherwise.
         * @return The builder.
         */
        @CanIgnoreReturnValue
        public @NonNull Builder setUserAuthenticationRequired(boolean userAuthenticationRequired) {
            mProfile.mUserAuthenticationRequired = userAuthenticationRequired;
            return this;
        }

        /**
         * Sets the authentication timeout to use.
         *
         * <p>The authentication timeout specifies the amount of time, in milliseconds, for which a
         * user authentication is valid, if user authentication is required (see
         * {@link #setUserAuthenticationRequired(boolean)}).</p>
         *
         * <p>If the timeout is zero, then authentication is always required for each reader
         * session.</p>
         *
         * <p>The default behavior of a {@link AccessControlProfile} created from a builder
         * is to use a timeout of 0.</p>
         *
         * @param userAuthenticationTimeoutMillis the authentication timeout, in milliseconds.
         * @return The builder.
         */
        @CanIgnoreReturnValue
        public @NonNull Builder setUserAuthenticationTimeout(long userAuthenticationTimeoutMillis) {
            mProfile.mUserAuthenticationTimeoutMillis = userAuthenticationTimeoutMillis;
            return this;
        }

        /**
         * Sets the reader certificate to use when checking access control.
         *
         * <p>If set, this is checked against the certificate chain presented by reader. The
         * access check is fulfilled only if the public key from one of the certificates in the
         * chain, matches the public key in the certificate set by this
         * method.</p>
         *
         * <p>The default behavior of a {@link AccessControlProfile} created from a builder
         * is to not use reader authentication.</p>
         *
         * @param readerCertificate the certificate to use for the access control check.
         * @return The builder.
         */
        @CanIgnoreReturnValue
        public @NonNull Builder setReaderCertificate(@NonNull X509Certificate readerCertificate) {
            mProfile.mReaderCertificate = readerCertificate;
            return this;
        }

        /**
         * Creates a new {@link AccessControlProfile} from the data supplied to the builder.
         *
         * @return The created {@link AccessControlProfile} object.
         */
        public @NonNull AccessControlProfile build() {
            return mProfile;
        }
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AccessControlProfile)) {
            return false;
        }
        AccessControlProfile that = (AccessControlProfile) o;
        return Objects.equals(mAccessControlProfileId, that.mAccessControlProfileId)
                && mUserAuthenticationRequired == that.mUserAuthenticationRequired
                && mUserAuthenticationTimeoutMillis == that.mUserAuthenticationTimeoutMillis;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                mAccessControlProfileId, mUserAuthenticationRequired, mUserAuthenticationTimeoutMillis);
    }
}
