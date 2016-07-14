/*
 * Copyright 2016 the original author or authors.
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

package org.jsqrl.service;

/**
 * A required service implementation to interact with server authentication data.
 * Have your service that handles authentication requests implement this interface.
 * <p>
 * Created by Brent Nichols
 */
public interface SqrlAuthenticationService {

    /**
     * This will create an authentication request for the user's
     * original nut token. It will get updated to authenticated
     * when the server receives and verifies an IDENT command.
     *
     * @param originalNut The original nut token the user received
     * @param ipAddress   The new nut that will be passed back to the SQRL client.
     * @return Returns true if the authentication request was created
     */
    Boolean createAuthenticationRequest(String originalNut, String ipAddress);

    /**
     * Links one nut with another. If the original nut is the user's nut
     * that they are trying to authenticate with, then the initial link should
     * be created. If it is not then the link between that original nut should
     * be updated from the oldNut to the newNut.
     *
     * @param oldNut The "old" nut that was provided by the client. Will be
     *               discarded unless it's the original authenticating nut.
     * @param newNut The new nut that's generated by the server.
     * @return Return true if the link was successfully created or updated
     */
    Boolean linkNut(String oldNut, String newNut);

    /**
     * Authenticates the user
     *
     * @param nut The linked nut token being used to authenticate the user
     * @param identityKey The user's public key
     * @return Returns an object to represent the user
     */
    Boolean authenticateNut(String nut, String identityKey);

    /**
     * This is used to retrieve the user by the nut they have in their
     * authentication request, but only after it has been authenticated.
     *
     * @param nut The nut that was initially provided to the user
     * @return Returns the user's SQRL public key
     */
    String getAuthenticatedSqrlIdentityKey(String nut);

}
