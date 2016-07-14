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

package org.jsqrl.model;

/**
 * The interface for a user that can be authenticated with SQRL.
 * Have your user object implement these methods and provide the
 * required SQRL data.
 * <p>
 * Created by Brent Nichols
 */
public interface SqrlUser {
    /**
     * Method that will return the user's identity key (idk)
     *
     * @return The user's public identity key
     */
    String getIdentityKey();

    /**
     * Method that returns the user's server unlock key (suk)
     *
     * @return The user's server unlock key
     */
    String getServerUnlockKey();

    /**
     * Method that returns the user's verify unlock key (vuk)
     *
     * @return The user's verify unlock key
     */
    String getVerifyUnlockKey();

    /**
     * Method to determine if SQRL authentication is enabled
     * for the user
     *
     * @return Returns true if SQRL authentication is enabled
     * for the user
     */
    Boolean sqrlEnabled();
}
