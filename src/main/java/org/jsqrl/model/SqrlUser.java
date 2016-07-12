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
