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

package org.jsqrl.server;


import lombok.extern.slf4j.Slf4j;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.jsqrl.config.SqrlConfig;
import org.jsqrl.error.SqrlException;
import org.jsqrl.model.*;
import org.jsqrl.nut.SqrlNut;
import org.jsqrl.service.SqrlAuthenticationService;
import org.jsqrl.service.SqrlNutService;
import org.jsqrl.service.SqrlUserService;
import org.jsqrl.util.SqrlUtil;

import java.security.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * The main service class that follows the SQRL protocol to
 * processes a client SQRL request.
 *
 * Created by Brent Nichols
 */
@Slf4j
public class JSqrlServer {

    private final SqrlUserService userService;
    private final SqrlAuthenticationService sqrlAuthenticationService;
    private final SqrlConfig config;
    private final SqrlNutService nutService;

    private final EdDSAParameterSpec edDsaSpec;

    public JSqrlServer(final SqrlUserService userService,
                       final SqrlAuthenticationService sqrlAuthenticationService,
                       final SqrlConfig config,
                       final SqrlNutService nutService) {
        this.userService = userService;
        this.sqrlAuthenticationService = sqrlAuthenticationService;
        this.config = config;
        this.nutService = nutService;
        edDsaSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
    }

    /**
     * This method should be the method called when a user is requesting
     * a nut. This creates the nut that signifies the authentication request,
     * which should get marked as authenticated when the user uses a SQRL client
     * to authenticate.
     *
     * @param ipAddress The requesting IP Address
     * @param qr        If the user used the QR code or not
     * @return Returns the nut to be provided to the user
     */
    public String createAuthenticationRequest(final String ipAddress, final Boolean qr) {
        SqrlNut nut = nutService.createNut(ipAddress, qr);
        String nutString = nutService.getNutString(nut);
        sqrlAuthenticationService.createAuthenticationRequest(nutString, ipAddress);
        log.debug("Creating nut {}", nutString);
        return nutString;
    }

    /**
     * This method should be used to check the authentication status of a nut.
     * This should be a nut created by the createAuthenticationRequest method
     * that was marked as authenticated by using a SQRL client.
     *
     * @param nut       The nut provided by the user
     * @param ipAddress The requesting IP Address
     * @return Returns true if the nut was marked as authenticated
     */
    public Boolean checkAuthenticationStatus(final String nut, final String ipAddress) {
        return nutService.nutBelongsToIp(nut, ipAddress) && sqrlAuthenticationService.getAuthenticatedSqrlIdentityKey(nut, ipAddress) != null;
    }

    public SqrlAuthResponse handleClientRequest(final SqrlClientRequest request,
                                                final String nut,
                                                final String ipAddress) {

        //Build the new nut for this request, retain the QR code
        SqrlNut requestNut = nutService.createNutFromString(nut);
        log.debug("Handling client request for nut {}", nut);
        SqrlNut responseNut = nutService.createNut(ipAddress, requestNut.isQr());
        String responseNutString = nutService.getNutString(responseNut);

        //Prepare the server unlock key value for the response
        String sukResponse = null;

        //Check protocol version first
        if (!request.getRequestVersion().equals(config.getSqrlVersion())) {
            return createResponse(responseNutString, null, TransactionInformationFlag.CLIENT_FAILURE);
        }

        //Validate IDS and PIDS request signatures
        Signature verifier;
        try {
            verifier = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            verifyIdSignature(request, verifier);
            verifyPreviousIdSignature(request, verifier);
        } catch (SqrlException | NoSuchAlgorithmException e) {
            log.debug("Unable to verify signature", e);
            return createResponse(responseNutString, null, TransactionInformationFlag.CLIENT_FAILURE);
        }

        String identityKey = request.getIdentityKey();
        String previousIdentityKey = request.getPreviousIdentityKey();

        Set<TransactionInformationFlag> tifs = new HashSet<>();

        //Check nut expiration
        Long nutAge = Duration.between(requestNut.getCreated(), LocalDateTime.now()).getSeconds();

        if (nutAge > config.getNutExpirationSeconds()) {
            tifs.add(TransactionInformationFlag.TRANSIENT_ERROR);
        } else {

            //Correlate the requesting nut with the new one that was generated
            sqrlAuthenticationService.linkNut(nut, responseNutString);

            //Add the TIF for an IP match
            if (requestNut.checkIpMatch(responseNut)) {
                tifs.add(TransactionInformationFlag.IP_MATCHED);
            }

            SqrlUser sqrlUser = userService.getUserBySqrlKey(identityKey);
            Boolean sqrlEnabled = true;

            if (sqrlUser != null) {
                //If the user is found, add the TIF for identity match
                tifs.add(TransactionInformationFlag.ID_MATCH);
            } else if (previousIdentityKey != null) {
                //Try their previous identity key if they are carrying one
                sqrlUser = userService.getUserBySqrlKey(previousIdentityKey);
                if (sqrlUser != null) {
                    userService.updateIdentityKey(previousIdentityKey, identityKey);
                    tifs.add(TransactionInformationFlag.PREVIOUS_ID_MATCH);
                }
            }

            if (sqrlUser != null && request.getOptionFlags().contains(SqrlOptionFlag.SERVER_UNLOCK_KEY)) {
                sukResponse = sqrlUser.getServerUnlockKey();
            }

            //Check for disabled status
            if (sqrlUser != null && !sqrlUser.sqrlEnabled()) {
                sqrlEnabled = false;
                tifs.add(TransactionInformationFlag.SQRL_DISABLED);
            }

            //Determine the command
            SqrlCommand command = request.getCommand();

            if (command == null) {
                //Unrecognized command
                tifs.add(TransactionInformationFlag.FUNCTION_NOT_SUPPORTED);
            } else if (command == SqrlCommand.QUERY && sqrlEnabled) {
                //Don't authenticate the user, just provide the client
                //with information on what we know about the user via
                //the transaction information flags.
            } else if (command == SqrlCommand.IDENT && sqrlEnabled) {
                //Authenticate the user
                //Register if needed
                if (sqrlUser == null) {
                    userService.registerSqrlUser(identityKey, request.getServerUnlockKey(), request.getVerifyUnlockKey());
                }

                //Authenticate the user
                sqrlAuthenticationService.authenticateNut(responseNutString, identityKey);

                tifs.add(TransactionInformationFlag.ID_MATCH);
            } else if (command == SqrlCommand.DISABLE && sqrlEnabled) {
                //Disable the user's account
                userService.disableSqrlUser(identityKey);
            } else if (command == SqrlCommand.REMOVE && sqrlEnabled) {
                if (sqrlUser != null) {
                    //Remove the user's account
                    verifyUnlockRequestSignature(request, sqrlUser.getVerifyUnlockKey(), verifier);
                    userService.removeSqrlUser(identityKey);
                } else {
                    tifs.add(TransactionInformationFlag.CLIENT_FAILURE);
                }
            } else if (command == SqrlCommand.ENABLE) {
                if (sqrlUser != null) {
                    //Re-enable the user's account
                    verifyUnlockRequestSignature(request, sqrlUser.getVerifyUnlockKey(), verifier);
                    userService.enableSqrlUser(identityKey);
                } else {
                    tifs.add(TransactionInformationFlag.CLIENT_FAILURE);
                }
            }

        }

        SqrlAuthResponse response = createResponse(
                responseNutString,
                sukResponse,
                tifs.toArray(new TransactionInformationFlag[tifs.size()]));

        log.debug("Response: {}", response);

        return response;

    }

    private SqrlAuthResponse createResponse(final String nut,
                                            final String suk,
                                            final TransactionInformationFlag... tifs) {

        return SqrlAuthResponse.builder()
                .nut(nut)
                .qry(config.getSqrlBaseUri() + "?nut=" + nut)
                .addTifs(tifs)
                .ver(config.getSqrlVersion())
                .suk(suk).build();

    }

    private void verifyIdSignature(final SqrlClientRequest request, final Signature verifier) {
        verifySqrlRequestSignature(
                request,
                verifier,
                SqrlUtil.base64UrlDecode(request.getIdentityKey()),
                request.getDecodedIdentitySignature(),
                "Unable to verify ID Signature");
    }

    private void verifyUnlockRequestSignature(final SqrlClientRequest request,
                                              final String verifyUnlockKey,
                                              final Signature verifier) {
        verifySqrlRequestSignature(
                request,
                verifier,
                SqrlUtil.base64UrlDecode(verifyUnlockKey),
                request.getDecodedUnlockRequestSignature(),
                "Unable to verify Unlock Request Signature");
    }

    private void verifyPreviousIdSignature(final SqrlClientRequest request,
                                           final Signature verifier) {
        if (request.getPreviousIdentityKey() != null) {
            verifySqrlRequestSignature(
                    request,
                    verifier,
                    SqrlUtil.base64UrlDecode(request.getPreviousIdentityKey()),
                    request.getDecodedPreviousIdSignature(),
                    "Unable to verify Previous ID Signature");
        }
    }

    private void verifySqrlRequestSignature(final SqrlClientRequest request,
                                            final Signature verifier,
                                            final byte[] key,
                                            final byte[] signature,
                                            final String errorMessage) {
        byte[] requestMessage = (request.getClient() + request.getServer()).getBytes();
        try {
            if (!verifyEdDSASignature(verifier, key, requestMessage, signature)) {
                throw new SqrlException(errorMessage);
            }
        } catch (InvalidKeyException | SignatureException e) {
            throw new SqrlException("Unable to verify message signature", e);
        }
    }

    private Boolean verifyEdDSASignature(final Signature verifier,
                                         final byte[] key,
                                         final byte[] message,
                                         final byte[] signature) throws InvalidKeyException, SignatureException {
        verifier.initVerify(new EdDSAPublicKey(new EdDSAPublicKeySpec(key, edDsaSpec)));
        verifier.update(message);
        return verifier.verify(signature);
    }

}
