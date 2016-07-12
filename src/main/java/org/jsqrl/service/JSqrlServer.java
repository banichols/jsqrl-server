package org.jsqrl.service;


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
import org.jsqrl.util.SqrlUtil;

import java.security.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * The main service class that follows the SQRL protocol to
 * processes a client SQRL request.
 * <p>
 * Created by Brent Nichols
 */
@Slf4j
public class JSqrlServer {

    private SqrlUserService userService;
    private SqrlAuthenticationService sqrlSqrlAuthenticationService;
    private SqrlConfig config;
    private SqrlNutService nutService;

    public JSqrlServer(SqrlUserService userService,
                       SqrlAuthenticationService sqrlSqrlAuthenticationService,
                       SqrlConfig config,
                       SqrlNutService nutService) {
        this.userService = userService;
        this.sqrlSqrlAuthenticationService = sqrlSqrlAuthenticationService;
        this.config = config;
        this.nutService = nutService;
    }

    public String createAuthenticationRequest(String ipAddress, Boolean qr) {
        SqrlNut nut = nutService.createNut(ipAddress, qr);
        String nutString = nutService.getNutString(nut);
        sqrlSqrlAuthenticationService.createAuthenticationRequest(nutString, ipAddress);
        log.debug("Creating nut {}", nutString);
        return nutString;
    }

    public SqrlAuthResponse handleClientRequest(SqrlClientRequest request,
                                                String nut,
                                                String ipAddress) {

        //Build the new nut for this request, retain the QR code
        SqrlNut requestNut = nutService.createNutFromString(nut);
        log.debug("Handling client request for nut {}", nut);
        SqrlNut responseNut = nutService.createNut(ipAddress, requestNut.isQr());
        String responseNutString = nutService.getNutString(responseNut);

        //Check protocol version first
        if (!request.getRequestVersion().equals(config.getSqrlVersion())) {
            return createResponse(responseNutString, null, TransactionInformationFlag.CLIENT_FAILURE);
        }

        byte[] messageBytes = (request.getClient() + request.getServer()).getBytes();

        String identityKey = request.getIdentityKey();
        String previousIdentityKey = request.getPreviousIdentityKey();

        //Validate message signature
        byte[] key = SqrlUtil.base64UrlDecode(identityKey);
        try {
            verifySqrlSignature(request.getDecodedIdentitySignature(), messageBytes, key);
        } catch (SqrlException e) {
            return createResponse(responseNutString, null, TransactionInformationFlag.CLIENT_FAILURE);
        }

        Set<TransactionInformationFlag> tifs = new HashSet<>();

        //Check nut expiration
        Long nutAge = Duration.between(requestNut.getCreated(), LocalDateTime.now()).getSeconds();

        if (nutAge > config.getNutExpirationSeconds()) {
            tifs.add(TransactionInformationFlag.TRANSIENT_ERROR);
        } else {

            //Correlate the requesting nut with the new one that was generated
            sqrlSqrlAuthenticationService.linkNut(nut, responseNutString);

            //Add the TIF for an IP match
            if (requestNut.checkIpMatch(responseNut)) {
                tifs.add(TransactionInformationFlag.IP_MATCHED);
            }

            SqrlUser sqrlUser = userService.getUserBySqrlKey(identityKey);

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

            //Determine the command
            SqrlCommand command = request.getCommand();

            if (command == SqrlCommand.QUERY) {
                //Don't authenticate the user, just provide the client
                //with information on what we know about the user via
                //the transaction information flags.
            } else if (command == SqrlCommand.IDENT) {
                //Authenticate the user
                //Register if needed
                if (sqrlUser == null) {
                    userService.registerSqrlUser(identityKey, request.getServerUnlockKey(), request.getVerifyUnlockKey());
                }

                //Authenticate the user
                sqrlSqrlAuthenticationService.authenticateNut(responseNutString, identityKey);

                tifs.add(TransactionInformationFlag.ID_MATCH);
            } else if (command == SqrlCommand.DISABLE) {
                //Disable the user's account
                userService.disableSqrlUser(identityKey);
            } else if (command == SqrlCommand.REMOVE) {
                //Remove the user's account
                userService.removeSqrlUser(identityKey);
            } else if (command == SqrlCommand.ENABLE) {
                //Re-enable the user's account
                userService.enableSqrlUser(identityKey);
            } else {
                //Unrecognized command
                tifs.add(TransactionInformationFlag.FUNCTION_NOT_SUPPORTED);
            }

            //Check if SQRL has been disabled for this user
            if (sqrlUser != null) {
                if (!sqrlUser.sqrlEnabled()) {
                    tifs.add(TransactionInformationFlag.SQRL_DISABLED);
                }
            }

        }

        String sukResponse = null;
        /**
         * TODO Windows client is re-creating the query incorrectly if the SUK is provided
         * TODO Check to see if it's a bug here, or with the client.
         */
/*        if(request.getOptionFlags().contains(SqrlOptionFlag.SERVER_UNLOCK_KEY) && sqrlUser != null){
            sukResponse = sqrlUser.getServerUnlockKey();
        }*/

        SqrlAuthResponse response = createResponse(
                responseNutString,
                sukResponse,
                tifs.toArray(new TransactionInformationFlag[tifs.size()]));

        log.debug("Response: {}", response);

        return response;

    }

    private SqrlAuthResponse createResponse(String nut, String suk, TransactionInformationFlag... tifs) {

        return SqrlAuthResponse.builder()
                .nut(nut)
                .qry(config.getSqrlBaseUri() + "?nut=" + nut)
                .addTifs(tifs)
                .ver(config.getSqrlVersion())
                .suk(suk).build();

    }

    private void verifySqrlSignature(byte[] idSignature,
                                     byte[] message,
                                     byte[] clientKey) {

        try {
            Signature signature = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            EdDSAParameterSpec edDsaSpec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);

            signature.initVerify(new EdDSAPublicKey(new EdDSAPublicKeySpec(clientKey, edDsaSpec)));
            signature.update(message);

            if (!signature.verify(idSignature)) {
                throw new SqrlException("Invalid message signature");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new SqrlException("Unable to verify message signature", e);
        }

    }

}
