/*
 * GidsApplet: A Java Card implementation of the GIDS (Generic Identity
 * Device Specification) specification
 * https://msdn.microsoft.com/en-us/library/windows/hardware/dn642100%28v=vs.85%29.aspx
 * Copyright (C) 2016  Vincent Le Toux(vincent.letoux@mysmartlogon.com)
 *
 * It has been based on the IsoApplet
 * Copyright (C) 2014  Philip Wendland (wendlandphilip@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

package com.mysmartlogon.gidsApplet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * \brief class used to encapsulte authentication functions
 // This class is for managing the GidsPIN
 // Set default constant values for PIN and State Assignment to Admin Authentications
 */
public class GidsPINManager {

    /* PIN, PUK and key realted constants */
    // PIN:
    private static final byte PIN_MAX_TRIES = 3;
    private static final byte PIN_MIN_LENGTH = 4;
    private static final byte PIN_MAX_LENGTH = 16;
    // PUK:
    private static final byte PUK_MAX_TRIES = 3;
    private static final byte PUK_MIN_LENGTH = 4;
    private static final byte PUK_MAX_LENGTH = 16;
    // Challenge:
    private static final short CHALLENGE_LENGTH = 16;
    // Application lifecycle state
    public static final byte CREATION_STATE = (byte)0x11;
    public static final byte INITIALIZATION_STATE = (byte)0x22;
    public static final byte OPERATIONAL_STATE = (byte)0x44;
    public static final byte TERMINATION_STATE = (byte)0x88;
    // State for admin authentication
    private static final byte ADMIN_NOT_AUTHENTICATED = (byte)0x00;
    private static final byte EXTERNAL_CHALLENGE = (byte)0x11;
    private static final byte MUTUAL_CHALLENGE = (byte)0x22;
    private static final byte EXTERNAL_AUTHENTICATED = (byte)0x44;
    private static final byte MUTUAL_AUTHENTICATED = (byte)0x88;

    // An instance of GidsPIN Class
    private GidsPIN pin_pin = null;
    private GidsPIN puk_puk = null;
    private byte applicationState = CREATION_STATE;

    private byte[] ExternalChallenge = null;
    private byte[] CardChallenge = null;
    private Object[] KeyReference = null;
    private byte[] buffer = null;
    private byte[] sharedKey = null;
    private byte[] status = null;

    // Constructor for setting default values for the variables of the instance GidsPIN
    // also specifying the challenges, keys and status.
    public GidsPINManager() {
        pin_pin = new GidsPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH, PIN_MIN_LENGTH);
        puk_puk = new GidsPIN(PUK_MAX_TRIES, PUK_MAX_LENGTH, PUK_MIN_LENGTH);
        ExternalChallenge = JCSystem.makeTransientByteArray(CHALLENGE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        CardChallenge = JCSystem.makeTransientByteArray(CHALLENGE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        KeyReference = JCSystem.makeTransientObjectArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        buffer = JCSystem.makeTransientByteArray((short)40, JCSystem.CLEAR_ON_DESELECT);
        sharedKey = JCSystem.makeTransientByteArray((short)40, JCSystem.CLEAR_ON_DESELECT);
        status = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_DESELECT);
        status[0] = ADMIN_NOT_AUTHENTICATED;
    }

    private GidsPIN GetPINByReference(byte reference) throws NotFoundException {
        switch(reference) {
        case (byte) 0x80:
        case (byte) 0x00:
            return pin_pin;
        case (byte) 0x81:
        // No PUK on v2 of the card
        default:
            throw NotFoundException.getInstance();
        }
    }
 
    private GidsPIN GetPUKByReference(byte reference) throws NotFoundException {
         switch(reference) {
         case (byte) 0x80:
         case (byte) 0x00:
             return puk_puk;
         case (byte) 0x81:
         
         default:
             throw NotFoundException.getInstance();
         }
     }

    /**
     * Checks if the current application state matches any of the required state(s).
     * @param requiredState Either ADMIN_NOT_AUTHENTICATED, or one or several required state(s), to give several possible states use the OR operation.
     * @return true if operation was successful, false otherwise
     */
    public boolean CheckAdminAuthenticationState (final byte requiredState) {
        final byte authState = status[0];

        // Check for no current authentication
        if (requiredState == ADMIN_NOT_AUTHENTICATED) {
            return authState == ADMIN_NOT_AUTHENTICATED;
        }

        // Check if admin authentication state is contained within required state(s)
        if ((byte) (authState & requiredState) != authState) {
            return false;
        }

        // Check if admin authentication state matches any known states exactly (trying to detect memory corruption)
        switch (authState) {
            case EXTERNAL_CHALLENGE:
            case EXTERNAL_AUTHENTICATED:
            case MUTUAL_CHALLENGE:
            case MUTUAL_AUTHENTICATED:
                return true;
            default: // No known state matched! Something must be going wrong with the variable.
                return false;
        }
    }

    /**
     * Checks if the current application state matches any of the required state(s).
     * @param requiredState One or several required state(s), to give several possible states use the OR operation
     * @return true if operation was successful, false otherwise
     */
    public boolean CheckApplicationState (final byte requiredState) {
        // Check if application state is contained within required state(s)
        if ((byte) (applicationState & requiredState) != applicationState) {
            return false;
        }

        // Check if application state matches any known states exactly (trying to detect memory corruption)
        switch (applicationState) {
            case CREATION_STATE:
            case INITIALIZATION_STATE:
            case OPERATIONAL_STATE:
            case TERMINATION_STATE:
                return true;
            default: // No known state matched! Something must be going wrong with the variable.
                return false;
        }
    }

    /**
     * Changes the current external/mutual authentication state. Only used internally.
     * @param nextState Next state of the application
     * @return true if operation was successful, false otherwise
     */
    private boolean SetAdminAuthenticationState (final byte nextState) {

        // No further checks for deauthentication (we just clear the challenge data)
        if (nextState == ADMIN_NOT_AUTHENTICATED) {
            status[0] = ADMIN_NOT_AUTHENTICATED;
            ClearChallengeData();
            return true;
        }

        if (nextState == EXTERNAL_CHALLENGE) {
            if (CheckAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED)) {
                status[0] = EXTERNAL_CHALLENGE;
                return true;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return false;
            }
        }

        if (nextState == EXTERNAL_AUTHENTICATED) {
            if (CheckAdminAuthenticationState(EXTERNAL_CHALLENGE)) {
                status[0] = EXTERNAL_AUTHENTICATED;
                ClearChallengeData();
                return true;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return false;
            }
        }

        if (nextState == MUTUAL_CHALLENGE) {
            if (CheckAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED)) {
                status[0] = MUTUAL_CHALLENGE;
                return true;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return false;
            }
        }

        if (nextState == MUTUAL_AUTHENTICATED) {
            if (CheckAdminAuthenticationState(MUTUAL_CHALLENGE)) {
                status[0] = MUTUAL_AUTHENTICATED;
                ClearChallengeData();
                return true;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return false;
            }
        }

        // Something went wrong!
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return false;
    }

    /**
     * Changes the current state of the application.
     * Some states can only be defined from a specific previous state. Throws an ISO security exception if specific state is not met.
     * @param nextState Next state of the application
     * @return true if operation was successful, false otherwise
     */
    public boolean SetApplicationState (final byte nextState) {

        // Entering initialization state:
        //  - The card can now accept external commands (such as read/write operations)
        if (nextState == INITIALIZATION_STATE) {
            if (CheckApplicationState(CREATION_STATE)) {
                applicationState = INITIALIZATION_STATE;
                return true;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return false;
            }
        }

        // Entering operational state:
        //  - The card now requires authentication for external commands
        //  - The card can now perform cryptographic operations
        if (nextState == OPERATIONAL_STATE) {
            if (CheckApplicationState(INITIALIZATION_STATE)) {
                DeauthenticateAllPin(); // Make sure we get fully deauthenticated before changing state
                applicationState = OPERATIONAL_STATE;
                return true;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return false;
            }
        }

        // Entering termination state:
        //  - The card no longer accepts cryptographic and write commands
        if (nextState == TERMINATION_STATE) {
            if (CheckApplicationState(OPERATIONAL_STATE)) {
                applicationState = TERMINATION_STATE;
                return true;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return false;
            }
        }

        // Something went wrong!
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return false;
    }

    public void DeauthenticateAllPin() {
        pin_pin.reset();
        puk_puk.reset();
        // Deauthenticate admin key
        SetAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED);
        // Clear shared key
        Util.arrayFillNonAtomic(sharedKey, (short) 0,   (short) sharedKey.length, (byte)0x00);
        KeyReference[0] = null;
    }

    //This function check the user authentication by first checking the initialization mode followed by the PIN/PUK validation
    private boolean CheckUserAuthentication() {
        // No user authentication required during initialization mode
        if (CheckApplicationState(INITIALIZATION_STATE))
            return true;
        if (pin_pin.isValidated())
            return true;
        return puk_puk.isValidated();
    }

   // This function checks the type of authentication is either of CheckExternal Or MutualAuthentication using 
   // state of admin authentication if it is already in initialization mode, if yes return TRUE else false
    private boolean CheckExternalOrMutualAuthentication() {
        // No external/mutual authentication required during initialization mode
        if (CheckApplicationState(INITIALIZATION_STATE))
            return true;
        return CheckAdminAuthenticationState((byte) (EXTERNAL_AUTHENTICATED | MUTUAL_AUTHENTICATED));
    }

    // Sets the CRT in the key reference from the Control Reference Template 
    public void SetKeyReference(CRTKeyFile crt) {
        KeyReference[0] = crt;
    }

    /**
     * \
     // This function checks the value of ACL, and accordingly put restriction or no restriction.
     // If neither of above case, it will check for the value of acl for type of operation i.e. contact or contactless
     // After checking the type of operation the type of authentication required: may be PIN/PUK or external/mutual authentication)
     // Which is mandatory or not. In all these cases throws an SW_SECURITY_STATUS_NOT_SATISFIED exception if not allowed.
     */
    public void CheckACL(byte acl) {
        if(acl == (byte) 0x00) { // No restrictions.
            return;
        } else if(acl == (byte) 0xFF) { // Never.
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte SEID = (byte)(acl & (byte)0x0F);
        // Contact / contactless ACL
        if (SEID > 0) {
            byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
            if (SEID == 1) {
                // Contact operation
                if (protocol != APDU.PROTOCOL_MEDIA_USB && protocol != APDU.PROTOCOL_MEDIA_DEFAULT) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            } else if (SEID == 2) {
                // Contactless operation
                if (protocol != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A && protocol != APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }
        }
        byte authentication = (byte)(acl & (byte)0xF0);
        if(authentication  == (byte) 0x90) {
            // PIN/PUK required.
            if (CheckUserAuthentication()) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if ((byte)(authentication&(byte)0x90) == (byte)0x10) {
            // PIN/PUK can valid the ACL
            if (CheckUserAuthentication()) {
                return;
            }
            // Else continue
        }
        if(authentication  == (byte) 0xA0) {
            // External or mutual authentication mandatory
            if (CheckExternalOrMutualAuthentication()) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if((authentication&(byte)0xA0) == (byte)0x20) {
            // External or mutual authentication optional
            if (CheckExternalOrMutualAuthentication()) {
                return;
            }
            // Else continue
        }
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    /**
     * \brief Process the VERIFY APDU (INS = 20).
     *
     * This APDU is used to verify a PIN and authenticate the user. A counter is used
     * to limit unsuccessful tries (i.e. brute force attacks).
     *
     * \param apdu The APDU.
     *
     * \throw ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING.
     */
    public void processVerify(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        short lc;
        GidsPIN pin = null;
        GidsPIN puk = null;

        // P1P2 0001 only at the moment. (key-reference 01 = PIN)
        if(buf[ISO7816.OFFSET_P1] != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Deauthenticate PIN/PUK if the OFFSET_P2 is 0x82
        if (buf[ISO7816.OFFSET_P2] == (byte) 0x82) {
            // special resetting code for GIDS
            DeauthenticateAllPin();
            return;
        }

        // Try to get the PIN from the APDU buffer otherwise throw exception SW_REFERENCE_DATA_NOT_FOUND
        try {
            pin = GetPINByReference(buf[ISO7816.OFFSET_P2]);
        } catch(NotFoundException e) {
            ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
        }

        lc = apdu.setIncomingAndReceive();
        // Check the number of tries remaining if all tries are over then throw SW_FILE_INVALID exception.
        if (pin.getTriesRemaining() == (byte) 0) {
            // pin blocked
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        }

        // Lc might be 0, in this case the caller checks if verification is required.
        if((lc > 0 && (lc < pin.GetMinPINSize()) || lc > pin.GetMaxPINSize())) {
            ISOException.throwIt((short) (ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }

        // Caller asks if verification is needed.
        if(lc == 0) {
            if (CheckApplicationState(INITIALIZATION_STATE)) {
                // No verification required.
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
            } else {
                // Verification required, return remaining tries.
                ISOException.throwIt((short)(ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            }
        }

        // Check the PIN.
        if(!pin.check(buf, ISO7816.OFFSET_CDATA, (byte) lc)) {
            ISOException.throwIt((short)(ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
        }
    }

    /**
     * \brief Process the CHANGE REFERENCE DATA apdu (INS = 24).
     *
     * If the state is STATE_CREATION, we can set the PUK without verification.
     * The state will advance to STATE_INITIALISATION (i.e. the PUK must be set before the PIN).
     * In a "later" state the user must authenticate himself to be able to change the PIN.
     *
     * \param apdu The APDU.
     *
     * \throws ISOException SW_INCORRECT_P1P2, ISO7816.SW_WRONG_LENGTH, SW_PIN_TRIES_REMAINING.
     */
    public void processChangeReferenceData(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        GidsPIN pin = null;
        GidsPIN puk = null;

        lc = apdu.setIncomingAndReceive();

        if (p1 == (byte) 0x01) {
            try {
                pin = GetPINByReference(p2);
                puk = GetPUKByReference(p2);
            } catch(NotFoundException e) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }

            // Check length.
            pin.CheckLength((byte) lc);

            // Authentication not needed for the first PIN set
            if (!CheckApplicationState(INITIALIZATION_STATE)) {
                if (!pin.isValidated() && !puk.isValidated()) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
            }

            // Set PIN value
            pin.update(buf, ISO7816.OFFSET_CDATA, (byte)lc);
            if(CheckApplicationState(INITIALIZATION_STATE)) {
                pin.resetAndUnblock();
            }

        } else if (p1 == (byte) 0x00) {
            try {
                pin = GetPINByReference(buf[ISO7816.OFFSET_P2]);
                puk = GetPUKByReference(buf[ISO7816.OFFSET_P2]);
            } catch(NotFoundException e) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }

            // Check PIN lengths
            if(lc > (short)(pin.GetMaxPINSize() *2) || lc < (short)(pin.GetMinPINSize() *2)) {
                ISOException.throwIt((short) (ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            }

            byte currentPinLength = pin.GetCurrentPINLen();
            byte currentPukLength = puk.GetCurrentPINLen();
            // If the current PIN is very long and the tested PIN is very short, force the verification to decreate the remaining try count
            // do not allow the revelation of currentPinLength until pin.check is done
            if (lc < currentPinLength) {
                currentPinLength = (byte) lc;
            }
            if (pin.getTriesRemaining() == (byte) 0 && puk.getTriesRemaining() == (byte) 0 ) {
                // PIN blocked
                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
            }
            // Check the old PIN.
            if(!pin.check(buf, ISO7816.OFFSET_CDATA, currentPinLength)) {
                ISOException.throwIt((short)(ErrorCode.SW_PIN_TRIES_REMAINING | pin.getTriesRemaining()));
            }
            if(lc > (short)(pin.GetMaxPINSize() + currentPinLength) || lc < (short)(currentPinLength + pin.GetMinPINSize())) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            // Update PIN
            pin.update(buf, (short) (ISO7816.OFFSET_CDATA+currentPinLength), (byte) (lc - currentPinLength));
            pin.setAsAuthenticated();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    } // End processChangeReferenceData()




    /**
     * \brief Process the RESET RETRY COUNTER apdu (INS = 2C).
     *
     * This is used to unblock the PIN with the PUK and set a new PIN value.
     *
     * \param apdu The RESET RETRY COUNTER apdu.
     *
     * \throw ISOException SW_COMMAND_NOT_ALLOWED, ISO7816.SW_WRONG_LENGTH, SW_INCORRECT_P1P2,
     *			SW_PIN_TRIES_REMAINING.
     */
    public void	processResetRetryCounter(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;
        GidsPIN pin = null;

        if(!CheckApplicationState((byte)(OPERATIONAL_STATE | TERMINATION_STATE))) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        if(p1 == (byte) 0x02) {
            // This supposes a previous authentication of the admin via
            // external or mutual authentication
            lc = apdu.setIncomingAndReceive();
            // Only P2 = 80 is specified
            if (p2 != (byte) 0x80) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }
            try {
                pin = GetPINByReference(p2);
            } catch(NotFoundException e) {
                ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            }
            if (!CheckExternalOrMutualAuthentication()) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            // Check length.
            pin.CheckLength((byte) lc);
            // Set PIN value
            pin.update(buf, ISO7816.OFFSET_CDATA, (byte)lc);
            pin.resetAndUnblock();
            // Admin is deauthenticated at the end of the process
            DeauthenticateAllPin();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

    }

    /**
     * \brief Process the general authentication process
         
     */
    public void processGeneralAuthenticate(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        short lc;

        if(!CheckApplicationState((byte)(OPERATIONAL_STATE | TERMINATION_STATE))) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        // Followed by the correctness of P1P2 otherwise SW_INCORRECT_P1P2
        if(p1 != (byte) 0x00 || p2 != (byte) 0x00 ) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Bytes received must be Lc.
        lc = apdu.setIncomingAndReceive();

        // Check data is valid or not 
        short innerPos = 0, innerLen = 0;
        if (buf[ISO7816.OFFSET_CDATA] != (byte) 0x7C) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Try to get the length and position from the APDU
        try {
            innerLen = UtilTLV.decodeLengthField(buf, (short) (ISO7816.OFFSET_CDATA+1));
            innerPos = (short) (ISO7816.OFFSET_CDATA + 1 + UtilTLV.getLengthFieldLength(buf, (short) (ISO7816.OFFSET_CDATA+1)));
        } catch (InvalidArgumentsException e1) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // Inner functions never return if their input tag is found
        // Check for external challenge followed by challenge response, if any of them is successful, authentication is done otherwise
        if (CheckForExternalChallenge(apdu, buf, innerPos, innerLen)) {
            return;
        }
        if (CheckForChallengeResponse(apdu, buf, innerPos, innerLen)) {
            return;
        }
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    /**
     * \brief Clear the data used for admin authentication
     // For Security, we have to clear all the field by putting/assigning 0 (Zero) 
     */
    private void ClearChallengeData() {
        Util.arrayFillNonAtomic(ExternalChallenge, (short) 0,   (short) ExternalChallenge.length, (byte)0x00);
        Util.arrayFillNonAtomic(CardChallenge, (short) 0,   (short) CardChallenge.length, (byte)0x00);
        Util.arrayFillNonAtomic(buffer, (short) 0,   (short) buffer.length, (byte)0x00);
    }

    /**
     * \brief Handle the first part of the general authenticate APDU
     */
    private boolean CheckForExternalChallenge(APDU apdu, byte[] buf, short innerPos, short innerLen) {
        short pos = 0, len = 0;
        try {
            pos = UtilTLV.findTag(buf, innerPos, innerLen, (byte) 0x81);
            if (buf[(short) (pos+1)] == 0) {
                // Zero length TLV allowed
                len = 0;
            } else {
                len = UtilTLV.decodeLengthField(buf, (short)(pos+1));
            }
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (NotFoundException e) {
            return false;
        }

        SetAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED);

        pos += 1 + UtilTLV.getLengthFieldLength(buf, (short)(pos+1));
        // Challenge size = 16 => mutual authentication
        // Challenge size = 0 => external authentication, request for a challenge
        if (len == (short)16) {
            Util.arrayCopyNonAtomic(buf, pos, ExternalChallenge, (short) 0, len);
            // Generate a 16 bytes challenge
            SetAdminAuthenticationState(MUTUAL_CHALLENGE);
        } else if (len == 0) {
            // Generate a 8 bytes challenge
            len = 8;
            SetAdminAuthenticationState(EXTERNAL_CHALLENGE);
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        randomData.setSeed(buf, pos, len);
        randomData.generateData(CardChallenge, (short) 0, len);

        pos = 0;
        buf[pos++] = (byte) 0x7C;
        buf[pos++] = (byte) (len + 2);
        buf[pos++] = (byte) 0x81;
        buf[pos++] = (byte) (len);
        Util.arrayCopyNonAtomic(CardChallenge, (short) 0, buf, pos, len);
        apdu.setOutgoingAndSend((short)0, (short) (len + 4));
        return true;
    }

    /**
     * \brief Handle the second part of the general authenticate APDU
     */
    private boolean CheckForChallengeResponse(APDU apdu, byte[] buf, short innerPos, short innerLen) {
        short pos = 0, len = 0;
        try {
            pos = UtilTLV.findTag(buf, innerPos, innerLen, (byte) 0x82);
            len = UtilTLV.decodeLengthField(buf, (short)(pos+1));
        } catch (InvalidArgumentsException e) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } catch (NotFoundException e) {
            return false;
        }

        pos += 1 + UtilTLV.getLengthFieldLength(buf, (short)(pos+1));
        if (len > (short)40) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        if (CheckAdminAuthenticationState(MUTUAL_CHALLENGE)) {
            if (len != (short) 40) {
                SetAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
         
            Cipher cipherDES = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
            DESKey key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
            key.setKey(((CRTKeyFile)(KeyReference[0])).GetSymmectricKey(), (short) 0);

            // Decrypt message
            cipherDES.init(key, Cipher.MODE_DECRYPT);
            cipherDES.doFinal(buf, pos, len, buffer, (short) 0);

            if (Util.arrayCompare(buffer, (short) 0, CardChallenge, (short) 0, (short) 16) != 0) {
                SetAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            if (Util.arrayCompare(buffer, (short) 16, ExternalChallenge, (short) 0, (short) 16) != 0) {
                SetAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            // Check the padding of Z1 (7 bytes)
            if (buffer[(short)39] != (byte) 0x80) {
                SetAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            // Copy Z1 for later use
            Util.arrayCopy(buffer, (short) 32, sharedKey, (short) 0, (short) 7);

            // Generate Z2
            RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            randomData.generateData(sharedKey, (short) 7, (short) 7);

            // Copy R1
            Util.arrayCopy(ExternalChallenge, (short) 0, buffer, (short) 0, CHALLENGE_LENGTH);
            // Copy R2
            Util.arrayCopy(CardChallenge, (short) 0, buffer, CHALLENGE_LENGTH, CHALLENGE_LENGTH);
            // Copy Z2
            Util.arrayCopy(sharedKey, (short) 7, buffer, (short) (CHALLENGE_LENGTH * 2), (short) 7);
            // Set padding for Z2 (7 bytes)
            buffer[(short) 39] = (byte) 0x80;

            cipherDES.init(key, Cipher.MODE_ENCRYPT);
            cipherDES.doFinal(buffer, (short) 0, (short)40, buf, (short) 4);

            // Header
            buf[0] = (byte) 0x7C;
            buf[1] = (byte) 0x2A;
            buf[2] = (byte) 0x82;
            buf[3] = (byte) 0x28;
            
            // Avoid replay attack
            SetAdminAuthenticationState(MUTUAL_AUTHENTICATED);

            apdu.setOutgoing();
            apdu.setOutgoingLength((short)44);
            apdu.sendBytes((short) 0, (short)44);

        } else if (CheckAdminAuthenticationState(EXTERNAL_CHALLENGE)) {
            Cipher cipherDES = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
            DESKey key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
            key.setKey(((CRTKeyFile)(KeyReference[0])).GetSymmectricKey(), (short) 0);

            // Decrypt message
            cipherDES.init(key, Cipher.MODE_DECRYPT);
            cipherDES.doFinal(buf, pos, len, buffer, (short) 0);

            if (Util.arrayCompare(buffer, (short) 0, CardChallenge, (short) 0, (short) 8) != 0) {
                SetAdminAuthenticationState(ADMIN_NOT_AUTHENTICATED);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Avoid replay attack
            SetAdminAuthenticationState(EXTERNAL_AUTHENTICATED);
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        return true;
    }

    /**
     * \brief Return information regarding the PIN
     // 
     */
    public void returnPINStatus(APDU apdu, short id) {
        byte[] buf = apdu.getBuffer();
        GidsPIN pin = null;
        switch(id) {
        default:
            ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            break;
        case (short) 0x7F71:
        case (short) 0x7F72:
            pin = pin_pin;
            break;
        }
       // APDU is generated with the status of PIN which include the number of tries remaining and the try limit.
        Util.setShort(buf, (short) 0, id);
        buf[2] = (byte) 0x06;
        buf[3] = (byte) 0x97;
        buf[4] = (byte) 0x01;
        buf[5] = pin.getTriesRemaining();
        buf[6] = (byte) 0x93;
        buf[7] = (byte) 0x01;
        buf[8] = pin.getTryLimit();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)9);
        apdu.sendBytes((short) 0, (short) 9);
    }
 
 public void returnPUKStatus(APDU apdu, short id) {
        byte[] buf = apdu.getBuffer();
        GidsPIN puk = null;
        switch(id) {
        default:
            ISOException.throwIt(ErrorCode.SW_REFERENCE_DATA_NOT_FOUND);
            break;
        case (short) 0x7F71:
        case (short) 0x7F72:
            puk = puk_puk;
            break;
        }
       // APDU is generated with the status of PIN which include the number of tries remaining and the try limit.
        Util.setShort(buf, (short) 0, id);
        buf[2] = (byte) 0x06;
        buf[3] = (byte) 0x97;
        buf[4] = (byte) 0x01;
        buf[5] = puk.getTriesRemaining();
        buf[6] = (byte) 0x93;
        buf[7] = (byte) 0x01;
        buf[8] = puk.getTryLimit();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)9);
        apdu.sendBytes((short) 0, (short) 9);
    }
}
