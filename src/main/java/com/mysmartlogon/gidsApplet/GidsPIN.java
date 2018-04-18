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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.PIN;

/**
 * \brief The GidsPIN class.
 * This Class GidsPIN is extends OwnerPIN Class i.e. inherit/override code and extend functionality from this Class . and 
 implements interface PIN, i.e. implements the function/methods of PIN.
 */

public class GidsPIN extends OwnerPIN implements PIN {


    private byte currentPINLen = 0;     // Length of Current PIN
    private byte minPINSize = 0;        // Minimum Pin Size
    private byte maxPINSize = 0;        // Maximum PIN Size
    private byte tryLimit = 0;          // Maximum Limit for PIN Try

    // Constructor with three arguments, which are declared above
    // It sets the values passed as argument.
    public GidsPIN(byte tryLimit, byte maxPINSize, byte minPINSize) {
        super(tryLimit, maxPINSize);
        this.maxPINSize = maxPINSize;
        this.tryLimit = tryLimit;
        this.minPINSize = minPINSize;
    }
    
    // Four functions to get one variable each from this class.
    public byte GetCurrentPINLen() {
        return currentPINLen;
    }

    public byte GetMinPINSize() {
        return minPINSize;
    }

    public byte GetMaxPINSize() {
        return maxPINSize;
    }
    
    public byte getTryLimit() {
        return tryLimit;
    }

    /*
    // This function checks whether the length of PIN is outside of the Range ( minPINSize and maxPINSize), 
    // and if yes, throws an exception Wrong Length
    */
    public void CheckLength(byte len) {
        if (len < minPINSize || len > maxPINSize) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }
    
    public void setAsAuthenticated() {
        this.setValidatedFlag(true);
    }

    // This function updates the PIN
    public void update(byte[] pin,
                       short offset,
                       byte length) {
        super.update(pin, offset, length);
        currentPINLen = length;
    }

    
}
