/*
 * This test class is to check generic cryptographic properties of the application by the means of the cryptographic 
 * goal 'authenticity'. 
 */
package com.mysmartlogon.gidsAppletTests;

import org.junit.Before;
import org.junit.Test;

public class CryptoTest extends GidsBaseTestClass {

    @Before
    public void setUp() throws Exception {
        super.setUp();
        createcard();
    }

    @Test
    public void generateKeyAndReadItThenDeleteIt() {
        // Authenticate
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
        execute("00 A4 00 0C 02 3F FF");
        // Generate new key
        execute("00 E0 00 00 49 62 47 82 01 18 83 02 B0 81 8C 05 8F 10 10 10 00 A5 37 B8 09 80 01 06 83 01 81 95 01 40 B8 09 80 01 86 83 01 81 95 01 40 B8 09 80 01 46 83 01 81 95 01 40 B6 09 80 01 16 83 01 81 95 01 40 B6 09 80 01 56 83 01 81 95 01 40");
        // Execute("00 A4 00 0C 02 B0 81");
        execute("00 44 00 00 00");
        // Generate asymetric key
        execute("00 47 00 00 08 AC 06 80 01 06 83 01 81");
        execute("00 A4 00 0C 02 B0 81");
        // Read the public key
        execute("00 CB 3F FF 0A 70 08 84 01 81 A5 03 7F 49 80 00");
        // Keymap file
        execute("00 DB A0 00 10 DF 20 0D 01 01 00 00 00 06 9A 81 B0 FF FF 00 00");
        // Cmapfile
        execute("00 DB A0 10 59 DF 23 56 37 00 64 00 39 00 64 00 34 00 35 00 66 00 38 00 2D 00 66 00 36 00 64 00 66 00 2D 00 34 00 30 00 35 00 38 00 2D 00 39 00 65 00 61 00 39 00 2D 00 36 00 37 00 35 00 33 00 31 00 65 00 65 00 38 00 32 00 36 00 61 00 35 00 00 00 00 00 00 00 00 00 03 00 00 00 00 04");
        // Deauthenticate
        execute("00 20 00 82");

        // Authenticate
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
        execute("00 A4 00 0C 02 3F FF");
        // Select key
        execute("00 A4 00 0C 02 B0 81");
        // Delete it
        execute("00 E4 00 00");
        // Delete cmapfile
        execute("00 DB A0 00 03 DF 20 00");
        // Update cardcf file
        execute("00 DB A0 10 09 DF 22 06 00 00 02 00 06 00");
        // Clean cmapfile
        execute("00 DB A0 10 59 DF 23 56 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        // Deauthenticate
        execute("00 20 00 82");
    }
}
