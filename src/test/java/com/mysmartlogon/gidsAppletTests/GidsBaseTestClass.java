/*
 * This class is to create the succesfull commands and command chains to be used by other test initally.
 */

package com.mysmartlogon.gidsAppletTests;

import static org.junit.Assert.*;

import java.util.*;

import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;

import org.junit.Before;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import com.mysmartlogon.gidsApplet.GidsApplet;

import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public abstract class GidsBaseTestClass {
    final boolean USE_SIMULATOR = false;
    private final int TARGET_READER_INDEX = 0;

    static Card physicalCard = null;
    JavaxSmartCardInterface simulator = null;
    private boolean display = false;

    @Before
    public void setUp() throws Exception {
        perfMap.clear();

        // Using simulator
        if (USE_SIMULATOR) {

            // 1. Create simulator
            byte[] TEST_APPLET_AID_BYTES = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x03, (byte) 0x97, 0x42, 0x54, 0x46, 0x59};
            AID TEST_APPLET_AID = new AID(TEST_APPLET_AID_BYTES, (short) 0, (byte) TEST_APPLET_AID_BYTES.length);
            simulator = new JavaxSmartCardInterface();

            // 2. Install applet
            simulator.installApplet(TEST_APPLET_AID, GidsApplet.class);

            // 3. Select applet
            simulator.selectApplet(TEST_APPLET_AID);

        // Using real card
        } else {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = new ArrayList<>();

            System.out.print("Installing applet...");
                try {
                    Process p1 = Runtime.getRuntime().exec("java -jar ext/gp.jar -uninstall build/javacard/GidsApplet.cap");
                    p1.waitFor();
                    Process p2 = Runtime.getRuntime().exec("java -jar ext/gp.jar -install build/javacard/GidsApplet.cap -default");
                    p2.waitFor();
                    System.out.println(" Done.");
                } catch (Exception e) {
                    e.printStackTrace();
                    fail("Failed to install applet.");
            }

            boolean card_found = false;
            CardTerminal terminal = null;

            System.out.print("Looking for card terminals...");
            try {
                for (CardTerminal t : factory.terminals().list()) {
                    terminals.add(t);
                    if (t.isCardPresent()) {
                        card_found = true;
                    }
                }
                System.out.println(" Done.");
            } catch (Exception e) {
                fail("Failed to access card terminals.");
            }

            if (card_found) {
                System.out.println("Cards found: " + terminals);

                terminal = terminals.get(TARGET_READER_INDEX); // Prioritize physical card over simulations

                System.out.print("Connecting to card...");
                physicalCard = terminal.connect("*"); // Connect to the card
                if (physicalCard == null) fail("Failed to connect to card.");
                System.out.println(" Done.");

                // Select applet
                // Applet ID = A0 00 00 03 97 42 54 46 59
                System.out.print("Selecting applet...");
                execute("00 A4 04 00 09 A0 00 00 03 97 42 54 46 59 00");
                System.out.println(" Done.");

            } else {
                fail("Failed to find physical card.");
            }

        }
    }

    protected void createcard() {

        // Display = false;
        execute("00A4040409A0000003974254465900");

        // PIN 0x6C63
        execute("00240180083132333435363738");

        execute("00E000000E620C8201398302A0008C03033000");
        execute("0044000000");
        execute("00E000000E620C8201398302A0108C03033000");
        execute("0044000000");
        execute("00E000000E620C8201398302A0118C030330FF");
        execute("0044000000");
        execute("00E000000E620C8201398302A0128C03032000");
        execute("0044000000");
        execute("00E000000E620C8201398302A0138C03033030");
        execute("0044000000");
        execute("00E000000E620C8201398302A0148C03032020");
        execute("0044000000");
        // Create admin key
        execute("00 E0 00 00 1C 62 1A 82 01 18 83 02 B0 80 8C 04 87 00 20 FF A5 0B A4 09 80 01 02 83 01 80 95 01 C0");
        execute("0044000000");
        // Set admin key
        execute("00DB3FFF267024840180A51F87180102030405060708010203040506070801020304050607088803B073DC");
        // Set masterfile
        execute("00DBA00091DF1F818D016d736370000000000000000000000000000000000000000000a00000000000000000000000636172646964000000000020df000012a00000000000000000000000636172646170707300000021df000010a00000000000000000000000636172646366000000000022df000010a000006d7363700000000000636d617066696c6500000023df000010a00000");
        execute("00 DB A0 10 0B DF 21 08 6d 73 63 70 00 00 00 00");
        execute("00 DB A0 10 09 DF 22 06 00 00 00 00 00 00");
        execute("00 DB A0 10 03 DF 23 00");
        execute("00 DB A0 10 13 DF 20 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");

        // Activate
        execute("00 A4 00 0C 02 3F FF");
        execute("00 44 00 00 00");
        //display = true;
    }

    protected void authenticateGeneral() {
        byte[] key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
        authenticateGeneral(key, true);
    }

    protected void authenticateMutual() {
        byte[] key = DatatypeConverter.parseHexBinary("010203040506070801020304050607080102030405060708");
        authenticateMutual(key, true);
    }

    protected void authenticatePin() {
        execute("00 20 00 80 08 31 32 33 34 35 36 37 38");
    }
    protected void deauthenticate() {
        execute("00 20 00 82 00");
    }

    protected void authenticateMutual(byte[] key, boolean successexpected) {
        byte[] myChallenge= new byte [16], globalchallenge = new byte[40], challengeresponse = new byte[40];
        byte[] cardChallenge;
        Cipher cipherDES = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        DESKey deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
        deskey.setKey(key, (short) 0);
        new Random().nextBytes(myChallenge);
        // Select admin key
        execute("00 22 81 A4 03 83 01 80");
        // Get a challenge
        ResponseAPDU response = execute("00 87 00 00 14 7C 12 81 10" + DatatypeConverter.printHexBinary(myChallenge) + "00");
        if (!Arrays.equals(Arrays.copyOfRange(response.getBytes(), 0, 4), new byte[] {0x7C,0x12,(byte) 0x81,0x10})) {
            fail("not a challenge:" + DatatypeConverter.printHexBinary(response.getBytes()));
        }
        // Compute the response
        cardChallenge = Arrays.copyOfRange(response.getBytes(), 4, 20);
        // Solve challenge
        // R2
        System.arraycopy(cardChallenge, 0, globalchallenge, 0, 16);
        // R1
        System.arraycopy(myChallenge, 0, globalchallenge, 16, 16);
        // Keep Z1 random
        globalchallenge[(short)39] = (byte) 0x80;
        cipherDES.init(deskey, Cipher.MODE_ENCRYPT);
        cipherDES.doFinal(globalchallenge, (short) 0, (short)40, challengeresponse, (short) 0);
        // Send the response
        String command = "00 87 00 00 2C 7C 2A 82 28" + DatatypeConverter.printHexBinary(challengeresponse);
        
        ResponseAPDU responseAPDU = execute(command, true);
        
        if (!successexpected)
        {
            if(responseAPDU.getSW() != 0x6982) {
                fail("expected: " + Integer.toHexString(0x6982) + " but was: " + Integer.toHexString(responseAPDU.getSW()));
            }
            return;
        }
        if(responseAPDU.getSW() != 0x9000) {
            fail("expected: " + Integer.toHexString(0x9000) + " but was: " + Integer.toHexString(responseAPDU.getSW()));
        }
        byte[] cardresponse = responseAPDU.getBytes();
        if (!Arrays.equals(Arrays.copyOfRange(cardresponse, 0, 4), new byte[] {0x7C,0x2A,(byte)0x82,0x28}))
        {
            fail("header verification failed");
        }
        byte[] decryptedCardResponse = new byte[40];
        cipherDES.init(deskey, Cipher.MODE_DECRYPT);
        cipherDES.doFinal(cardresponse, (short) 4, (short)40, decryptedCardResponse, (short) 0);
       
        
        if (!Arrays.equals(Arrays.copyOfRange(decryptedCardResponse, 0, 16), myChallenge)) {
            fail("R1 verification failed");
        }
        
        if (!Arrays.equals(Arrays.copyOfRange(decryptedCardResponse, 16, 32), cardChallenge)) {
            fail("R2 verification failed");
        }
        if (decryptedCardResponse[(short)39] != (byte) 0x80) {
            fail("padding failed");
        }
        
    }

    protected void authenticateGeneral(byte[] key, boolean successexpected) {
        byte[] challenge, challengeresponse = new byte[8];
        Cipher cipherDES = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
        DESKey deskey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
        deskey.setKey(key, (short) 0);

        // Select admin key
        execute("00 22 81 A4 03 83 01 80");
        // Get a challenge
        ResponseAPDU response = execute("00 87 00 00 04 7C 02 81 00 00");
        if (!Arrays.equals(Arrays.copyOfRange(response.getBytes(), 0, 4), new byte[] {0x7C,0x0A,(byte) 0x81,0x08})) {
            fail("not a challenge:" + DatatypeConverter.printHexBinary(response.getBytes()));
        }
        // Compute the response
        challenge = Arrays.copyOfRange(response.getBytes(), 4, 12);
        // Solve challenge
        cipherDES.init(deskey, Cipher.MODE_ENCRYPT);
        cipherDES.doFinal(challenge, (short) 0, (short)8, challengeresponse, (short) 0);
        // Send the response
        execute("00 87 00 00 0C 7C 0A 82 08" + DatatypeConverter.printHexBinary(challengeresponse), (successexpected?0x9000: 0x6982));
    }

    protected void execute(String command, String expectedresponse) {
        byte[] expected = DatatypeConverter.parseHexBinary(expectedresponse.replaceAll("\\s",""));
        ResponseAPDU response = execute(command, 0xFFFF & Util.makeShort(expected[expected.length-2],expected[expected.length-1]));
        if (!Arrays.equals(response.getBytes(), expected)) {
            fail("expected: " + expectedresponse.replaceAll("\\s","") + " but was: " + DatatypeConverter.printHexBinary(response.getBytes()));
        }
    }

    protected ResponseAPDU execute(String Command) {
        return execute(Command,0x9000);
    }

    protected ResponseAPDU execute(String Command, int expectedReturn) {
        ResponseAPDU response = execute(Command, display);
        if(response.getSW() != expectedReturn) {
            fail("expected: " + Integer.toHexString(expectedReturn) + " but was: " + Integer.toHexString(response.getSW()));
        }
        return response;
    }

    private ResponseAPDU execute(String Command, boolean display) {
        ResponseAPDU response = null;
        Command = Command.replaceAll("\\s","");
        if (display) System.out.println(Command);

        // Using simulator
        if (USE_SIMULATOR) {
            response = simulator.transmitCommand(new CommandAPDU(DatatypeConverter.parseHexBinary(Command)));

        // Using real card
        } else {
            try {
                response = physicalCard.getBasicChannel().transmit(new CommandAPDU(DatatypeConverter.parseHexBinary(Command)));
            } catch (CardException exception) {
                fail("Couldn't transmit APDU command to physical card.");
            }
        }

        if (display) System.out.println(DatatypeConverter.printHexBinary(response.getBytes()));
        return response;
    }

    protected ResponseAPDU executePerf(String command) {
        return executePerf(command, 0x9000);
    }

    protected ResponseAPDU executePerf(String command, int expectedReturn) {
        long timeBefore = System.currentTimeMillis();
        ResponseAPDU res = execute(command, expectedReturn);
        long timeAfter = System.currentTimeMillis();
        String insKey = command.replaceAll("\\s","").substring(2,4);
        if (!perfMap.containsKey(insKey))
            perfMap.put(insKey, new LinkedList<Long>());
        perfMap.get(insKey).add(timeAfter - timeBefore);
        return res;
    }

    protected void printPerf () {
        // Print results
        for (String insKey : perfMap.keySet()) {
            List<Long> timeList = perfMap.get(insKey);
            System.out.print(String.format("> %s : ", insKey));
            long timeTotal = 0;
            for (long time : timeList) {
                //System.out.print(String.format("%d ", time));
                timeTotal += time;
            }
            System.out.println(String.format("(mean = %d) (samples = %d)", timeTotal / timeList.size(), timeList.size()));
        }
    }

    private Map<String, List<Long>> perfMap = new HashMap<String, List<Long>>();
}
