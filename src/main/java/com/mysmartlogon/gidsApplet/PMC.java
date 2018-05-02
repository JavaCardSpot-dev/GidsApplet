package com.mysmartlogon.gidsApplet; // TODO: change to your applet package

/**
 * Utility class for performance profiling constants
* @author Petr Svenda
 */
public class PMC {
    public static final short PERF_START        = (short) 0x0001;
            
    public static final short TRAP_UNDEFINED 	= (short) 0xffff;

//### PLACEHOLDER PMC CONSTANTS
    public static final short TRAP_ACTIVATEFILE = (short) 0x7770;
    public static final short TRAP_ACTIVATEFILE_1 = (short) (TRAP_ACTIVATEFILE + 1);
    public static final short TRAP_ACTIVATEFILE_COMPLETE = TRAP_ACTIVATEFILE;
}
