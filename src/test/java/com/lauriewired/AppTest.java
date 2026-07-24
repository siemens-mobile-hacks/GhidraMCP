package com.lauriewired;

import java.io.File;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.cparser.C.CParser;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.util.data.DataTypeParser;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testNativeCAndDataTypeParsers() throws Exception
    {
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            String ghidraHome = System.getenv("GHIDRA_HOME");
            if (ghidraHome == null || ghidraHome.isEmpty()) ghidraHome = "/opt/ghidra";
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(ghidraHome)), configuration);
        }
        try (StandAloneDataTypeManager dtm = new StandAloneDataTypeManager("test")) {
            CParser parser = new CParser(dtm, true, new DataTypeManager[0]);
            parser.parse("typedef unsigned int mcp_u32; " +
                "struct McpHeader { mcp_u32 flags; char name[8]; }; ");

            DataType structType = dtm.getDataType("/McpHeader");
            assertNotNull(structType);
            assertTrue(structType instanceof Structure);
            assertEquals(2, ((Structure) structType).getNumDefinedComponents());

            DataTypeParser typeParser = new DataTypeParser(
                dtm, dtm, null, DataTypeParser.AllowedDataTypes.ALL);
            DataType pointerType = typeParser.parse("McpHeader *");
            assertNotNull(pointerType);
            assertTrue(pointerType.getDisplayName().contains("McpHeader"));
        }
    }
}
