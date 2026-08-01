package com.lauriewired;

import java.lang.reflect.Proxy;

import ghidra.program.model.listing.Data;
import junit.framework.TestCase;

public class DisassemblyGuardTest extends TestCase {

    public void testUndefinedDataDoesNotBlockDisassembly() {
        assertFalse(GhidraMCPPlugin.isDefinedData(dataWithDefinedState(false)));
    }

    public void testDefinedDataBlocksDisassembly() {
        assertTrue(GhidraMCPPlugin.isDefinedData(dataWithDefinedState(true)));
    }

    public void testMissingCodeUnitDoesNotBlockDisassembly() {
        assertFalse(GhidraMCPPlugin.isDefinedData(null));
    }

    private Data dataWithDefinedState(boolean defined) {
        return (Data) Proxy.newProxyInstance(
            Data.class.getClassLoader(),
            new Class<?>[] { Data.class },
            (proxy, method, args) -> {
                if (method.getName().equals("isDefined")) {
                    return defined;
                }
                throw new UnsupportedOperationException(method.getName());
            });
    }
}
