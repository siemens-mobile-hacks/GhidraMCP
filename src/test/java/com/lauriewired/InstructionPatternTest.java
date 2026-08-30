package com.lauriewired;

import java.util.List;

import junit.framework.TestCase;

public class InstructionPatternTest extends TestCase {

    public void testFormatsExactWildcardNibbleAndBitTokens() {
        assertEquals("D8 ?? A? ?5 [10..01..]",
            GhidraMCPPlugin.formatInstructionPattern(
                "11011000........1010........010110..01.."));
    }

    public void testParsesSupportedPatternForms() {
        GhidraMCPPlugin.ParsedInstructionPattern pattern =
            GhidraMCPPlugin.parseInstructionPattern("D8A0 ?? A? ?5 [10..01..]");

        assertBytesEqual(new int[] { 0xd8, 0xa0, 0x00, 0xa0, 0x05, 0x84 }, pattern.value);
        assertBytesEqual(new int[] { 0xff, 0xff, 0x00, 0xf0, 0x0f, 0xcc }, pattern.mask);
    }

    public void testGeneratedPatternRoundTripsWithoutLosingBits() {
        String binary = "11011000........1010........010110..01..";
        String formatted = GhidraMCPPlugin.formatInstructionPattern(binary);
        GhidraMCPPlugin.ParsedInstructionPattern parsed =
            GhidraMCPPlugin.parseInstructionPattern(formatted);

        assertEquals(binary, toBinaryPattern(parsed));
    }

    public void testRejectsMalformedAndAllWildcardPatterns() {
        assertInvalid("GG");
        assertInvalid("[1010]");
        assertInvalid("?? ??");
    }

    public void testParsesAndDeduplicatesSelectiveOperandMasks() {
        List<int[]> selectors = GhidraMCPPlugin.parseOperandSelectors("0:1, 2:0,0:1");
        assertEquals(2, selectors.size());
        assertEquals(0, selectors.get(0)[0]);
        assertEquals(1, selectors.get(0)[1]);
        assertEquals(2, selectors.get(1)[0]);
        assertEquals(0, selectors.get(1)[1]);
    }

    public void testRejectsMalformedOperandMaskSelector() {
        try {
            GhidraMCPPlugin.parseOperandSelectors("0,1");
            fail("Expected invalid operand selector");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private void assertInvalid(String pattern) {
        try {
            GhidraMCPPlugin.parseInstructionPattern(pattern);
            fail("Expected invalid pattern: " + pattern);
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private void assertBytesEqual(int[] expected, byte[] actual) {
        assertEquals(expected.length, actual.length);
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], actual[i] & 0xff);
        }
    }

    private String toBinaryPattern(GhidraMCPPlugin.ParsedInstructionPattern pattern) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < pattern.value.length; i++) {
            for (int bit = 7; bit >= 0; bit--) {
                int bitMask = 1 << bit;
                result.append((pattern.mask[i] & bitMask) == 0
                    ? '.' : (pattern.value[i] & bitMask) == 0 ? '0' : '1');
            }
        }
        return result.toString();
    }
}
