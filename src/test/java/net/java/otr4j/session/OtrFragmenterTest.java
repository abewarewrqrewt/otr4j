/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.io.SerializationUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for OTR Fragmenter.
 *
 * @author Danny van Heumen
 */
public class OtrFragmenterTest {

	private static final String specV3MessageFull = "?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==.";

	private static final String[] specV3MessageParts199 = new String[] {
		"?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,",
		"?OTR|5a73a599|27e31597,00002,00003,jPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2i,",
		"?OTR|5a73a599|27e31597,00003,00003,pkTtquknfx6HodLvk3RAAAAAA==.,"
	};

	private static final String specV2MessageFull = "?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOrJvPUerB9mtf4bqQDFthfoz/XepysnYuReHHEXKe+BFkaEoMNGiBl4TCLZx72DvmZwKCewWRH1+W66ggrXKw2VdVl+vLsmzxNyWChGLfBTL5/3SUF09BfmCEl03Ckk7htAgyAQcBf90RJznZndv7HwVAi3syupi0sQDdOKNPyObR5FRtqyqudttWmSdmGCGFcZ/fZqxQNsHB8QuYaBiGL7CDusES+wwfn8Q7BGtoJzOPDDx6KyIyox/flPx2DZDJIZrMz9b0V70a9kqKLo/wcGhvHO6coCyMxenBAacLJ1DiINLKoYOoJTM7zcxsGnvCxaDZCvsmjx3j8Yc5r3i3ylllCQH2/lpr/xCvXFarGtG7+wts+UqstS9SThLBQ9Ojq4oPsX7HBHKvq19XU3/ChIgWMy+bczc5gpkC/eLAIGfJ0D5DJsl68vMXSmCoFK0HTwzzNa7lnZK4IutYPBNBCv0pWORQqDpskEz96YOGyB8+gtpFgCrkuV1bSB9SRVmEBfDtKPQFhKowAAAAA=.";

	private static final String[] specV2MessageParts318 = new String[] {
		"?OTR,1,3,?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOr,",
		"?OTR,2,3,JvPUerB9mtf4bqQDFthfoz/XepysnYuReHHEXKe+BFkaEoMNGiBl4TCLZx72DvmZwKCewWRH1+W66ggrXKw2VdVl+vLsmzxNyWChGLfBTL5/3SUF09BfmCEl03Ckk7htAgyAQcBf90RJznZndv7HwVAi3syupi0sQDdOKNPyObR5FRtqyqudttWmSdmGCGFcZ/fZqxQNsHB8QuYaBiGL7CDusES+wwfn8Q7BGtoJzOPDDx6KyIyox/flPx2DZDJIZrMz9b0V70a9kqKLo/wcGhvHO6coCyMxenBAacLJ1DiI,",
		"?OTR,3,3,NLKoYOoJTM7zcxsGnvCxaDZCvsmjx3j8Yc5r3i3ylllCQH2/lpr/xCvXFarGtG7+wts+UqstS9SThLBQ9Ojq4oPsX7HBHKvq19XU3/ChIgWMy+bczc5gpkC/eLAIGfJ0D5DJsl68vMXSmCoFK0HTwzzNa7lnZK4IutYPBNBCv0pWORQqDpskEz96YOGyB8+gtpFgCrkuV1bSB9SRVmEBfDtKPQFhKowAAAAA=.,"
	};

	private final int senderTag = 0x5a73a599;
	private final int receiverTag = 0x27e31597;
	private final SessionID sessionID = new SessionID("bob@chatnetwork", "alice@chatnetwork", "chat");

	@Test(expected = NullPointerException.class)
	@SuppressWarnings("ResultOfObjectAllocationIgnored")
	public void testNullHostConstruction() {
		new OtrFragmenter(null, sessionID, 0, 0);
	}

	@Test(expected = NullPointerException.class)
    public void testNullSessionID() {
        final OtrEngineHost host = host(100);
        new OtrFragmenter(host, null, 0, 0);
    }

	@Test
	@SuppressWarnings("ResultOfObjectAllocationIgnored")
	public void testConstruction() {
		new OtrFragmenter(host(100), sessionID, 0, 0);
	}

	@Test
	public void testFragmentNullInstructionsCompute() throws IOException {
		final OtrEngineHost host = mock(OtrEngineHost.class);
		when(host.getMaxFragmentSize(any(SessionID.class))).thenReturn(Integer.MAX_VALUE);
		final String message = "Some message that shouldn't be fragmented.";

		final int version = 3;
		final OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		final int number = fragmenter.numberOfFragments(version, message);
		assertEquals(1, number);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testFragmentNullInstructionsFragment() throws IOException {
		final OtrEngineHost host = mock(OtrEngineHost.class);
		when(host.getMaxFragmentSize(any(SessionID.class))).thenReturn(Integer.MAX_VALUE);
		final String message = "Some message that shouldn't be fragmented.";
		
		final OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		final String[] fragments = fragmenter.fragment(3, message);
		assertArrayEquals(new String[] {message}, fragments);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testUnlimitedSizedFragmentToSingleMessage() throws IOException {
		final OtrEngineHost host = host(Integer.MAX_VALUE);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		String[] msg = fragmenter.fragment(3, specV3MessageFull);
		assertArrayEquals(new String[] {specV3MessageFull}, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testUnlimitedSizedFragmentToSingleMessageV2() throws IOException {
		final OtrEngineHost host = host(Integer.MAX_VALUE);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		String[] msg = fragmenter.fragment(2, specV2MessageFull);
		assertArrayEquals(new String[] {specV2MessageFull}, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testLargeEnoughFragmentToSingleMessage() throws IOException {
		final OtrEngineHost host = host(354);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		String[] msg = fragmenter.fragment(3, specV3MessageFull);
		assertArrayEquals(new String[] {specV3MessageFull}, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testLargeEnoughFragmentToSingleMessageV2() throws IOException {
		final OtrEngineHost host = host(830);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		String[] msg = fragmenter.fragment(2, specV2MessageFull);
		assertArrayEquals(new String[] {specV2MessageFull}, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsUnlimitedSize() throws IOException {
		final OtrEngineHost host = host(Integer.MAX_VALUE);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		int num = fragmenter.numberOfFragments(3, specV3MessageFull);
		assertEquals(1, num);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsLargeEnoughSize() throws IOException {
		final OtrEngineHost host = host(1000);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		int num = fragmenter.numberOfFragments(3, specV3MessageFull);
		assertEquals(1, num);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsNumFragmentsSmallFragmentSize() throws IOException {
		final OtrEngineHost host = host(199);

		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		int num = fragmenter.numberOfFragments(3, specV3MessageFull);
		assertEquals(3, num);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsNumFragmentsSmallFragmentSize2() throws IOException {
		final OtrEngineHost host = host(80);

		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		int num = fragmenter.numberOfFragments(3, specV3MessageFull);
		assertEquals(9, num);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test(expected = IOException.class)
	public void testFragmentSizeTooSmallForOverhead() throws IOException {
		final OtrEngineHost host = host(35);

		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		fragmenter.numberOfFragments(3, specV3MessageFull);
	}
	
	@Test(expected = IOException.class)
	public void testFragmentSizeTooSmallForPayload() throws IOException {
		OtrFragmenter fragmenter = new OtrFragmenter(host(OtrFragmenter.computeHeaderV3Size()), this.sessionID, 0, 0);
		fragmenter.numberOfFragments(3, specV3MessageFull);
	}

	@Test
	public void testV3MessageToSplit() throws IOException {
		final OtrEngineHost host = host(199);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, this.senderTag, this.receiverTag);
		String[] msg = fragmenter.fragment(3, specV3MessageFull);
		assertArrayEquals(specV3MessageParts199, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testV2MessageToSplit() throws IOException {
		final OtrEngineHost host = host(318);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		String[] msg = fragmenter.fragment(2, specV2MessageFull);
		assertArrayEquals(specV2MessageParts318, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testV1ComputeHeaderSize() throws IOException {
		OtrFragmenter fragmenter = new OtrFragmenter(host(310), this.sessionID, 0, 0);
		fragmenter.numberOfFragments(1, specV2MessageFull);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testV1MessageToSplit() throws IOException {
		OtrFragmenter fragmenter = new OtrFragmenter(host(310), this.sessionID, 0, 0);
		fragmenter.fragment(1, specV2MessageFull);
	}

	@Test(expected = IOException.class)
	public void testExceedProtocolMaximumNumberOfFragments() throws IOException {
		final String veryLongString = new String(new char[65537]).replace('\0', 'a');
		OtrFragmenter fragmenter = new OtrFragmenter(host(OtrFragmenter.computeHeaderV3Size() + 1), this.sessionID, 0, 0);
		fragmenter.fragment(3, veryLongString);
	}
	
	@Test
	public void testFragmentPatternsV3() throws IOException {		
		final Pattern OTRv3_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR\\|[0-9abcdef]{8}\\|[0-9abcdef]{8},\\d{5},\\d{5},[a-zA-Z0-9\\+/=\\?:]+,$");
		final String payload = new String(Base64.encode(RandomStringUtils.random(1700).getBytes(SerializationUtils.UTF8)), SerializationUtils.ASCII);
		final OtrEngineHost host = host(150);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0x0a73a599, 0x00010007);
		String[] msg = fragmenter.fragment(3, payload);
		int count = 1;
		for (String part : msg) {
			assertTrue(OTRv3_FRAGMENT_PATTERN.matcher(part).matches());
			// Test monotonic increase of part numbers ...
			int partNumber = Integer.parseInt(part.substring(23, 28), 10);
			assertEquals(count, partNumber);
			count++;
		}
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}
	
	@Test
	public void testFragmentPatternsV2() throws IOException {		
		final Pattern OTRv2_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR,\\d{1,5},\\d{1,5},[a-zA-Z0-9\\+/=\\?:]+,$");
		final String payload = new String(Base64.encode(RandomStringUtils.random(700).getBytes(SerializationUtils.UTF8)), SerializationUtils.ASCII);
		final OtrEngineHost host = host(150);
		
		OtrFragmenter fragmenter = new OtrFragmenter(host, this.sessionID, 0, 0);
		String[] msg = fragmenter.fragment(2, payload);
		int count = 1;
		for (String part : msg) {
			assertTrue(OTRv2_FRAGMENT_PATTERN.matcher(part).matches());
			// Test monotonic increase of part numbers ...
			String temp = part.substring(5, 11);
			int partNumber = Integer.parseInt(temp.substring(0, temp.indexOf(',')), 10);
			assertEquals(count, partNumber);
			count++;
		}
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}
	
	/**
	 * Create mock OtrEngineHost which returns the provided instructions.
	 *
	 * @param maxFragmentSize the maximum fragment size
	 * @return returns mock host
	 */
	private OtrEngineHost host(final int maxFragmentSize) {
		final OtrEngineHost host = mock(OtrEngineHost.class);
		when(host.getMaxFragmentSize(any(SessionID.class)))
				.thenReturn(maxFragmentSize);
		return host;
	}
}
