/*
 * RED5 Open Source Flash Server - http://code.google.com/p/red5/
 * 
 * Copyright 2006-2014 by respective authors (see below). All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.red5.net.websocket;

import junit.framework.Assert;
import net.sourceforge.groboutils.junit.v1.MultiThreadedTestRunner;
import net.sourceforge.groboutils.junit.v1.TestRunnable;

import org.apache.mina.core.buffer.IoBuffer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.red5.net.websocket.codec.WebSocketDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests for websocket operations. 
 * 
 * @author Paul Gregoire (mondain@gmail.com)
 */
@SuppressWarnings("deprecation")
public class WebSocketServerTest {

	protected static Logger log = LoggerFactory.getLogger(WebSocketServerTest.class);

	/*
	 * Test data from the rfc
	    <pre>	   
	    A single-frame unmasked text message (contains "Hello")
	    0x81 0x05 0x48 0x65 0x6c 0x6c 0x6f
	    
	    A single-frame masked text message (contains "Hello")
	    0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58
	    
	    A fragmented unmasked text message
	    0x01 0x03 0x48 0x65 0x6c (contains "Hel")
	    0x80 0x02 0x6c 0x6f (contains "lo")
	    
	    Unmasked Ping request and masked Ping response
	    
	    0x89 0x05 0x48 0x65 0x6c 0x6c 0x6f (contains a body of "Hello", but the contents of the body are arbitrary)
	    
	    0x8a 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58 (contains a body of "Hello", matching the body of the ping)
	    
	    A 256 bytes binary message in a single unmasked frame
	    0x82 0x7E 0x0100 [256 bytes of binary data]
	    
	    A 64KiB binary message in a single unmasked frame
	    0x82 0x7F 0x0000000000010000 [65536 bytes of binary data]
	    </pre>	 
	 */	
	
	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}
	
	@SuppressWarnings("unused") 
	@Test
	public void testMultiThreaded2() throws Throwable {
		int threads = 10;
		TestRunnable[] trs = new TestRunnable[threads];
		for (int t = 0; t < threads; t++) {
			trs[t] = new Worker();
		}
		MultiThreadedTestRunner mttr = new MultiThreadedTestRunner(trs);
		//kickstarts the MTTR & fires off threads
		long start = System.nanoTime();
		mttr.runTestRunnables();
		log.info("Runtime: {} ns", (System.nanoTime() - start));
		for (TestRunnable r : trs) {
			// loop through and check results
			
		}	
	}
	
	@Test
	public void testMasked() throws Throwable {
		log.info("testMasked enter");
		// masked
		IoBuffer in = IoBuffer.wrap(new byte[] {(byte) 0x81, (byte) 0x85, (byte) 0x37, (byte) 0xfa, (byte) 0x21, (byte) 0x3d, (byte) 0x7f, (byte) 0x9f, (byte) 0x4d, (byte) 0x51, (byte) 0x58});
		// get results
		IoBuffer result = WebSocketDecoder.decodeIncommingData(in, null);		
		log.error("Result: {}", (result != null ? new String(result.array()) : result));	
		Assert.assertEquals("Hello", new String(result.array()));
		log.info("testMasked exit");
	}
	
	@Test
	public void testUnmasked() throws Throwable {
		log.info("testUnmasked enter");
		// unmasked
		IoBuffer in = IoBuffer.wrap(new byte[] {(byte) 0x81, (byte) 0x05, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f});
		// get results
		IoBuffer result = WebSocketDecoder.decodeIncommingData(in, null);		
		log.error("Result: {}", (result != null ? new String(result.array()) : result));	
		Assert.assertEquals("Hello", new String(result.array()));
		log.info("testUnmasked exit");
	}
	
	@Test
	public void testFragmented() throws Throwable {
		log.info("testFragmented enter");
		// fragmented
		IoBuffer in = IoBuffer.wrap(new byte[] {(byte) 0x01, (byte) 0x03, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x80, (byte) 0x02, (byte) 0x6c, (byte) 0x6f});
		// get results
		IoBuffer result = WebSocketDecoder.decodeIncommingData(in, null);		
		log.error("Result: {}", (result != null ? new String(result.array()) : result));	
		Assert.assertEquals("Hello", new String(result.array()).trim());
		log.info("testFragmented exit");
	}

	@Test
	public void testUnmaskedPing() throws Throwable {
		log.info("testUnmaskedPing enter");
		// unmasked ping
		IoBuffer in = IoBuffer.wrap(new byte[] {(byte) 0x89, (byte) 0x05, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f});
		// get results
		IoBuffer result = WebSocketDecoder.decodeIncommingData(in, null);		
		log.error("Result: {}", (result != null ? new String(result.array()) : result));	
		Assert.assertEquals("Hello", new String(result.array()));
		log.info("testUnmaskedPing exit");
	}

	@Test
	public void testMaskedPong() throws Throwable {
		log.info("testMaskedPong enter");
		// masked pong
		IoBuffer in = IoBuffer.wrap(new byte[] {(byte) 0x8a, (byte) 0x85, (byte) 0x37, (byte) 0xfa, (byte) 0x21, (byte) 0x3d, (byte) 0x7f, (byte) 0x9f, (byte) 0x4d, (byte) 0x51, (byte) 0x58});
		// get results
		IoBuffer result = WebSocketDecoder.decodeIncommingData(in, null);		
		log.error("Result: {}", (result != null ? new String(result.array()) : result));	
		Assert.assertEquals("Hello", new String(result.array()));
		log.info("testMaskedPong exit");
	}
	
	private class Worker extends TestRunnable {
		
		public void runTest() throws Throwable {
			
		}

	}
	
    //	WebSocketHandshake hs = new WebSocketHandshake();
    //	if ("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".equals(new String(hs.crypt("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))) {
    //		System.out.println("Accept routine is valid");
    //	} else {
    //		System.err.println("Accept routine is invalid!");
    //	}	
	
	//	public static void main(String[] args) throws Exception {
	//		WebSocketConnection cn = new WebSocketConnection();
	//		for (int i = 0; i < 20; i++) {
	//			cn = new WebSocketConnection();
	//		}
	//	}

}
