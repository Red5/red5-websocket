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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.sourceforge.groboutils.junit.v1.MultiThreadedTestRunner;
import net.sourceforge.groboutils.junit.v1.TestRunnable;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilter.NextFilter;
import org.apache.mina.core.filterchain.IoFilterChain;
import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.ReadFuture;
import org.apache.mina.core.future.WriteFuture;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.service.TransportMetadata;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.session.IoSessionConfig;
import org.apache.mina.core.write.WriteRequest;
import org.apache.mina.core.write.WriteRequestQueue;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;
import org.apache.mina.transport.socket.SocketConnector;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.mina.transport.socket.nio.NioSocketConnector;
import org.junit.Test;
import org.red5.net.websocket.codec.WebSocketCodecFactory;
import org.red5.net.websocket.codec.WebSocketDecoder;
import org.red5.net.websocket.codec.WebSocketEncoder;
import org.red5.net.websocket.model.ConnectionType;
import org.red5.net.websocket.model.HandshakeRequest;
import org.red5.net.websocket.model.MessageType;
import org.red5.net.websocket.model.Packet;
import org.red5.net.websocket.model.WSMessage;
import org.red5.server.plugin.PluginRegistry;
import org.red5.server.scope.GlobalScope;
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

	private static Object writtenResult;

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

	@SuppressWarnings("unused")
	@Test
	public void testMultiThreaded() throws Throwable {
		log.info("testMultiThreaded enter");
		// create the server instance
		Thread server = new Thread() {
			@Override
			public void run() {
				log.debug("Server thread run");
				try {
					WSServer.main(null);
				} catch (IOException e) {
					log.error("Error in server thread", e);
				}
				log.debug("Server thread exit");
			}
		};
		server.setDaemon(true);
		server.start();
		// add plugin to the registry
		WebSocketPlugin plugin = new WebSocketPlugin();
		PluginRegistry.register(plugin);
		WebSocketScopeManager manager = plugin.getManager();
		manager.addApplication(new GlobalScope());
		// start plugin
		plugin.doStart();
		// wait for server
		while (!WSServer.isListening()) {
			Thread.sleep(10L);
		}
		// how many threads
		int threads = 1;
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
		Thread.sleep(2000L);
		// stop server
		server.interrupt();
		WSServer.stop();
		// stop plugin
		PluginRegistry.shutdown();
		log.info("testMultiThreaded exit");
	}

	//	@Test
	//	public void testDecodingErrorJuneSixth() throws Throwable {
	//		log.info("-------------------------------------------------------test66 enter");
	//		// masked
	//		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x81, (byte) 0xFE, (byte) 0x00, (byte) 0xAE, (byte) 0x97, (byte) 0x6A, (byte) 0xAD, (byte) 0x23, (byte) 0xEC, (byte) 0x48, (byte) 0xC9, (byte) 0x42, (byte) 0xE3, (byte) 0x0B, (byte) 0x8F, (byte) 0x19, (byte) 0xEC, (byte) 0x48, (byte) 0xDE, (byte) 0x46,
	//				(byte) 0xE4, (byte) 0x19, (byte) 0xC4, (byte) 0x4C, (byte) 0xF9, (byte) 0x03, (byte) 0xC9, (byte) 0x01, (byte) 0xAD, (byte) 0x48, (byte) 0x9F, (byte) 0x12, (byte) 0xA3, (byte) 0x5A, (byte) 0x98, (byte) 0x16, (byte) 0xA4, (byte) 0x5E, (byte) 0x9E, (byte) 0x1A, (byte) 0xAE, (byte) 0x5C, (byte) 0x9A,
	//				(byte) 0x10, (byte) 0xA4, (byte) 0x5E, (byte) 0x9E, (byte) 0x01, (byte) 0xBB, (byte) 0x48, (byte) 0xD8, (byte) 0x50, (byte) 0xF2, (byte) 0x18, (byte) 0xC4, (byte) 0x47, (byte) 0xB5, (byte) 0x50, (byte) 0x8F, (byte) 0x4B, (byte) 0xE0, (byte) 0x03, (byte) 0xDF, (byte) 0x4D, (byte) 0xA4, (byte) 0x5B,
	//				(byte) 0x9D, (byte) 0x4F, (byte) 0xA3, (byte) 0x5F, (byte) 0x9F, (byte) 0x46, (byte) 0xA6, (byte) 0x53, (byte) 0xDF, (byte) 0x10, (byte) 0xFE, (byte) 0x09, (byte) 0xDC, (byte) 0x01, (byte) 0xBB, (byte) 0x48, (byte) 0xDE, (byte) 0x46, (byte) 0xE4, (byte) 0x19, (byte) 0xC4, (byte) 0x4C, (byte) 0xF9,
	//				(byte) 0x48, (byte) 0x97, (byte) 0x58, (byte) 0xB5, (byte) 0x0E, (byte) 0xCC, (byte) 0x57, (byte) 0xF6, (byte) 0x48, (byte) 0x97, (byte) 0x57, (byte) 0xE5, (byte) 0x1F, (byte) 0xC8, (byte) 0x5E, (byte) 0xBB, (byte) 0x48, (byte) 0xC8, (byte) 0x5B, (byte) 0xE3, (byte) 0x18, (byte) 0xCC, (byte) 0x01,
	//				(byte) 0xAD, (byte) 0x11, (byte) 0x8F, (byte) 0x56, (byte) 0xE4, (byte) 0x0F, (byte) 0xDF, (byte) 0x4D, (byte) 0xF6, (byte) 0x07, (byte) 0xC8, (byte) 0x01, (byte) 0xAD, (byte) 0x48, (byte) 0xFD, (byte) 0x42 });
	//		// get results
	//		WSMessage result = WebSocketDecoder.decodeIncommingData(in, null);
	//		assertTrue(result.getMessageType() == MessageType.TEXT);
	//		log.info("{}", result.getMessageAsString());
	//		assertEquals("Hello", result.getMessageAsString());
	//		log.info("-------------------------------------------------------test66 exit");
	//	}

	@Test
	public void testMasked() throws Throwable {
		log.info("testMasked enter");
		// masked
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x81, (byte) 0x85, (byte) 0x37, (byte) 0xfa, (byte) 0x21, (byte) 0x3d, (byte) 0x7f, (byte) 0x9f, (byte) 0x4d, (byte) 0x51, (byte) 0x58 });
		// create session and conn
		DummySession session = new DummySession();
		WebSocketConnection conn = new WebSocketConnection(session);
		session.setAttribute(Constants.CONNECTION, conn);
		// decode
		DummyDecoder decoder = new DummyDecoder();
		decoder.dummyDecode(session, in, new DummyOutput());
		assertTrue(((WSMessage) writtenResult).getMessageType() == MessageType.TEXT);
		assertEquals("Hello", ((WSMessage) writtenResult).getMessageAsString());
		log.info("testMasked exit");
	}

	@Test
	public void testUnmasked() throws Throwable {
		log.info("testUnmasked enter");
		// unmasked
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x81, (byte) 0x05, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f });
		// create session and conn
		DummySession session = new DummySession();
		WebSocketConnection conn = new WebSocketConnection(session);
		session.setAttribute(Constants.CONNECTION, conn);
		// decode
		DummyDecoder decoder = new DummyDecoder();
		decoder.dummyDecode(session, in, new DummyOutput());
		assertTrue(((WSMessage) writtenResult).getMessageType() == MessageType.TEXT);
		assertEquals("Hello", ((WSMessage) writtenResult).getMessageAsString());
		log.info("testUnmasked exit");
	}

	@Test
	public void testFragmented() throws Throwable {
		log.info("testFragmented enter");
		// fragments
		byte[] part1 = new byte[] { (byte) 0x01, (byte) 0x03, (byte) 0x48, (byte) 0x65, (byte) 0x6c };
		byte[] part2 = new byte[] { (byte) 0x80, (byte) 0x02, (byte) 0x6c, (byte) 0x6f };
		// create session and conn
		DummySession session = new DummySession();
		WebSocketConnection conn = new WebSocketConnection(session);
		session.setAttribute(Constants.CONNECTION, conn);
		// decode
		DummyDecoder decoder = new DummyDecoder();
		DummyOutput out = new DummyOutput();
		// create io buffer
		IoBuffer in = IoBuffer.allocate(5, false);
		// add part 1
		in.put(part1);
		in.flip();
		// decode with first fragment
		decoder.dummyDecode(session, in, out);
		// add part 2
		in = IoBuffer.allocate(4, false);
		in.put(part2);
		in.flip();
		// decode with second fragment
		decoder.dummyDecode(session, in, out);
		// check result
		assertTrue(((WSMessage) writtenResult).getMessageType() == MessageType.TEXT);
		assertEquals("Hello", ((WSMessage) writtenResult).getMessageAsString());
		log.info("testFragmented exit");
	}

	@Test
	public void testUnmaskedPing() throws Throwable {
		log.info("testUnmaskedPing enter");
		// unmasked ping
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x89, (byte) 0x05, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f });
		// create session and conn
		DummySession session = new DummySession();
		WebSocketConnection conn = new WebSocketConnection(session);
		session.setAttribute(Constants.CONNECTION, conn);
		// decode
		DummyDecoder decoder = new DummyDecoder();
		decoder.dummyDecode(session, in, new DummyOutput());
		assertTrue(((WSMessage) writtenResult).getMessageType() == MessageType.PING);
		assertEquals("Hello", ((WSMessage) writtenResult).getMessageAsString());
		log.info("testUnmaskedPing exit");
	}

	@Test
	public void testMaskedPong() throws Throwable {
		log.info("testMaskedPong enter");
		// masked pong
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x8a, (byte) 0x85, (byte) 0x37, (byte) 0xfa, (byte) 0x21, (byte) 0x3d, (byte) 0x7f, (byte) 0x9f, (byte) 0x4d, (byte) 0x51, (byte) 0x58 });
		// create session and conn
		DummySession session = new DummySession();
		WebSocketConnection conn = new WebSocketConnection(session);
		session.setAttribute(Constants.CONNECTION, conn);
		// decode
		DummyDecoder decoder = new DummyDecoder();
		decoder.dummyDecode(session, in, new DummyOutput());
		assertTrue(((WSMessage) writtenResult).getMessageType() == MessageType.PONG);
		assertEquals("Hello", ((WSMessage) writtenResult).getMessageAsString());
		log.info("testMaskedPong exit");
	}

	@Test
	public void testUnmaskedRoundTrip() throws Throwable {
		log.info("testUnmaskedRoundTrip enter");
		// create session and conn
		DummySession session = new DummySession();
		WebSocketConnection conn = new WebSocketConnection(session);
		session.setAttribute(Constants.CONNECTION, conn);
		// encode
		DummyEncoder encoder = new DummyEncoder();
		encoder.dummyEncode(session, Packet.build("Hello".getBytes(), MessageType.TEXT), new DummyOutput());
		// decode
		DummyDecoder decoder = new DummyDecoder();
		decoder.dummyDecode(session, (IoBuffer) writtenResult, new DummyOutput());
		assertTrue(((WSMessage) writtenResult).getMessageType() == MessageType.TEXT);
		assertEquals("Hello", ((WSMessage) writtenResult).getMessageAsString());
		log.info("testUnmaskedRoundTrip exit");
	}

	@Test
	public void testUnmaskedPingRoundTrip() throws Throwable {
		log.info("testUnmaskedPingRoundTrip enter");
		// create session and conn
		DummySession session = new DummySession();
		WebSocketConnection conn = new WebSocketConnection(session);
		session.setAttribute(Constants.CONNECTION, conn);
		// encode
		DummyEncoder encoder = new DummyEncoder();
		encoder.dummyEncode(session, Packet.build("Hello".getBytes(), MessageType.PING), new DummyOutput());
		// decode
		DummyDecoder decoder = new DummyDecoder();
		decoder.dummyDecode(session, (IoBuffer) writtenResult, new DummyOutput());
		assertTrue(((WSMessage) writtenResult).getMessageType() == MessageType.PING);
		assertEquals("Hello", ((WSMessage) writtenResult).getMessageAsString());
		log.info("testUnmaskedPingRoundTrip exit");
	}

	private class Worker extends TestRunnable {

		boolean failed;

		public void runTest() throws Throwable {
			WSClient client = new WSClient("localhost", 8888);
			client.connect();
			if (client.isConnected()) {
				client.send("This is a test: " + System.currentTimeMillis());
			} else {
				failed = true;
			}
		}

	}

	public static class WSServer {

		private static NioSocketAcceptor acceptor;

		private static boolean listening;

		public static void stop() {
			acceptor.unbind();
			listening = false;
		}

		public static boolean isListening() {
			return listening;
		}

		public static void main(String[] args) throws IOException {
			acceptor = new NioSocketAcceptor();
			acceptor.getFilterChain().addLast("protocol", new ProtocolCodecFilter(new WebSocketCodecFactory()));
			// close sessions when the acceptor is stopped
			acceptor.setCloseOnDeactivation(true);
			acceptor.setHandler(new WebSocketHandler());
			SocketSessionConfig sessionConf = acceptor.getSessionConfig();
			sessionConf.setReuseAddress(true);
			acceptor.setReuseAddress(true);
			// loop through the addresses and bind
			Set<InetSocketAddress> socketAddresses = new HashSet<InetSocketAddress>();
			socketAddresses.add(new InetSocketAddress("0.0.0.0", 8888));
			//socketAddresses.add(new InetSocketAddress("localhost", 8888));
			log.debug("Binding to {}", socketAddresses.toString());
			acceptor.bind(socketAddresses);
			System.out.println("WS server is listening");
			listening = true;
			while (true) {
				try {
					Thread.sleep(2000L);
				} catch (InterruptedException e) {
					System.out.println("WS server is not listening");
				}
			}
		}

	}

	public class WSClient extends IoHandlerAdapter {

		private String host;

		private int port;

		private SocketConnector connector;

		private IoSession session;

		public WSClient(String host, int port) {
			this.host = host;
			this.port = port;
			connector = new NioSocketConnector();
			connector.getFilterChain().addLast("codec", new ProtocolCodecFilter(new WebSocketCodecFactory()));
			connector.setHandler(this);
			SocketSessionConfig sessionConf = connector.getSessionConfig();
			sessionConf.setReuseAddress(true);
			connector.setConnectTimeout(3);
		}

		public void connect() {
			try {
				ConnectFuture future = connector.connect(new InetSocketAddress(host, port));
				future.awaitUninterruptibly();
				session = future.getSession();
				// write the handshake
				IoBuffer buf = IoBuffer.allocate(308);
				buf.setAutoExpand(true);
				buf.put("GET /default?encoding=text HTTP/1.1".getBytes());
				buf.put(Constants.CRLF);
				buf.put("Upgrade: websocket".getBytes());
				buf.put(Constants.CRLF);
				buf.put("Connection: Upgrade".getBytes());
				buf.put(Constants.CRLF);
				buf.put(String.format("%s: http://%s:%d", Constants.HTTP_HEADER_ORIGIN, host, port).getBytes());
				buf.put(Constants.CRLF);
				buf.put(String.format("%s: %s:%d", Constants.HTTP_HEADER_HOST, host, port).getBytes());
				buf.put(Constants.CRLF);
				buf.put(String.format("%s: dGhlIHNhbXBsZSBub25jZQ==", Constants.WS_HEADER_KEY).getBytes());
				buf.put(Constants.CRLF);
				buf.put("Sec-WebSocket-Version: 13".getBytes());
				buf.put(Constants.CRLF);
				buf.put(Constants.CRLF);
				HandshakeRequest request = new HandshakeRequest(buf);
				session.write(request);
				// create connection 
				WebSocketConnection conn = new WebSocketConnection(session);
				conn.setType(ConnectionType.WEB);
				conn.setConnected();
				// add connection to client side session
				session.setAttribute(Constants.CONNECTION, conn);
			} catch (Exception e) {
				log.error("Connection error", e);
			}
		}

		public void send(String text) {
			if (session != null) {
				session.write(Packet.build(text.getBytes(), MessageType.TEXT));
			}
		}

		public void ping() {
			if (session != null) {
				session.write(Packet.build("PINGING".getBytes(), MessageType.PING));
			}
		}

		@Override
		public void messageReceived(IoSession session, Object message) throws Exception {
			WSMessage msg = (WSMessage) message;
			System.out.println("Received: " + msg);
		}

		@Override
		public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
			log.error("exception", cause);
		}

		public boolean isConnected() {
			return session != null;
		}

	}

	private class DummyDecoder extends WebSocketDecoder {
		public boolean dummyDecode(IoSession session, IoBuffer in, ProtocolDecoderOutput out) throws Exception {
			return super.doDecode(session, in, out);
		}
	}

	private class DummyEncoder extends WebSocketEncoder {
		public void dummyEncode(IoSession session, Object message, ProtocolEncoderOutput out) throws Exception {
			super.encode(session, message, out);
		}
	}

	private class DummyOutput implements ProtocolDecoderOutput, ProtocolEncoderOutput {

		@Override
		public void mergeAll() {
		}

		@Override
		public WriteFuture flush() {
			return null;
		}

		@Override
		public void write(Object message) {
			log.debug("out: {}", message);
			WebSocketServerTest.writtenResult = message;
		}

		@Override
		public void flush(NextFilter nextFilter, IoSession session) {
		}

	}

	private class DummySession implements IoSession {

		Map<Object, Object> attr = new HashMap<Object, Object>();

		@Override
		public long getId() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public IoService getService() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public IoHandler getHandler() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public IoSessionConfig getConfig() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public IoFilterChain getFilterChain() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public WriteRequestQueue getWriteRequestQueue() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public TransportMetadata getTransportMetadata() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public ReadFuture read() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public WriteFuture write(Object message) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public WriteFuture write(Object message, SocketAddress destination) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public CloseFuture close(boolean immediately) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		@Deprecated
		public CloseFuture close() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		@Deprecated
		public Object getAttachment() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		@Deprecated
		public Object setAttachment(Object attachment) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Object getAttribute(Object key) {
			return attr.get(key);
		}

		@Override
		public Object getAttribute(Object key, Object defaultValue) {
			return attr.get(key);
		}

		@Override
		public Object setAttribute(Object key, Object value) {
			attr.put(key, value);
			return attr.get(key);
		}

		@Override
		public Object setAttribute(Object key) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Object setAttributeIfAbsent(Object key, Object value) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Object setAttributeIfAbsent(Object key) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Object removeAttribute(Object key) {
			return attr.remove(key);
		}

		@Override
		public boolean removeAttribute(Object key, Object value) {
			return attr.remove(key) != null;
		}

		@Override
		public boolean replaceAttribute(Object key, Object oldValue, Object newValue) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean containsAttribute(Object key) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public Set<Object> getAttributeKeys() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public boolean isConnected() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean isClosing() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public CloseFuture getCloseFuture() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public SocketAddress getRemoteAddress() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public SocketAddress getLocalAddress() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public SocketAddress getServiceAddress() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public void setCurrentWriteRequest(WriteRequest currentWriteRequest) {
			// TODO Auto-generated method stub

		}

		@Override
		public void suspendRead() {
			// TODO Auto-generated method stub

		}

		@Override
		public void suspendWrite() {
			// TODO Auto-generated method stub

		}

		@Override
		public void resumeRead() {
			// TODO Auto-generated method stub

		}

		@Override
		public void resumeWrite() {
			// TODO Auto-generated method stub

		}

		@Override
		public boolean isReadSuspended() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean isWriteSuspended() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void updateThroughput(long currentTime, boolean force) {
			// TODO Auto-generated method stub

		}

		@Override
		public long getReadBytes() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getWrittenBytes() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getReadMessages() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getWrittenMessages() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public double getReadBytesThroughput() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public double getWrittenBytesThroughput() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public double getReadMessagesThroughput() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public double getWrittenMessagesThroughput() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public int getScheduledWriteMessages() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getScheduledWriteBytes() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public Object getCurrentWriteMessage() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public WriteRequest getCurrentWriteRequest() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public long getCreationTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getLastIoTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getLastReadTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getLastWriteTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public boolean isIdle(IdleStatus status) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean isReaderIdle() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean isWriterIdle() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean isBothIdle() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public int getIdleCount(IdleStatus status) {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public int getReaderIdleCount() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public int getWriterIdleCount() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public int getBothIdleCount() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getLastIdleTime(IdleStatus status) {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getLastReaderIdleTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getLastWriterIdleTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public long getLastBothIdleTime() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public boolean isSecured() {
			// TODO Auto-generated method stub
			return false;
		}

	}

}
