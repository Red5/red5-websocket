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
import java.util.HashSet;
import java.util.Set;

import net.sourceforge.groboutils.junit.v1.MultiThreadedTestRunner;
import net.sourceforge.groboutils.junit.v1.TestRunnable;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
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

	@Test
	public void testMasked() throws Throwable {
		log.info("testMasked enter");
		// masked
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x81, (byte) 0x85, (byte) 0x37, (byte) 0xfa, (byte) 0x21, (byte) 0x3d, (byte) 0x7f, (byte) 0x9f, (byte) 0x4d, (byte) 0x51, (byte) 0x58 });
		// get results
		WSMessage result = WebSocketDecoder.decodeIncommingData(in, null);
		assertTrue(result.getMessageType() == MessageType.TEXT);
		assertEquals("Hello", result.getMessageAsString());
		log.info("testMasked exit");
	}

	@Test
	public void testUnmasked() throws Throwable {
		log.info("testUnmasked enter");
		// unmasked
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x81, (byte) 0x05, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f });
		// get results
		WSMessage result = WebSocketDecoder.decodeIncommingData(in, null);
		assertTrue(result.getMessageType() == MessageType.TEXT);
		assertEquals("Hello", result.getMessageAsString());
		log.info("testUnmasked exit");
	}

	@Test
	public void testFragmented() throws Throwable {
		log.info("testFragmented enter");
		// fragmented
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x01, (byte) 0x03, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x80, (byte) 0x02, (byte) 0x6c, (byte) 0x6f });
		// get results
		WSMessage result = WebSocketDecoder.decodeIncommingData(in, null);
		assertEquals("Hello", result.getMessageAsString());
		log.info("testFragmented exit");
	}

	@Test
	public void testUnmaskedPing() throws Throwable {
		log.info("testUnmaskedPing enter");
		// unmasked ping
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x89, (byte) 0x05, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f });
		// get results
		WSMessage result = WebSocketDecoder.decodeIncommingData(in, null);
		assertTrue(result.getMessageType() == MessageType.PING);
		assertEquals("Hello", result.getMessageAsString());
		log.info("testUnmaskedPing exit");
	}

	@Test
	public void testMaskedPong() throws Throwable {
		log.info("testMaskedPong enter");
		// masked pong
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x8a, (byte) 0x85, (byte) 0x37, (byte) 0xfa, (byte) 0x21, (byte) 0x3d, (byte) 0x7f, (byte) 0x9f, (byte) 0x4d, (byte) 0x51, (byte) 0x58 });
		// get results
		WSMessage result = WebSocketDecoder.decodeIncommingData(in, null);
		assertTrue(result.getMessageType() == MessageType.PONG);
		assertEquals("Hello", result.getMessageAsString());
		log.info("testMaskedPong exit");
	}

	@Test
	public void testUnmaskedRoundTrip() throws Throwable {
		log.info("testUnmaskedRoundTrip enter");
		// unmasked
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x81, (byte) 0x05, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f });
		// get results
		IoBuffer out = WebSocketEncoder.encodeOutgoingData(Packet.build("Hello".getBytes(), MessageType.TEXT));
		WSMessage result = WebSocketDecoder.decodeIncommingData(out, null);
		assertTrue(result.getMessageType() == MessageType.TEXT);
		assertEquals("Hello", result.getMessageAsString());
		log.info("testUnmaskedRoundTrip exit");
	}
	
	@Test
	public void testUnmaskedPingRoundTrip() throws Throwable {
		log.info("testUnmaskedPingRoundTrip enter");
		// unmasked ping
		IoBuffer in = IoBuffer.wrap(new byte[] { (byte) 0x89, (byte) 0x05, (byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c, (byte) 0x6f });
		// get results
		IoBuffer out = WebSocketEncoder.encodeOutgoingData(Packet.build("Hello".getBytes(), MessageType.PING));
		WSMessage result = WebSocketDecoder.decodeIncommingData(out, null);
		assertTrue(result.getMessageType() == MessageType.PING);
		assertEquals("Hello", result.getMessageAsString());
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

}
