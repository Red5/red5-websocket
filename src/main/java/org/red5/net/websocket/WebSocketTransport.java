/*
 * RED5 Open Source Flash Server - https://github.com/red5
 * 
 * Copyright 2006-2015 by respective authors (see below). All rights reserved.
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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.mina.core.filterchain.DefaultIoFilterChainBuilder;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.service.IoService;
import org.apache.mina.core.service.IoServiceListener;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.logging.LoggingFilter;
import org.apache.mina.filter.ssl.SslFilter;
import org.apache.mina.transport.socket.SocketAcceptor;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.red5.net.websocket.codec.WebSocketCodecFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * WebSocketTransport
 * <br>
 * this class will be instanced in red5.xml(or other xml files). * will make port listen...
 * 
 * @author Toda Takahiko
 * @author Paul Gregoire
 */
public class WebSocketTransport implements InitializingBean, DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(WebSocketTransport.class);

    private int sendBufferSize = 2048;

    private int receiveBufferSize = 2048;

    private int port = 80;

    private Set<String> addresses = new HashSet<>();

    private int writeTimeout = 30;
    
    private int idleTimeout = 60;
    
    private IoHandlerAdapter ioHandler;

    private SocketAcceptor acceptor;

    private SecureWebSocketConfiguration secureConfig;

    // Same origin policy enable/disabled
    private static boolean sameOriginPolicy;

    // Cross-origin policy enable/disabled
    private static boolean crossOriginPolicy;

    // Cross-origin names
    private static String[] allowedOrigins = new String[] { "*" };

    /**
     * Creates the i/o handler and nio acceptor; ports and addresses are bound.
     * 
     * @throws IOException
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        // create the nio acceptor
        acceptor = new NioSocketAcceptor(Runtime.getRuntime().availableProcessors() * 4);
        acceptor.addListener(new IoServiceListener() {

            @Override
            public void serviceActivated(IoService service) throws Exception {
                //log.debug("serviceActivated: {}", service);
            }

            @Override
            public void serviceIdle(IoService service, IdleStatus idleStatus) throws Exception {
                //logger.debug("serviceIdle: {} status: {}", service, idleStatus);
            }

            @Override
            public void serviceDeactivated(IoService service) throws Exception {
                //log.debug("serviceDeactivated: {}", service);
            }

            @Override
            public void sessionCreated(IoSession session) throws Exception {
                log.info("sessionCreated: {}", session);
                //log.trace("Acceptor sessions: {}", acceptor.getManagedSessions());
            }

            @Override
            public void sessionClosed(IoSession session) throws Exception {
                log.info("sessionClosed: {}", session);
            }

            @Override
            public void sessionDestroyed(IoSession session) throws Exception {
                //log.debug("sessionDestroyed: {}", session);
            }

        });        
        // configure the acceptor
        SocketSessionConfig sessionConf = acceptor.getSessionConfig();
        sessionConf.setReuseAddress(true);
        sessionConf.setTcpNoDelay(true);
        sessionConf.setSendBufferSize(sendBufferSize);
        sessionConf.setReadBufferSize(receiveBufferSize);
        // prevent the background blocking queue
        sessionConf.setUseReadOperation(false);
        // seconds
        sessionConf.setWriteTimeout(writeTimeout);
        // set an idle time of 30s
        sessionConf.setIdleTime(IdleStatus.BOTH_IDLE, idleTimeout);
        // close sessions when the acceptor is stopped
        acceptor.setCloseOnDeactivation(true);
        // requested maximum length of the queue of incoming connections
        acceptor.setBacklog(64);
        acceptor.setReuseAddress(true);
        // instance the websocket handler
        if (ioHandler == null) {
            ioHandler = new WebSocketHandler();
        }
        log.trace("I/O handler: {}", ioHandler);
        acceptor.setHandler(ioHandler);
        DefaultIoFilterChainBuilder chain = acceptor.getFilterChain();
        // if handling wss init the config
        SslFilter sslFilter = null;
        if (secureConfig != null) {
            try {
                sslFilter = secureConfig.getSslFilter();
                chain.addFirst("sslFilter", sslFilter);
            } catch (Exception e) {
                log.warn("SSL configuration failed, websocket will not be secure", e);
            }
        }
        if (log.isTraceEnabled()) {
            chain.addLast("logger", new LoggingFilter());
        }
        // add the websocket codec factory
        chain.addLast("protocol", new ProtocolCodecFilter(new WebSocketCodecFactory()));
        if (addresses.isEmpty()) {
            if (sslFilter != null) {
                log.info("WebSocket (wss) will be bound to port {}", port);
            } else {
                log.info("WebSocket (ws) will be bound to port {}", port);
            }
            acceptor.bind(new InetSocketAddress(port));
        } else {
            if (sslFilter != null) {
                log.info("WebSocket (wss) will be bound to {}", addresses);
            } else {
                log.info("WebSocket (ws) will be bound to {}", addresses);
            }
            try {
                // loop through the addresses and bind
                Set<InetSocketAddress> socketAddresses = new HashSet<InetSocketAddress>();
                for (String addr : addresses) {
                    if (addr.indexOf(':') != -1) {
                        String[] parts = addr.split(":");
                        socketAddresses.add(new InetSocketAddress(parts[0], Integer.valueOf(parts[1])));
                    } else {
                        socketAddresses.add(new InetSocketAddress(addr, port));
                    }
                }
                log.debug("Binding to {}", socketAddresses.toString());
                acceptor.bind(socketAddresses);
            } catch (Exception e) {
                log.warn("Exception occurred during resolve / bind", e);
            }
        }
        log.info("started {} websocket transport", (isSecure() ? "secure" : ""));
        if (log.isDebugEnabled()) {
            log.debug("Acceptor sizes - send: {} recv: {}", acceptor.getSessionConfig().getSendBufferSize(), acceptor.getSessionConfig().getReadBufferSize());
        }
    }

    /**
     * Ports and addresses are unbound (stop listening).
     */
    @Override
    public void destroy() throws Exception {
        log.info("stopped {} websocket transport", (isSecure() ? "secure" : ""));
        acceptor.unbind();
    }

    public void setAddresses(List<String> addrs) {
        for (String addr : addrs) {
            addresses.add(addr);
        }
    }

    /**
     * @param port the port to set
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * @param sendBufferSize the sendBufferSize to set
     */
    public void setSendBufferSize(int sendBufferSize) {
        this.sendBufferSize = sendBufferSize;
    }

    /**
     * @param receiveBufferSize the receiveBufferSize to set
     */
    public void setReceiveBufferSize(int receiveBufferSize) {
        this.receiveBufferSize = receiveBufferSize;
    }

    /**
     * Write timeout.
     * 
     * @param writeTimeout
     */
    public void setWriteTimeout(int writeTimeout) {
        this.writeTimeout = writeTimeout;
    }

    /**
     * Idle timeout.
     * 
     * @param idleTimeout
     */
    public void setIdleTimeout(int idleTimeout) {
        this.idleTimeout = idleTimeout;
    }

    /**
     * @param connectionThreads the connectionThreads to set
     */
    @Deprecated
    public void setConnectionThreads(int connectionThreads) {
    }

    /**
     * @param ioThreads the ioThreads to set
     */
    @Deprecated
    public void setIoThreads(int ioThreads) {
    }

    public boolean isSecure() {
        return secureConfig != null;
    }

    public void setIoHandler(IoHandlerAdapter ioHandler) {
        this.ioHandler = ioHandler;
    }

    public void setSecureConfig(SecureWebSocketConfiguration secureConfig) {
        this.secureConfig = secureConfig;
    }

    public static boolean isSameOriginPolicy() {
        return sameOriginPolicy;
    }

    public void setSameOriginPolicy(boolean sameOriginPolicy) {
        WebSocketTransport.sameOriginPolicy = sameOriginPolicy;
    }

    public static boolean isCrossOriginPolicy() {
        return crossOriginPolicy;
    }

    public void setCrossOriginPolicy(boolean crossOriginPolicy) {
        WebSocketTransport.crossOriginPolicy = crossOriginPolicy;
    }

    public static String[] getAllowedOrigins() {
        return allowedOrigins;
    }

    public void setAllowedOrigins(String[] allowedOrigins) {
        WebSocketTransport.allowedOrigins = allowedOrigins;
        log.info("allowedOrigins: {}", Arrays.toString(WebSocketTransport.allowedOrigins));
    }

}
