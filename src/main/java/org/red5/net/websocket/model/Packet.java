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

package org.red5.net.websocket.model;

import org.apache.mina.core.buffer.IoBuffer;

/**
 * Defines the class whose objects are understood by websocket encoder.
 * 
 * @author Dhruv Chopra
 * @author Paul Gregoire
 */
public class Packet {

    private final IoBuffer data;

    private final MessageType type;

    private Packet(byte[] buf) {
        this.data = IoBuffer.wrap(buf);
        this.type = MessageType.BINARY;
    }

    private Packet(byte[] buf, MessageType type) {
        this.data = IoBuffer.wrap(buf);
        this.type = type;
    }

    /**
     * Returns the data.
     * 
     * @return data
     */
    public IoBuffer getData() {
        return data;
    }

    /**
     * Returns the message type.
     * 
     * @return type
     */
    public MessageType getType() {
        return type;
    }

    /**
     * Builds the packet which just wraps the IoBuffer.
     * 
     * @param buf
     * @return packet
     */
    public static Packet build(byte[] buf) {
        return new Packet(buf);
    }

    /**
     * Builds the packet which just wraps the IoBuffer.
     * 
     * @param buffer
     * @return packet
     */
    public static Packet build(IoBuffer buffer) {
        if (buffer.hasArray()) {
            return new Packet(buffer.array());
        }
        byte[] buf = new byte[buffer.remaining()];
        buffer.get(buf);
        return new Packet(buf);
    }

    public static Packet build(MessageType type) {
        return new Packet(new byte[0], type);
    }

    public static Packet build(byte[] bytes, MessageType type) {
        return new Packet(bytes, type);
    }

}
