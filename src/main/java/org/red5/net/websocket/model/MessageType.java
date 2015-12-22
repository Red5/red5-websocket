package org.red5.net.websocket.model;

public enum MessageType {

    CONTINUATION((byte) 0), TEXT((byte) 1), BINARY((byte) 2), CLOSE((byte) 8), PING((byte) 9), PONG((byte) 0xa);

    private byte type;

    MessageType(byte type) {
        this.type = type;
    }

    byte getType() {
        return type;
    }

}
