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

package org.red5.net.websocket.util;

import java.util.concurrent.ThreadLocalRandom;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;

/**
 * Id generator.
 * 
 * @author Paul Gregoire
 */
public class IdGenerator {

    private static final DigestRandomGenerator random = new DigestRandomGenerator(new SHA1Digest());

    /**
     * Returns a cryptographically generated id.
     * 
     * @return id
     */
    public static final long generateId() {
        long id = 0;
        // add new seed material from current time
        random.addSeedMaterial(ThreadLocalRandom.current().nextLong());
        // get a new id
        byte[] bytes = new byte[16];
        // get random bytes
        random.nextBytes(bytes);
        for (int i = 0; i < bytes.length; i++) {
            id += ((long) bytes[i] & 0xffL) << (8 * i);
        }
        //System.out.println("Id: " + id);
        return id;
    }

}
