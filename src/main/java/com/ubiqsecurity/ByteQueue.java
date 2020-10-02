/*
 * Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains the property
 * of Ubiq Security, Inc. The intellectual and technical concepts contained
 * herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
 * covered by U.S. and Foreign Patents, patents in process, and are
 * protected by trade secret or copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden
 * unless prior written permission is obtained from Ubiq Security, Inc.
 *
 * Your use of the software is expressly conditioned upon the terms
 * and conditions available at:
 *
 *     https://ubiqsecurity.com/legal
 *
 */

package com.ubiqsecurity;

class ByteQueue {
    private byte[] buffer;      // never null, but can be empty

    // 'data' can be null
    ByteQueue(byte[] data) {
        if (data != null) {
            this.buffer = data;
        } else {
            this.buffer = new byte[0];
        }
    }

    int getLength() {
        return this.buffer.length;
    }

    // quick + dirty: a stronger impl would return a cloned *copy* of the buffer
    byte[] peek() {
        return this.buffer;
    }

    void enqueue(byte[] data, int offset, int count) {
        if ((offset + count) > data.length) {
            throw new IllegalArgumentException("offset + count would cause overflow");
        }

        if (count > 0) {
            var newBuffer = new byte[this.buffer.length + count];
            System.arraycopy(this.buffer, 0, newBuffer, 0, this.buffer.length);
            System.arraycopy(data, offset, newBuffer, this.buffer.length, count);
            this.buffer = newBuffer;
        }
    }

    byte[] dequeue(int count) {
        if (count > this.buffer.length) {
            throw new IllegalArgumentException("count exceeds Length");
        }

        // copy bytes from front of original buffer
        byte[] dequeuedBytes = new byte[count];
        System.arraycopy(this.buffer, 0, dequeuedBytes, 0, dequeuedBytes.length);

        // strip dequeued bytes from front of original buffer
        var newBuffer = new byte[this.buffer.length - count];
        System.arraycopy(this.buffer, count, newBuffer, 0, newBuffer.length);
        this.buffer = newBuffer;

        return dequeuedBytes;
    }
}
