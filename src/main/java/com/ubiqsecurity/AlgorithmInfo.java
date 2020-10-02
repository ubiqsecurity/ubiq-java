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

// Supports AES-GCM only!
class AlgorithmInfo {
    private static AlgorithmInfo[] supportedAlgorithms = new AlgorithmInfo[] {
            new AlgorithmInfo((byte) 0, "AES-256-GCM", 32, 12, 16),
            new AlgorithmInfo((byte) 1, "AES-128-GCM", 16, 12, 16) };

    private byte id;
    private String name;
    private int keyLength;          // in bytes
    private int initVectorLength;   // in bytes
    private int macLength;          // in bytes

    private AlgorithmInfo(byte id, String name, int keyLength, int initVectorLength, int macLength) {
        this.id = id;
        this.name = name;
        this.keyLength = keyLength;
        this.initVectorLength = initVectorLength;
        this.macLength = macLength;
    }

    AlgorithmInfo(String name) {
        AlgorithmInfo match = null;
        for (int ii = 0; ii < supportedAlgorithms.length; ii++) {
            if (supportedAlgorithms[ii].name.equals(name)) {
                match = supportedAlgorithms[ii];
                break;
            }
        }

        if (match == null) {
            throw new IllegalArgumentException("algorithm not found");
        }

        this.id = match.id;
        this.name = match.name;
        this.keyLength = match.keyLength;
        this.initVectorLength = match.initVectorLength;
        this.macLength = match.macLength;
    }

    AlgorithmInfo(byte id) {
        AlgorithmInfo match = null;
        for (int ii = 0; ii < supportedAlgorithms.length; ii++) {
            if (supportedAlgorithms[ii].id == id) {
                match = supportedAlgorithms[ii];
                break;
            }
        }

        if (match == null) {
            throw new IllegalArgumentException("algorithm not found");
        }

        this.id = match.id;
        this.name = match.name;
        this.keyLength = match.keyLength;
        this.initVectorLength = match.initVectorLength;
        this.macLength = match.macLength;
    }

    byte getId() {
        return this.id;
    }

    String getName() {
        return this.name;
    }

    int getKeyLength() {
        return this.keyLength;
    }

    int getInitVectorLength() {
        return this.initVectorLength;
    }

    int getMacLength() {
        return this.macLength;
    }
}
