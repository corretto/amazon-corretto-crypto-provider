// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import com.amazon.corretto.crypto.provider.test.integration.TestHTTPSServer;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Setup;
//import org.openjdk.jmh.annotations.Teardown;
import org.openjdk.jmh.annotations.Threads;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.SSLSocket;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


@State(Scope.Benchmark)
public class TlsHandshake {

    private TestHTTPSServer server;

    // TODO [childw] odify TestHTTPSServer to allow turning BC off
    //@Param({ AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC", "SUN" })
    @Param({ AmazonCorrettoCryptoProvider.PROVIDER_NAME, "BC" })
    public String provider;

    @Setup
    public void setup() throws Exception {
        BenchmarkUtils.setupProvider(provider);
        server = TestHTTPSServer.launch(provider.equals(AmazonCorrettoCryptoProvider.PROVIDER_NAME));
    }

    //@Teardown
    public void teardown() throws Exception {
        server.kill();
    }

    @Benchmark
    @Threads(1)
    public void singleThreaded() throws Exception {
        SSLSocket client = new SSLSocket("127.0.0.1", server.getPort());
        client.setUseClientMode(true);
        client.startHandshake();
        client.close();
    }

    //@Benchmark
    //@Threads(Threads.MAX)
    //public byte[] multiThreaded() {
        //random.nextBytes(data);
        //return data;
    //}
}

