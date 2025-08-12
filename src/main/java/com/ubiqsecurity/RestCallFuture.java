package com.ubiqsecurity;

import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;

class RestCallFuture {
  Future future;
  String payload;
  Integer processingCount;
  ExecutorService execService;

  RestCallFuture(ExecutorService execService, Future future,  String payload, Integer count) {
    this.execService = execService;
    this.future = future;
    this.payload = payload;
    this.processingCount = count;
  }
}
