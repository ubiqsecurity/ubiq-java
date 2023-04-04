package com.ubiqsecurity;

import java.util.concurrent.Future;

class RestCallFuture {
  Future future;
  String payload;
  Integer processingCount;

  RestCallFuture( Future future,  String payload, Integer count) {
    this.future = future;
    this.payload = payload;
    this.processingCount = count;
  }
}