package com.ubiqsecurity.pipeline;

import java.util.concurrent.ExecutionException;

public interface Operation {
  String Invoke(OperationContext context) throws ExecutionException;
}
