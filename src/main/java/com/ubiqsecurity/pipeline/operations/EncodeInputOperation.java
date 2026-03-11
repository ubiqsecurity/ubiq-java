package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import java.nio.charset.StandardCharsets;

import java.util.Base64;
import com.google.common.io.BaseEncoding;
import java.lang.UnsupportedOperationException;
import java.util.concurrent.ExecutionException;

public class EncodeInputOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          boolean verbose = false;
          String inputEncoding = context.getDataset().getInputEncoding();
          String ret = context.getCurrentValue();
          if (verbose) System.out.printf("%s   : %s Start: inputEncoding: %s getCurrentValue: %s\n",this.getClass().getName(), new java.util.Date(), inputEncoding, ret);
            if (inputEncoding == null || inputEncoding.trim().isEmpty()) {
              // NOP - nothing to do
            } else if (inputEncoding.equals("base64")) {
              ret = Base64.getEncoder().encodeToString(context.getCurrentValue().getBytes(StandardCharsets.UTF_8));
            } else if (inputEncoding.equals("base32")) {
              ret =  BaseEncoding.base32().encode(context.getCurrentValue().getBytes(StandardCharsets.UTF_8));
            } else {
              throw new UnsupportedOperationException("context.dataset.inputEncoding value '" + inputEncoding + "' is not currently supported");
            }
            if (verbose) System.out.printf("%s   : %s End: inputEncoding: %s getCurrentValue: %s\n",this.getClass().getName(), new java.util.Date(), inputEncoding, ret);
            return ret;
        }
}
