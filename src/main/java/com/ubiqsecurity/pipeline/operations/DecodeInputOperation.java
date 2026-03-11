package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;

import java.nio.charset.StandardCharsets;

import java.util.Base64;
import com.google.common.io.BaseEncoding;
import java.lang.UnsupportedOperationException;
import java.util.concurrent.ExecutionException;

public class DecodeInputOperation implements Operation {
        public String Invoke(OperationContext context)  throws ExecutionException
        {
          String inputEncoding = context.getDataset().getInputEncoding();
          String ret = context.getCurrentValue();
            if (inputEncoding == null || inputEncoding.trim().isEmpty()) {
              // NOP - nothing to do
            } else if (inputEncoding.equals("base64")) {
              ret = new String(Base64.getDecoder().decode(context.getCurrentValue()), StandardCharsets.UTF_8);
            } else if (inputEncoding.equals("base32")) {
              ret =  new String(BaseEncoding.base32().decode(context.getCurrentValue()), StandardCharsets.UTF_8);
            } else {
              throw new UnsupportedOperationException("context.dataset.inputEncoding value '" + inputEncoding + "' is not currently supported");
            }
            return ret;
        }
}
