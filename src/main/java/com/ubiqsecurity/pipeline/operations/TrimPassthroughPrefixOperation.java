package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;
import java.lang.StringBuilder;




import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class TrimPassthroughPrefixOperation implements Operation {
        private final static boolean verbose= false;

        public String Invoke(OperationContext context) throws ExecutionException
        {
          String ret = context.getCurrentValue();

          Integer prefixLength = context.getDataset().getPassthroughPrefixLength();

          if (prefixLength == null || prefixLength == 0) {
            // NOP
          } else {
            context.getData().put("Prefix", context.getCurrentValue().substring(0, prefixLength));
            if (verbose) System.out.println("Prefix: '" + context.getCurrentValue().substring(0, prefixLength) + "'");
            ret = context.getCurrentValue().substring(prefixLength);
            if (verbose) System.out.println("ret: '" + ret + "'");
          }
          return ret;
        }
}
