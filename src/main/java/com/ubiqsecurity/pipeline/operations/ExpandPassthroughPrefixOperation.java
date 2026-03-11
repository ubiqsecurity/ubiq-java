package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;


import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class ExpandPassthroughPrefixOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String ret = context.getCurrentValue();
          Integer prefixLength = context.getDataset().getPassthroughPrefixLength();

          if (prefixLength == null || prefixLength == 0 || !context.getData().containsKey("Prefix")) {
            // NOP
          } else {
            ret = context.getData().get("Prefix") + context.getCurrentValue();
          }
          return ret;
        }
}
