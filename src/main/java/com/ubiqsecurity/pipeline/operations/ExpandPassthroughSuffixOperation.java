package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;


import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class ExpandPassthroughSuffixOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String ret = context.getCurrentValue();
          Integer suffixLength = context.getDataset().getPassthroughSuffixLength();

          if (suffixLength == null || suffixLength == 0 || !context.getData().containsKey("Suffix")) {
            // NOP
          } else {
            ret = context.getCurrentValue() + context.getData().get("Suffix");
          }
          return ret;
        }
}
