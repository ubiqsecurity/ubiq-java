package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;
import java.lang.StringBuilder;




import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class TrimPassthroughSuffixOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String ret = context.getCurrentValue();

          Integer suffixLength = context.getDataset().getPassthroughSuffixLength();

          if (suffixLength == null || suffixLength == 0) {
            // NOP
          } else {
            String currentValue = context.getCurrentValue();
            context.getData().put("Suffix", currentValue.substring(currentValue.length() - suffixLength));
            ret = currentValue.substring(0, currentValue.length() - suffixLength);
          }
          return ret;
        }
}
