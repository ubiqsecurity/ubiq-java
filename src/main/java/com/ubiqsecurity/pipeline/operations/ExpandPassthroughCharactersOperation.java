package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;


import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class ExpandPassthroughCharactersOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String ret = context.getCurrentValue();
          String passthroughCharacterSet = context.getDataset().getPassthroughCharacterSet();
          if (passthroughCharacterSet == null || passthroughCharacterSet.trim().isEmpty() ||
           !context.getData().containsKey("PassthroughTemplate")) {
            // NOP
           } else {
            ret = StringUtils.formatToTemplate(context.getCurrentValue(), context.getData().get("PassthroughTemplate"), passthroughCharacterSet);
           }

          return ret;
        }
}
