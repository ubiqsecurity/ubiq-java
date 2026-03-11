package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;


import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class UnpadInputOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String ret = context.getCurrentValue();
          FFS_Record dataset = context.getDataset();

          if (StringUtils.isNullOrEmpty(dataset.getInputPadCharacter())) {
            // NOP
          } else {
            // Pad the current value but also pad the template if necessary
            ret = StringUtils.trimLeftPad(context.getCurrentValue(), dataset.getInputPadCharacter());
            if (context.getData().containsKey("PassthroughTemplate")) {
              context.getData().put("PassthroughTemplate", StringUtils.trimLeftPad( context.getData().get("PassthroughTemplate"), dataset.getInputPadCharacter()));
            }
          }
          return ret;
        }
}
