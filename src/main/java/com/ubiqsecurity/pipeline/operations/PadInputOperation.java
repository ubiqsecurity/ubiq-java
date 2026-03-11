package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;


import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class PadInputOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String ret = context.getCurrentValue();
          FFS_Record dataset = context.getDataset();

          if (StringUtils.isNullOrEmpty(dataset.getInputPadCharacter())) {
            // NOP
          } else {
            if (context.getCurrentValue().indexOf(dataset.getInputPadCharacter()) != -1) {
              throw new RuntimeException("Input string already includes the padding character: '" + dataset.getInputPadCharacter() + "'");
            }
            // Pad the current value but also padd the template if necessary
            ret = StringUtils.padLeft( dataset.getInputPadCharacter(), dataset.getMinInputLength(),context.getCurrentValue());
            if (context.getData().containsKey("PassthroughTemplate")) {
              context.getData().put("PassthroughTemplate", StringUtils.padLeft( dataset.getInputPadCharacter(), dataset.getMinInputLength(), context.getData().get("PassthroughTemplate")));
            }
          }
          return ret;
        }
}
