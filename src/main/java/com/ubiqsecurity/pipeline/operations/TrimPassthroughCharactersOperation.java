package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;
import java.lang.StringBuilder;




import java.util.Base64;
import java.util.concurrent.ExecutionException;

public class TrimPassthroughCharactersOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String ret = context.getCurrentValue();

          String passthroughCharacterSet = context.getDataset().getPassthroughCharacterSet();
          if (StringUtils.isNullOrEmpty(passthroughCharacterSet)) {
            // NOP - Return existing current value
           } else {
            // Get the first character of either the output or input character set
            char templateChar = context.getIsEncrypt() ? context.getDataset().getOutputCharacterSet().charAt(0) :  context.getDataset().getInputCharacterSet().charAt(0);
            StringBuilder templateBuilder = new StringBuilder();
            StringBuilder trimmedBuilder = new StringBuilder();

            for (char c : context.getCurrentValue().toCharArray()) {
              // Character is in the passthrough character set
              if (passthroughCharacterSet.indexOf(c) != -1) {
                templateBuilder.append(c);
              } else {
                   trimmedBuilder.append(c);
                  templateBuilder.append(templateChar);
              }
            }

            context.getData().put("PassthroughTemplate", templateBuilder.toString());
            ret = trimmedBuilder.toString();
           }

          return ret;
        }
}
