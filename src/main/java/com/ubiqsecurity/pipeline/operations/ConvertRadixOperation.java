package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.StringUtils;
import com.ubiqsecurity.FFS_Record;
import java.util.concurrent.ExecutionException;

public class ConvertRadixOperation implements Operation {
        public String Invoke(OperationContext context)  throws ExecutionException
        {
          String ret = "";
          FFS_Record dataset = context.getDataset();
            if (context.getIsEncrypt())
            {
                ret = StringUtils.convertRadix(context.getCurrentValue(), dataset.getInputCharacterSet(), dataset.getOutputCharacterSet(), false, true);
            } else {
                ret = StringUtils.convertRadix(context.getCurrentValue(), dataset.getOutputCharacterSet(), dataset.getInputCharacterSet(), false, true);
            }
            return ret;
        }
}
