package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;

import java.util.concurrent.ExecutionException;


import java.lang.UnsupportedOperationException;

public class EncodeKeyNumberOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          FFS_Record dataset = context.getDataset();
          return StringUtils.encodeKeyNumber(context.getCurrentValue(), dataset.getOutputCharacterSet(), dataset.getMsbEncodingBits(), context.getKeyNumber());
        }
}
