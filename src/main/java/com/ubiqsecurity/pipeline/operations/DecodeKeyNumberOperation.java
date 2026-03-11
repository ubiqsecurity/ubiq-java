package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;
import java.util.concurrent.ExecutionException;



import java.lang.UnsupportedOperationException;

public class DecodeKeyNumberOperation implements Operation {
        final static boolean verbose = false;
        public String Invoke(OperationContext context)  throws ExecutionException
        {
          FFS_Record dataset = context.getDataset();
          Integer[] keyNumber = {0};

          String ret = StringUtils.decodeKeyNumber(context.getCurrentValue(), dataset.getOutputCharacterSet(), dataset.getMsbEncodingBits(), keyNumber);
          if (verbose) System.out.println(this.getClass().getName() + " keyNumber: " + keyNumber[0]);

          context.setKeyNumber(keyNumber[0]);
          return ret;
        }
}
