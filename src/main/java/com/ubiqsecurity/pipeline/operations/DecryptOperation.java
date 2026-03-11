package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;
import com.ubiqsecurity.FFS_KeyId;
import com.ubiqsecurity.FFX_Ctx;

import java.lang.IllegalArgumentException;
import java.util.concurrent.ExecutionException;


import java.lang.UnsupportedOperationException;

public class DecryptOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String currentValue = context.getCurrentValue();
          FFS_Record dataset = context.getDataset();

          if (context.getIsEncrypt()) {
            throw new UnsupportedOperationException("DecryptOperation not allowed in a encryption pipeline");
          }

          if (currentValue.length() < dataset.getMinInputLength()) {
            throw new IllegalArgumentException("Input length is less than the dataset's minimum input length");
          }
          if (currentValue.length() > dataset.getMaxInputLength()) {
            throw new IllegalArgumentException("Input length is greater than the dataset's maximum input length");
          }

          FFX_Ctx ctx = context.getFfxCache().FFXCache.get(new FFS_KeyId(dataset, context.getKeyNumber()));

          return ctx.getFF1().decrypt(currentValue, context.getUserSuppliedTweak());
        }
}
