package com.ubiqsecurity.pipeline.operations;

import com.ubiqsecurity.pipeline.Operation;
import com.ubiqsecurity.pipeline.OperationContext;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;
import com.ubiqsecurity.FFS_KeyId;
import com.ubiqsecurity.FFX_Ctx;

import java.lang.IllegalArgumentException;
import java.util.concurrent.ExecutionException;

public class EncryptOperation implements Operation {
        public String Invoke(OperationContext context) throws ExecutionException
        {
          String currentValue = context.getCurrentValue();
          FFS_Record dataset = context.getDataset();

          if (!context.getIsEncrypt()) {
            throw new UnsupportedOperationException("EncryptOperation not allowed in a decryption pipeline");
          }

          if (currentValue.length() < dataset.getMinInputLength()) {
            throw new IllegalArgumentException("Input length is less than the dataset's minimum input length");
          }
          if (currentValue.length() > dataset.getMaxInputLength()) {
            throw new IllegalArgumentException("Input length is greater than the dataset's maximum input length");
          }
          String inputChars = dataset.getInputCharacterSet();
          for (int idx = 0; idx < currentValue.length(); idx++) {
              char c = currentValue.charAt(idx);
              if (inputChars.indexOf(c) == -1) {
                  throw new IllegalArgumentException("Input string has invalid character:  '" + c + "'");
              }
          }

          FFX_Ctx ctx = context.getFfxCache().FFXCache.get(new FFS_KeyId(dataset, context.getKeyNumber()));
          // If context.getKeyNumber() is NULL, then use the dataset key_number
          context.setKeyNumber(ctx.getKeyNumber());

          return ctx.getFF1().encrypt(currentValue, context.getUserSuppliedTweak());
        }
}
