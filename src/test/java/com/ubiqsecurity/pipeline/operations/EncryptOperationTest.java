package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;

import org.junit.Test;
import static org.junit.Assert.*;

public class EncryptOperationTest {

  private OperationContext setup() {
    OperationContext oc = new OperationContext();

    FFS_Record dataset = new FFS_Record();
    dataset.setMinInputLength(4);
    oc.setIsEncrypt(true);
    oc.setDataset(dataset);
    oc.setCurrentValue("abc-123");
    return oc;
  }


  @Test
  public void simple_DecryptContext_ThrowsException() {
    OperationContext context = setup();
    context.setIsEncrypt(false);
    Operation op = new EncryptOperation();

    Throwable exception = assertThrows(UnsupportedOperationException.class, () -> op.Invoke(context));
  }

  @Test
  public void simple_CurrentValueLengthLessThanInputMinimum_ThrowsException() {
    OperationContext context = setup();
    context.getDataset().setMinInputLength(11);

    Operation op = new EncryptOperation();

    Throwable exception = assertThrows(IllegalArgumentException.class, () -> op.Invoke(context));
  }

  @Test
  public void simple_CurrentValueLengthGreaterThanInputMaximum_ThrowsException() {
    OperationContext context = setup();
    context.getDataset().setMaxInputLength(1);

    Operation op = new EncryptOperation();

    Throwable exception = assertThrows(IllegalArgumentException.class, () -> op.Invoke(context));
  }

}
