package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.lang.UnsupportedOperationException;

import org.junit.Test;
import static org.junit.Assert.*;

public class EncodeInputOperationTest {

  private OperationContext setup() {
    OperationContext oc = new OperationContext();
    FFS_Record dataset = new FFS_Record();
    oc.setCurrentValue("1234567890abcde");
    oc.setDataset(dataset);
    return oc;
  }


  @Test
  public void simple() {
    try {
      OperationContext context = setup();
      Operation op = new EncodeInputOperation();

      String encoded = op.Invoke(context);

      assertEquals(encoded, "1234567890abcde");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }

  @Test
  public void simple_base64() {
    try {
      OperationContext context = setup();
      FFS_Record dataset = context.getDataset();
      dataset.setInputEncoding("base64");
      context.setDataset(dataset);

      Operation op = new EncodeInputOperation();
      String encoded = op.Invoke(context);

      assertEquals(encoded, "MTIzNDU2Nzg5MGFiY2Rl");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }

  @Test
  public void simple_base32() {
    try {
      OperationContext context = setup();
      FFS_Record dataset = context.getDataset();
      dataset.setInputEncoding("base32");
      context.setDataset(dataset);

      Operation op = new EncodeInputOperation();

      String encoded = op.Invoke(context);

      assertEquals(encoded, "GEZDGNBVGY3TQOJQMFRGGZDF");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }
}
