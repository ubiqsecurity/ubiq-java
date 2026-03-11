package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.lang.UnsupportedOperationException;

import org.junit.Test;
import static org.junit.Assert.*;

public class DecodeInputOperationTest {

  private OperationContext setup() {
    OperationContext oc = new OperationContext();
    FFS_Record dataset = new FFS_Record();
    oc.setCurrentValue("1234567890abcde");
    oc.setDataset(dataset);
    return oc;
  }


  @Test
  public void simple_NullInputEncoding_ReturnsCurrentValue() {
    try {
      OperationContext context = setup();
      Operation op = new DecodeInputOperation();

      assertEquals(op.Invoke(context), "1234567890abcde");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }

  @Test
  public void simple_EncodeBase64_ReturnsExpectedBase64DecodedString() {
    try {
      OperationContext context = setup();
      context.setCurrentValue("MTIzNDU2Nzg5MGFiY2Rl");
      FFS_Record dataset = context.getDataset();
      dataset.setInputEncoding("base64");
      context.setDataset(dataset);

      Operation op = new DecodeInputOperation();

      assertEquals(op.Invoke(context), "1234567890abcde");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }

  }

  @Test
  public void simple_EncodeBase32_ThrowsNotImplementedException() {
    try {
      OperationContext context = setup();
      context.setCurrentValue("GEZDGNBVGY3TQOJQMFRGGZDF");
      FFS_Record dataset = context.getDataset();
      dataset.setInputEncoding("base32");
      context.setDataset(dataset);

      Operation op = new DecodeInputOperation();
      assertEquals(op.Invoke(context), "1234567890abcde");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }

  }


}
