package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;

import org.junit.Test;
import static org.junit.Assert.*;

public class PadInputOperationTest {

  private OperationContext setup() {
    OperationContext oc = new OperationContext();
    FFS_Record dataset = new FFS_Record();
    dataset.setInputCharacterSet("1234567890");
    dataset.setOutputCharacterSet("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    dataset.setInputPadCharacter('*');
    dataset.setMinInputLength(10);

    List<DatasetPassthroughRule> rules = new ArrayList<DatasetPassthroughRule>();
    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("passthrough");
    pr.setPriority(1);
    pr.setValue("-");
    rules.add(pr);
    dataset.setPassthrough_Rules(rules);

    oc.setDataset(dataset);
    oc.setCurrentValue("123-456");

    return oc;
  }


  @Test
  public void simple() {
    try {
      OperationContext context = setup();
      Operation pad = new PadInputOperation();
      String original = context.getCurrentValue();

      String padded = pad.Invoke(context);

      assertEquals(padded, "***123-456");

      Operation unpad = new UnpadInputOperation();
      context.setCurrentValue(padded);

      String unpadded = unpad.Invoke(context);
      assertEquals(unpadded, original);
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }

  @Test
  public void invalidInput() {
    try {
      OperationContext context = setup();
      // Input string will contain pad character
      context.setCurrentValue("123*456");

      Operation pad = new PadInputOperation();
      String original = context.getCurrentValue();

      String padded = pad.Invoke(context);

      assertEquals(false, true);
    } catch (RuntimeException e) {
      assertTrue(e.getMessage().contains("'*'"));
    } catch (Exception e) {
      System.out.println(e.getMessage());
      assertEquals(false, true);
    }
  }

  @Test
  public void simple_none_needed() {
    try {
      OperationContext context = setup();

      HashMap<String, String> data = context.getData();
      data.put("PassthroughTemplate", "xxx-xxx");
      context.setData(data);
      String original = "1234567890";
      Operation op = new PadInputOperation();
      context.setCurrentValue(original);
      String padded = op.Invoke(context);

      assertEquals(padded, original);
      assertEquals(context.getData().get("PassthroughTemplate"), "***xxx-xxx");

      Operation unpad = new UnpadInputOperation();
      context.setCurrentValue(padded);

      String unpadded = unpad.Invoke(context);
      assertEquals(unpadded, original);
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }

  @Test
  public void simple_template_padded() {
    try {
      OperationContext context = setup();

      String original = context.getCurrentValue();
      HashMap<String, String> data = context.getData();
      data.put("PassthroughTemplate", "xxx-xxx");
      context.setData(data);

      Operation op = new PadInputOperation();
      String padded = op.Invoke(context);

      assertEquals(padded, "***123-456");
      assertEquals(context.getData().get("PassthroughTemplate"), "***xxx-xxx");

      Operation unpad = new UnpadInputOperation();
      context.setCurrentValue(padded);

      String unpadded = unpad.Invoke(context);
      assertEquals(unpadded, original);
      assertEquals(context.getData().get("PassthroughTemplate"), "xxx-xxx");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }

  @Test
  public void trim_pad() {
    try {
      String src = "123045607890";
      String ret = StringUtils.trimLeftPad(src, '0');
      assertEquals(src,ret);

      src = "01230456067890";
      ret = StringUtils.trimLeftPad(src, '0');
      assertEquals(src.substring(1),ret);

      src = "0000";
      ret = StringUtils.trimLeftPad(src, '0');
      assertEquals(ret, "");

      src = "00001";
      ret = StringUtils.trimLeftPad(src, '0');
      assertEquals(ret, "1");

    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }



}
