package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.lang.UnsupportedOperationException;

import org.junit.Test;
import static org.junit.Assert.*;

public class TrimPassthroughCharactersOperationTest {

  private OperationContext setup() {
    OperationContext oc = new OperationContext();
    oc.setIsEncrypt(true);
    FFS_Record dataset = new FFS_Record();

    dataset.setInputCharacterSet("abc123");
    dataset.setOutputCharacterSet("xyz456");

    List<DatasetPassthroughRule> rules = new ArrayList<DatasetPassthroughRule>();
    dataset.setPassthrough_Rules(rules);

    oc.setCurrentValue("abc-123");
    oc.setDataset(dataset);
    return oc;
  }


  @Test
  public void simple_NoPassthroughRules_ReturnsCurrentValue() {
    OperationContext context = setup();
    Operation op = new TrimPassthroughCharactersOperation();

    try {
      String encoded = op.Invoke(context);

      assertEquals(encoded, "abc-123");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }


  @Test
  public void simple_PassthroughCharacterSetEmpty_ReturnsCurrentValue() {
    try {
      OperationContext context = setup();

      FFS_Record dataset = context.getDataset();
      List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

      DatasetPassthroughRule pr = new DatasetPassthroughRule();
      pr.setType("passthrough");
      pr.setPriority(1);
      pr.setValue("");
      rules.add(pr);
      dataset.setPassthrough_Rules(rules);
      context.setDataset(dataset);
      Operation op = new TrimPassthroughCharactersOperation();

      String encoded = op.Invoke(context);

      assertEquals(encoded, "abc-123");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }

  }

  @Test
  public void simple_PassthroughCharactersNotFound_ReturnsCurrentValue() {
    try {
      OperationContext context = setup();

      FFS_Record dataset = context.getDataset();
      List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

      DatasetPassthroughRule pr = new DatasetPassthroughRule();
      pr.setType("passthrough");
      pr.setPriority(1);
      pr.setValue("!");
      rules.add(pr);
      dataset.setPassthrough_Rules(rules);
      context.setDataset(dataset);
      Operation op = new TrimPassthroughCharactersOperation();

      String encoded = op.Invoke(context);

      assertEquals(encoded, "abc-123");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }

  }

  @Test
  public void simple_PassthroughCharactersExists_ReturnsTrimmedValue() throws Exception {
    OperationContext context = setup();

    FFS_Record dataset = context.getDataset();
    List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("passthrough");
    pr.setPriority(1);
    pr.setValue("-");
    rules.add(pr);
    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();
    context.setDataset(dataset);
    Operation op = new TrimPassthroughCharactersOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "abc123");

  }

  @Test
  public void simple_Encrypt_PassthroughTemplateContainsFirstOutputCharacter() throws Exception {
    OperationContext context = setup();

    FFS_Record dataset = context.getDataset();
    List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("passthrough");
    pr.setPriority(1);
    pr.setValue("-");
    rules.add(pr);
    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();
    context.setDataset(dataset);
    Operation op = new TrimPassthroughCharactersOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "abc123");
    assertEquals(context.getData().get("PassthroughTemplate"), "xxx-xxx");

  }


  @Test
  public void simple_Decrypt_PassthroughTemplateContainsFirstInputCharacter() throws Exception {
    OperationContext context = setup();
    context.setIsEncrypt(false);
    FFS_Record dataset = context.getDataset();
    List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("passthrough");
    pr.setPriority(1);
    pr.setValue("-");
    rules.add(pr);
    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();
    context.setDataset(dataset);
    Operation op = new TrimPassthroughCharactersOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "abc123");
    assertEquals(context.getData().get("PassthroughTemplate"), "aaa-aaa");

  }

}
