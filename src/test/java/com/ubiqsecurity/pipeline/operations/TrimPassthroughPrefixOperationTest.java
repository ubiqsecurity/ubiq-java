package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.lang.UnsupportedOperationException;

import org.junit.Test;
import static org.junit.Assert.*;

public class TrimPassthroughPrefixOperationTest {

  private OperationContext setup() {
    OperationContext oc = new OperationContext();
    oc.setIsEncrypt(true);
    FFS_Record dataset = new FFS_Record();
    List<DatasetPassthroughRule> rules = new ArrayList<DatasetPassthroughRule>();
    dataset.setPassthrough_Rules(rules);
    oc.setDataset(dataset);

    oc.setCurrentValue("abc123");
    return oc;
  }


  @Test
  public void simple_NoPassthroughRules_ReturnsCurrentValue() {
    try {
      OperationContext context = setup();
      Operation op = new TrimPassthroughPrefixOperation();

      String encoded = op.Invoke(context);

      assertEquals(encoded, "abc123");
    } catch (Exception e) {
      e.printStackTrace();
      assertEquals(false, true);
    }
  }

  @Test
  public void simple_PrefixLengthZero_ReturnsCurrentValue()  throws Exception {
    OperationContext context = setup();

    FFS_Record dataset = context.getDataset();
    List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("prefix");
    pr.setPriority(1);
    pr.setValue(0);
    rules.add(pr);
    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();
    context.setDataset(dataset);
    Operation op = new TrimPassthroughPrefixOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "abc123");
  }

  @Test
  public void simple_PrefixLengthGreaterThanCurrentValueLength_ThrowsException() throws Exception {
    OperationContext context = setup();

    FFS_Record dataset = context.getDataset();
    List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("prefix");
    pr.setPriority(1);
    pr.setValue(7);
    rules.add(pr);
    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();
    context.setDataset(dataset);
    Operation op = new TrimPassthroughPrefixOperation();

    Throwable exception = assertThrows(IndexOutOfBoundsException.class, () -> op.Invoke(context));
  }

  @Test
  public void simple_PrefixLengthEqualToCurrentValueLength_ReturnsEmptyString()  throws Exception {
    OperationContext context = setup();

    FFS_Record dataset = context.getDataset();
    List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("prefix");
    pr.setPriority(1);
    pr.setValue(6);
    rules.add(pr);
    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();
    context.setDataset(dataset);
    Operation op = new TrimPassthroughPrefixOperation();

    assertEquals(op.Invoke(context), "");
    assertEquals(context.getData().get("Prefix"), "abc123");
  }

  @Test
  public void simple_PrefixLengthThree_ReturnsTrimmedValue()  throws Exception {
    OperationContext context = setup();

    FFS_Record dataset = context.getDataset();
    List<DatasetPassthroughRule> rules = dataset.getPassthrough_Rules();

    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("prefix");
    pr.setPriority(1);
    pr.setValue(4);
    rules.add(pr);
    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();
    context.setDataset(dataset);
    Operation op = new TrimPassthroughPrefixOperation();

    assertEquals(op.Invoke(context), "23");
    assertEquals(context.getData().get("Prefix"), "abc1");
  }


}
