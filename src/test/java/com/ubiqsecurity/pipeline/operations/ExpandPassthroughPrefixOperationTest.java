package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.lang.UnsupportedOperationException;

import org.junit.Test;
import static org.junit.Assert.*;

public class ExpandPassthroughPrefixOperationTest {

  private OperationContext setup() throws Exception {
    OperationContext oc = new OperationContext();
    FFS_Record dataset = new FFS_Record();

    List<DatasetPassthroughRule> rules = new ArrayList<DatasetPassthroughRule>();
    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("prefix");
    pr.setPriority(1);
    pr.setValue("3");
    rules.add(pr);

    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();

    oc.setCurrentValue("123");
    oc.setDataset(dataset);

    oc.getData().put("Prefix", "abc");

    return oc;
  }


  @Test
  public void simple_NoPrefixRules_ReturnsCurrentValue() throws Exception {
    OperationContext context = setup();
    FFS_Record dataset = context.getDataset();
    dataset.setPassthrough_Rules(new ArrayList<DatasetPassthroughRule>());
    dataset.completeDeserialization();
    context.setDataset(dataset);

    Operation op = new ExpandPassthroughPrefixOperation();

    assertEquals(op.Invoke(context), "123");

  }


  @Test
  public void simple_NoPrefix_ReturnsCurrentValue() throws Exception {
    OperationContext context = setup();

    context.getData().remove("Prefix");

    Operation op = new ExpandPassthroughPrefixOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "123");

  }

  @Test
  public void simple_PrefixExists_ReturnsFormattedValue() throws Exception {
    OperationContext context = setup();

    Operation op = new ExpandPassthroughPrefixOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "abc123");

  }

}
