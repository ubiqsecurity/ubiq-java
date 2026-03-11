package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.lang.UnsupportedOperationException;

import org.junit.Test;
import static org.junit.Assert.*;

public class ExpandPassthroughSuffixOperationTest {

  private OperationContext setup() throws Exception {
    OperationContext oc = new OperationContext();
    FFS_Record dataset = new FFS_Record();

    List<DatasetPassthroughRule> rules = new ArrayList<DatasetPassthroughRule>();
    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("suffix");
    pr.setPriority(1);
    pr.setValue("3");
    rules.add(pr);

    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();

    oc.setCurrentValue("abc");
    oc.setDataset(dataset);

    oc.getData().put("Suffix", "123");

    return oc;
  }


  @Test
  public void simple_NoSuffixRules_ReturnsCurrentValue() throws Exception {
    OperationContext context = setup();
    FFS_Record dataset = context.getDataset();
    dataset.setPassthrough_Rules(new ArrayList<DatasetPassthroughRule>());
    dataset.completeDeserialization();
    context.setDataset(dataset);

    Operation op = new ExpandPassthroughSuffixOperation();

    assertEquals(op.Invoke(context), "abc");
  }


  @Test
  public void simple_NoSuffix_ReturnsCurrentValue() throws Exception {
    OperationContext context = setup();

    context.getData().remove("Suffix");

    Operation op = new ExpandPassthroughSuffixOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "abc");
  }

  @Test
  public void simple_SuffixExists_ReturnsFormattedValue() throws Exception {
    OperationContext context = setup();

    Operation op = new ExpandPassthroughSuffixOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "abc123");
  }

}
