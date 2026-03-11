package com.ubiqsecurity.pipeline.operations;
import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.lang.UnsupportedOperationException;

import org.junit.Test;
import static org.junit.Assert.*;

public class ExpandPassthroughCharactersOperationTest {

  private OperationContext setup() throws Exception {
    OperationContext oc = new OperationContext();
    oc.setIsEncrypt(true);
    FFS_Record dataset = new FFS_Record();

    dataset.setInputCharacterSet("abc123");
    dataset.setOutputCharacterSet("xyz456");

    List<DatasetPassthroughRule> rules = new ArrayList<DatasetPassthroughRule>();
    DatasetPassthroughRule pr = new DatasetPassthroughRule();
    pr.setType("passthrough");
    pr.setPriority(1);
    pr.setValue("-");
    rules.add(pr);

    dataset.setPassthrough_Rules(rules);
    dataset.completeDeserialization();

    oc.setOriginalValue("abc-123");
    oc.setCurrentValue("654zyx");
    oc.setDataset(dataset);

    oc.getData().put("PassthroughTemplate", "xxx-xxx");

    return oc;
  }


  @Test
  public void simple_NoPassthroughRules_ReturnsCurrentValue() throws Exception {
    OperationContext context = setup();
    FFS_Record dataset = context.getDataset();
    dataset.setPassthrough_Rules(new ArrayList<DatasetPassthroughRule>());
    dataset.completeDeserialization();
    context.setDataset(dataset);
    context.setData(new HashMap<>());

    Operation op = new ExpandPassthroughCharactersOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "654zyx");

  }


  @Test
  public void simple_NoPassthroughTemplate_ReturnsCurrentValue() throws Exception {
    OperationContext context = setup();

    context.getData().remove("PassthroughTemplate");

    Operation op = new ExpandPassthroughCharactersOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "654zyx");

  }

  @Test
  public void simple_ValidPassthroughTemplate_ReturnsFormattedValue() throws Exception {
    OperationContext context = setup();

    Operation op = new ExpandPassthroughCharactersOperation();

    String encoded = op.Invoke(context);

    assertEquals(encoded, "654-zyx");

  }

}
