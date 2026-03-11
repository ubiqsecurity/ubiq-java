package com.ubiqsecurity.pipeline;


import com.ubiqsecurity.pipeline.operations.*;

import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.StringUtils;
import com.ubiqsecurity.DatasetPassthroughRule;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.ListIterator;

public class DecryptionPipeline extends StructuredPipeline{

  protected static Iterable<Operation> baseOperations = Arrays.asList(
    new DecodeKeyNumberOperation(),
    new ConvertRadixOperation(),
    new DecryptOperation(),
    new UnpadInputOperation(),
    new DecodeInputOperation()
  );

  public DecryptionPipeline() {
    super();

    Iterable<Operation> operations = baseOperations;

    this.operations = operations;
  }


  public DecryptionPipeline(Iterable<Operation> operations) {
      this.operations = operations;
  }

  public DecryptionPipeline(FFS_Record dataset) {
    this();

    // Needs to be a mutable list
    List<Operation> operations = new ArrayList();
    this.operations.forEach(operations::add);

    // Rules are returned in order sorted by priority.  Want to run through this in decending order of priority
    // for (DatasetPassthroughRule rule : dataset.getPassthrough_Rules()) {
    ListIterator<DatasetPassthroughRule> itr = dataset.getPassthrough_Rules().listIterator(dataset.getPassthrough_Rules().size());
    while (itr.hasPrevious()) {
      DatasetPassthroughRule rule = itr.previous();
      switch (rule.getType()) {
        case "passthrough":
          operations.add(0, new TrimPassthroughCharactersOperation());
          operations.add(new ExpandPassthroughCharactersOperation());
          break;
        case "prefix":
          operations.add(0, new TrimPassthroughPrefixOperation());
          operations.add(new ExpandPassthroughPrefixOperation());
          break;
        case "suffix":
          operations.add(0, new TrimPassthroughSuffixOperation());
          operations.add(new ExpandPassthroughSuffixOperation());
          break;
        default:
          // Ignore other rule types
      }
    }

    // If there aren't any passthrough rules but there are passthrough characters from
    // an old dataset, need to add passthrough handing
    if (dataset.getPassthrough_Rules().size() == 0 && !StringUtils.isNullOrEmpty(dataset.getPassthroughCharacterSet())) {
      operations.add(0, new TrimPassthroughCharactersOperation());
      operations.add(new ExpandPassthroughCharactersOperation());
    }

    this.operations = operations;
  }
}
