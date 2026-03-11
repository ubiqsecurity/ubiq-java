package com.ubiqsecurity.pipeline;

import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

public class StructuredPipeline implements Operation{
  private final static boolean verbose= false;

  protected Iterable<Operation> operations = new ArrayList<Operation>();

  public StructuredPipeline() {
  }


  public StructuredPipeline(Iterable<Operation> operations) {
      this.operations = operations;
  }

  public String Invoke(OperationContext context) throws ExecutionException {
      if (verbose) System.out.println("Start " + this.getClass().getName() + " start: " + context.getCurrentValue());

      for (Operation operation : operations)
      {
        if (verbose) System.out.println("Invoke " + operation.getClass().getName() + " start: " + context.currentValue);
        context.setCurrentValue(operation.Invoke(context));
        if (verbose) System.out.println("Invoke " + operation.getClass().getName() + " end: " + context.currentValue);
      }
      if (verbose) System.out.println("End " + this.getClass().getName() + " end: " + context.getCurrentValue());

      return context.getCurrentValue();
  }
}
