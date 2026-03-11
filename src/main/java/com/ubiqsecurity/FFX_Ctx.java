package com.ubiqsecurity;

import com.ubiqsecurity.structured.FF1;


public class FFX_Ctx {
  protected FF1 ctxFF1;
  protected Integer key_number;


  public FF1 getFF1() {
    return ctxFF1;
  }

  public void setFF1(FF1 ctxFF1, Integer key_number) {
    this.ctxFF1 = ctxFF1;
    this.key_number = key_number;
  }

  public int getKeyNumber() {
		return key_number;
	}

}