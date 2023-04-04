package com.ubiqsecurity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

class FPEBillingResponse {


    @SerializedName("message")
    String message;

    @SerializedName("status")
    int status;

    FPEBillingResponse(int status, String message) {
      this.message = message;
      this.status = status;
    }
  
}
