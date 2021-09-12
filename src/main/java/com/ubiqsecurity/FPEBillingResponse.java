package com.ubiqsecurity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

class FPEBillingResponse {
    @SerializedName("message")
    String message;

    @SerializedName("status")
    int status;

    @SerializedName("last_valid")
    LastValidRecord last_valid;

}

class LastValidRecord {

    @SerializedName("id")
    String id;
}

// {"message":"Invalid FFS Name UNKNOWN_FFS","status":400,"last_valid":{"id":"716365fc-329d-4b27-a285-4016a95867fa"}}