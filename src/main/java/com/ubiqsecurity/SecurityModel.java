package com.ubiqsecurity;

import com.google.gson.annotations.SerializedName;

class SecurityModel {
    @SerializedName("algorithm")
    String Algorithm;

    @SerializedName("enable_data_fragmentation")
    boolean EnableDataFragmentation;
}
