package com.ubiqsecurity;




public class FFS {
    private String encryption_algorithm;   //e.g. FF1 or FF3_1
    
    private String user;
    private String customer;
    private String name;   //e.g."SSN",
    private String regex;   //e.g. "(\d{3})-(\d{2})-(\d{4})",
    private String tweak_source;   //e.g. "generated",
    private int min_input_length;   //e.g. 9 
    private int max_input_length;   //e.g. 9
    private boolean fpe_definable;
    
    private String cachingKey;
    
	
	public String getAlgorithm() {
		return encryption_algorithm;
	}
	public void setAlgorithm(String encryption_algorithm) {
		this.encryption_algorithm = encryption_algorithm;
		this.cachingKey = this.encryption_algorithm + "-" + this.user;
	}
	
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
		this.cachingKey = this.encryption_algorithm + "-" + this.user;
	}
	
	public String getCustomer() {
		return customer;
	}
	public void setCustomer(String customer) {
		this.customer = customer;
	}
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
	public String getRegex() {
		return regex;
	}
	public void setRegex(String regex) {
		this.regex = regex;
	}
	
	public String getTweak_source() {
		return tweak_source;
	}
	public void setTweak_source(String tweak_source) {
		this.tweak_source = tweak_source;
	}
	
	public int getMin_input_length() {
		return min_input_length;
	}
	public void setMin_input_length(int min_input_length) {
		this.min_input_length = min_input_length;
	}
	
	public int getMax_input_length() {
		return max_input_length;
	}
	public void setMax_input_length(int max_input_length) {
		this.max_input_length = max_input_length;
	}
	
	public boolean getFpe_definable() {
		return fpe_definable;
	}
	public void setFpe_definable(boolean fpe_definable) {
		this.fpe_definable = fpe_definable;
	}
	
	
} 