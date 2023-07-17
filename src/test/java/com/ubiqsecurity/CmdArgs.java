package com.ubiqsecurity;

import com.beust.jcommander.Parameter;

public class CmdArgs {

    @Parameter(
            names = "-c",
            description = "Name of the credentials file"
    )
    public String credentials = null;

    @Parameter(
            names = "-P",
            description = "Identify the profile within the credentials file"
    )
    public String profile = "default";

    @Parameter(
            names = "-i",
            description = "input file name"
    )
    public String inputFileName = null;

    @Parameter(
            names = {"--help", "-h"},
            description = "Print app parameter summary",
            help = true
    )
    public boolean help;

    @Parameter(
      names = "-e", 
      description = "Maximum allowed average encrypt time in microseconds.  Not including first call to server" )
    public Long max_avg_encrypt = null;

    @Parameter(
      names = "-d", 
      description = "Maximum allowed average decrypt time in microseconds.  Not including first call to server" )
    public Long max_avg_decrypt = null;

    @Parameter(
      names = "-E", 
      description = "Maximum allowed total encrypt time in microseconds.  Not including first call to server" )
    public Long max_total_encrypt = null;

    @Parameter(
      names = "-D", 
      description = "Maximum allowed total decrypt time in microseconds.  Not including first call to server" )
    public Long max_total_decrypt = null;

}
