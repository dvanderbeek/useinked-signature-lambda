package com.serverless;

public class SigningRequest {
  String filename;

  public String getFilename() {
      return filename;
  }

  public void setFilename(String filename) {
      this.filename = filename;
  }

  public SigningRequest(String filename) {
      this.filename = filename;
  }

  public SigningRequest() {
  }
}
