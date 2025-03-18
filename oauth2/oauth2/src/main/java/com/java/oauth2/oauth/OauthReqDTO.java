package com.java.oauth2.oauth;

class OauthReqDTO {

    private String id;
    private String pwd;

    public void setId(String id) {
        this.id = id;
    }
    public void setPwd(String pwd) {
        this.pwd = pwd;
    }
    public String getId() {
        return this.id;
    }
    public String getPwd() {
        return this.pwd;
    }
    public String toString() {
        return "[id:" + this.id + ", pwd:" + this.pwd + "]";
    }

}