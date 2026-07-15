package burp;

public interface IHttpRequestResponse {
    byte[] getRequest();

    byte[] getResponse();

    IHttpService getHttpService();

    default String getHighlight() {
        return null;
    }

    default void setHighlight(String color) {
    }
}
