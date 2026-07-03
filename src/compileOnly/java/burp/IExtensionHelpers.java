package burp;

import java.util.List;

public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(byte[] request);

    IRequestInfo analyzeRequest(IHttpService httpService, byte[] request);

    IResponseInfo analyzeResponse(byte[] response);

    String bytesToString(byte[] data);

    byte[] stringToBytes(String data);

    byte[] buildHttpMessage(List<String> headers, byte[] body);

    String urlEncode(String data);

    String urlDecode(String data);

    IHttpService buildHttpService(String host, int port, String protocol);
}
