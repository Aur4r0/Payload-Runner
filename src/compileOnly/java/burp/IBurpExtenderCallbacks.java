package burp;

import java.awt.Component;

public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);

    void registerContextMenuFactory(IContextMenuFactory factory);

    void addSuiteTab(ITab tab);

    void customizeUiComponent(Component component);

    IExtensionHelpers getHelpers();

    IMessageEditor createMessageEditor(IMessageEditorController controller, boolean editable);

    IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request);

    void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption);

    void saveExtensionSetting(String name, String value);

    String loadExtensionSetting(String name);

    void printError(String message);
}
