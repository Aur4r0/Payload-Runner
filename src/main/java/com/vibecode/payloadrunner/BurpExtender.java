package com.vibecode.payloadrunner;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.ITab;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {
    private PayloadRunnerPanel panel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        panel = new PayloadRunnerPanel(callbacks, helpers);

        callbacks.setExtensionName("Payload Runner");
        callbacks.registerContextMenuFactory(this);
        callbacks.customizeUiComponent(panel);
        callbacks.addSuiteTab(this);
        callbacks.printOutput("Payload Runner loaded successfully.");
        callbacks.printOutput("Right-click a Burp request and choose Send to Payload Runner.");
        callbacks.printOutput("GitHub: https://github.com/Aur4r0/Payload-Runner");
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] selectedMessages = resolveMessages(invocation);

        List<JMenuItem> items = new ArrayList<JMenuItem>();
        JMenuItem sendItem = new JMenuItem("Send to Payload Runner");
        sendItem.addActionListener(event -> panel.addRequests(selectedMessages));
        items.add(sendItem);
        return items;
    }

    @Override
    public String getTabCaption() {
        return "Payload Runner";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    private IHttpRequestResponse[] resolveMessages(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages != null && selectedMessages.length > 0) {
            return selectedMessages;
        }

        Object reflected = invokeNoArg(invocation, "getHttpRequestResponse");
        if (reflected instanceof IHttpRequestResponse) {
            return new IHttpRequestResponse[] {(IHttpRequestResponse) reflected};
        }

        reflected = invokeNoArg(invocation, "getSelectedMessage");
        if (reflected instanceof IHttpRequestResponse) {
            return new IHttpRequestResponse[] {(IHttpRequestResponse) reflected};
        }
        return selectedMessages;
    }

    private Object invokeNoArg(Object target, String methodName) {
        try {
            return target.getClass().getMethod(methodName).invoke(target);
        } catch (RuntimeException ex) {
            return null;
        } catch (Exception ex) {
            return null;
        }
    }
}
