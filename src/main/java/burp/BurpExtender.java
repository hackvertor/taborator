package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener, IContextMenuFactory, IHttpListener {
    private String extensionName = "Taborator";
    private String extensionVersion = "0.1";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stderr;
    private PrintWriter stdout;
    private JPanel panel;
    private volatile boolean running;
    private int unread = 0;
    long pollEveryMS = 3000;
    private Date lastPollDate = null;
    private ArrayList<Integer> readRows = new ArrayList<Integer>();
    private IBurpCollaboratorClientContext collaborator = null;
    private HashMap<Integer, IBurpCollaboratorInteraction> interactionHistory = new HashMap<>();
    private int selectedRow = -1;
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        callbacks.registerExtensionStateListener(this);
        callbacks.registerContextMenuFactory(this);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName(extensionName);
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                stdout.println(extensionName + " " + extensionVersion);
                running = true;
                panel = new JPanel(new BorderLayout());
                JSplitPane collaboratorClientSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                collaboratorClientSplit.setResizeWeight(.5d);
                DefaultTableModel model = new DefaultTableModel() {
                    @Override
                    public boolean isCellEditable(int row, int column) {
                        return false;
                    }
                };
                JTable collaboratorTable = new JTable(model);
                collaboratorTable.setAutoCreateRowSorter(true);
                model.addColumn("#");
                model.addColumn("Time");
                model.addColumn("Type");
                model.addColumn("IP");
                model.addColumn("Payload");
                model.addColumn("Comment");
                JScrollPane collaboratorScroll = new JScrollPane(collaboratorTable);
                collaboratorTable.setFillsViewportHeight(true);
                collaboratorClientSplit.setTopComponent(collaboratorScroll);
                collaboratorClientSplit.setBottomComponent(new JPanel());
                panel.add(collaboratorClientSplit, BorderLayout.CENTER);
                callbacks.addSuiteTab(BurpExtender.this);
                collaborator = callbacks.createBurpCollaboratorClientContext();
                collaboratorTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer()
                {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)
                    {
                        final Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                        if(isSelected) {
                            if(!readRows.contains(row)) {
                                c.setFont(c.getFont().deriveFont(Font.PLAIN));
                                readRows.add(row);
                                unread--;
                            }
                            if(selectedRow != row) {
                                JTabbedPane interactionsTab = new JTabbedPane();
                                JPanel descriptionPanel = new JPanel(new BorderLayout());
                                int collaboratorID = (int) collaboratorTable.getModel().getValueAt(row, 0);
                                IBurpCollaboratorInteraction interaction = interactionHistory.get(collaboratorID);
                                JTextArea description = new JTextArea();
                                description.setEditable(false);
                                description.setBorder(null);
                                interactionsTab.addTab("Description", descriptionPanel);
                                if(interaction.getProperty("type").equals("DNS")) {
                                    TaboratorMessageEditorController taboratorMessageEditorController = new TaboratorMessageEditorController();
                                     description.setText("The Collaborator server received a DNS lookup of type "+interaction.getProperty("query_type")+" for the domain name "+interaction.getProperty("interaction_id")+"."+collaborator.getCollaboratorServerLocation()+".\n\n" +
                                             "The lookup was received from IP address "+interaction.getProperty("client_ip")+" at "+interaction.getProperty("time_stamp"));
                                     IMessageEditor messageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                     messageEditor.setMessage(helpers.base64Decode(interaction.getProperty("raw_query")), false);
                                     interactionsTab.addTab("DNS query", messageEditor.getComponent());
                                } else if(interaction.getProperty("type").equals("HTTP")) {
                                    TaboratorMessageEditorController taboratorMessageEditorController = new TaboratorMessageEditorController();
                                    URL collaboratorURL = null;
                                    try {
                                        collaboratorURL = new URL(interaction.getProperty("protocol").toLowerCase()+"://"+collaborator.getCollaboratorServerLocation());
                                    } catch (MalformedURLException e) {
                                        stderr.println("Failed parsing Collaborator URL:"+e.toString());
                                    }
                                    if(collaboratorURL != null) {
                                        IHttpService httpService = helpers.buildHttpService(collaboratorURL.getHost(), collaboratorURL.getPort() == -1 ? collaboratorURL.getDefaultPort() : collaboratorURL.getPort(), interaction.getProperty("protocol").equals("HTTPS"));
                                        taboratorMessageEditorController.setHttpService(httpService);
                                    }
                                    byte[] collaboratorResponse = helpers.base64Decode(interaction.getProperty("response"));
                                    byte[] collaboratorRequest = helpers.base64Decode(interaction.getProperty("request"));
                                    taboratorMessageEditorController.setRequest(collaboratorRequest);
                                    taboratorMessageEditorController.setResponse(collaboratorResponse);
                                    description.setText("The Collaborator server received an "+interaction.getProperty("protocol")+" request.\n\nThe request was received from IP address "+interaction.getProperty("client_ip")+" at "+interaction.getProperty("time_stamp"));
                                    interactionsTab.addTab("Original request", new JPanel());
                                    IMessageEditor requestMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                    requestMessageEditor.setMessage(collaboratorRequest, true);
                                    interactionsTab.addTab("Request to Collaborator", requestMessageEditor.getComponent());
                                    IMessageEditor responseMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                    responseMessageEditor.setMessage(collaboratorResponse, true);
                                    interactionsTab.addTab("Response from Collaborator", responseMessageEditor.getComponent());
                                }
                                description.setBorder(BorderFactory.createCompoundBorder(description.getBorder(), BorderFactory.createEmptyBorder(10, 10, 10, 10)));
                                descriptionPanel.add(description);
                                collaboratorClientSplit.setBottomComponent(interactionsTab);
                                selectedRow = row;
                                updateTab();
                            }
                        } else {
                            if(!readRows.contains(row)) {
                                c.setFont(c.getFont().deriveFont(Font.BOLD));
                            }
                        }
                        return c;
                    }
                });
                Runnable collaboratorRunnable = new Runnable() {
                    public void run() {
                        while(running){
                            Date date = new Date();
                            if(lastPollDate == null || (date.getTime() - lastPollDate.getTime()) > pollEveryMS) {
                                lastPollDate = date;
                                List<IBurpCollaboratorInteraction> interactions = collaborator.fetchAllCollaboratorInteractions();
                                for(int i=0;i<interactions.size();i++) {
                                    IBurpCollaboratorInteraction interaction =  interactions.get(i);
                                    int rowID = model.getRowCount()+1;
                                    model.addRow(new Object[]{rowID, interaction.getProperty("time_stamp"), interaction.getProperty("type"), interaction.getProperty("client_ip"), interaction.getProperty("interaction_id"), ""});
                                    unread++;
                                    interactionHistory.put(rowID, interaction);
                                }
                                updateTab();
                            }
                            try {
                                Thread.sleep(pollEveryMS);
                            } catch (InterruptedException e) {
                                stderr.println(e.toString());
                                return;
                            }
                        }
                    }
                };
                new Thread(collaboratorRunnable).start();
            }
        });
    }
    @Override
    public Component getUiComponent() {
        return panel;
    }
    @Override
    public String getTabCaption() {
        return extensionName + " ("+unread+")";
    }

    private void updateTab() {
        JTabbedPane tp = (JTabbedPane) BurpExtender.this.getUiComponent().getParent();
        int tIndex = getTabIndex(BurpExtender.this);
        if(tIndex > -1) {
            tp.setTitleAt(tIndex, getTabCaption());
        }
    }

    private int getTabIndex(ITab your_itab) {
        JTabbedPane parent = (JTabbedPane) your_itab.getUiComponent().getParent();
        for(int i = 0; i < parent.getTabCount(); ++i) {
            if(parent.getTitleAt(i).contains(extensionName+" (")) {
                return i;
            }
        }
        return -1;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(!messageIsRequest) {
            return;
        }
        switch(toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                if(!tagsInProxy) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                if(!tagsInIntruder) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                if(!tagsInRepeater) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                if(!tagsInScanner) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                if(!tagsInExtensions) {
                    return;
                }
                break;
            default:
                return;
        }
        byte[] request = messageInfo.getRequest();
        if(helpers.indexOf(request,helpers.stringToBytes("<@"), true, 0, request.length) > -1) {
            Hackvertor hv = new Hackvertor();
            request = helpers.stringToBytes(hv.convert(helpers.bytesToString(request)));
            if(autoUpdateContentLength) {
                request = fixContentLength(request);
            }
            messageInfo.setRequest(request);
        }
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        int[] bounds = invocation.getSelectionBounds();

        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
                break;
            default:
                return null;
        }
        List<JMenuItem> menu = new ArrayList<JMenuItem>();
        JMenu submenu = new JMenu(extensionName);
        JMenuItem createPayload = new JMenuItem("Insert Collaborator payload");
        createPayload.addActionListener(e -> {
            if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                try {
                    outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                    outputStream.write(helpers.stringToBytes(collaborator.generatePayload(true)));
                    outputStream.write(Arrays.copyOfRange(message, bounds[1],message.length));
                    outputStream.flush();
                    invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                } catch (IOException e1) {
                    System.err.println(e1.toString());
                }
            }
        });
        JMenuItem createPlaceholder = new JMenuItem("Insert Collaborator placeholder");
        createPlaceholder.addActionListener(e -> {
            if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                try {
                    outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                    outputStream.write(helpers.stringToBytes("$collab"));
                    outputStream.write(Arrays.copyOfRange(message, bounds[1],message.length));
                    outputStream.flush();
                    invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                } catch (IOException e1) {
                    System.err.println(e1.toString());
                }
            }
        });
        submenu.add(createPayload);
        submenu.add(createPlaceholder);
        menu.add(submenu);
        return menu;
    }

    @Override
    public void extensionUnloaded() {
        stdout.println(extensionName + " unloaded");
        running = false;
    }
}