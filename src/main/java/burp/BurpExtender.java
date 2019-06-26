package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    private ArrayList<Integer> readRows = new ArrayList<Integer>();
    private IBurpCollaboratorClientContext collaborator = null;
    private HashMap<Integer, IBurpCollaboratorInteraction> interactionHistory = new HashMap<>();
    private HashMap<String, IHttpRequestResponse> originalRequests = new LimitedHashMap<>(10000);
    private JTabbedPane interactionsTab;
    private int selectedRow = -1;
    private HashMap<Integer, Color> colours = new HashMap<>();
    private HashMap<Integer, Color> textColours = new HashMap<>();
    private static final String COLLABORATOR_PLACEHOLDER = "$collabplz";
    private Thread pollThread;
    private long POLL_EVERY_MS = 10000;
    private boolean pollNow = false;
    private boolean createdCollaboratorPayload = false;
    private int pollCounter = 0;
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        callbacks.registerExtensionStateListener(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName(extensionName);
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                stdout.println(extensionName + " " + extensionVersion);
                running = true;
                panel = new JPanel(new BorderLayout());
                JLabel informationText = new JLabel("<html>To use Taborator right click in the repeater request tab and select \"Taborator->Insert Collaborator payload\".<br> Use \"Taborator->Insert Collaborator placeholder\" to insert a placeholder that will be replaced by a Collaborator payload in every request. The Taborator placeholder also works in other Burp tools.");
                informationText.setBorder(BorderFactory.createCompoundBorder(informationText.getBorder(), BorderFactory.createEmptyBorder(10, 10, 10, 10)));
                panel.add(informationText, BorderLayout.NORTH);
                panel.addComponentListener(new ComponentAdapter() {
                    @Override
                    public void componentShown(ComponentEvent e) {
                        pollNow = true;
                    }
                });
                interactionsTab = new JTabbedPane();
                JSplitPane collaboratorClientSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                collaboratorClientSplit.setResizeWeight(.5d);
                final Class[] classes = new Class[]{Integer.class, Date.class, String.class, String.class, String.class, String.class};
                DefaultTableModel model = new DefaultTableModel() {
                    @Override
                    public boolean isCellEditable(int row, int column) {
                        return false;
                    }
                    @Override
                    public Class<?> getColumnClass(int columnIndex) {
                        if (columnIndex < classes.length)
                            return classes[columnIndex];
                        return super.getColumnClass(columnIndex);
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
                collaboratorTable.getColumnModel().getColumn(0).setPreferredWidth(50);
                collaboratorTable.getColumnModel().getColumn(0).setMaxWidth(50);
                collaboratorTable.getColumnModel().getColumn(2).setPreferredWidth(80);
                collaboratorTable.getColumnModel().getColumn(2).setMaxWidth(80);
                JPopupMenu popupMenu = new JPopupMenu();
                JMenuItem commentMenuItem = new JMenuItem("Add comment");
                commentMenuItem.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int rowNum = collaboratorTable.getSelectedRow();
                        if(rowNum > -1) {
                            String comment = JOptionPane.showInputDialog("Please enter a comment");
                            collaboratorTable.getModel().setValueAt(comment, rowNum, 5);
                        }
                    }
                });
                popupMenu.add(commentMenuItem);
                JMenu highlightMenu = new JMenu("Highlight");
                highlightMenu.add(generateMenuItem(collaboratorTable, null, "HTTP", null));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0xfa6364"), "HTTP", Color.white));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0xfac564"), "HTTP", Color.black));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0xfafa64"), "HTTP", Color.black));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0x63fa64"), "HTTP", Color.black));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0x63fafa"), "HTTP", Color.black));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0x6363fa"), "HTTP", Color.white));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0xfac5c5"), "HTTP", Color.black));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0xfa63fa"), "HTTP", Color.black));
                highlightMenu.add(generateMenuItem(collaboratorTable, Color.decode("0xb1b1b1"), "HTTP", Color.black));
                popupMenu.add(highlightMenu);
                JMenuItem clearMenuItem = new JMenuItem("Clear");
                clearMenuItem.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int[] rows = collaboratorTable.getSelectedRows();
                        int answer = JOptionPane.showConfirmDialog(null,"This will clear all interactions, are you sure?");
                        TableModel model = (DefaultTableModel) collaboratorTable.getModel();
                        if(answer == 0) {
                            interactionHistory = new HashMap<>();
                            originalRequests = new LimitedHashMap<>(10000);
                            readRows = new ArrayList<Integer>();
                            unread = 0;
                            ((DefaultTableModel) model).setRowCount(0);
                            interactionsTab.removeAll();
                            updateTab(false);
                        }
                        collaboratorTable.clearSelection();
                    }
                });
                popupMenu.add(clearMenuItem);
                collaboratorTable.setComponentPopupMenu(popupMenu);

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
                                JPanel descriptionPanel = new JPanel(new BorderLayout());
                                int collaboratorID = (int) collaboratorTable.getModel().getValueAt(row, 0);
                                IBurpCollaboratorInteraction interaction = interactionHistory.get(collaboratorID);
                                JTextArea description = new JTextArea();
                                description.setEditable(false);
                                description.setBorder(null);
                                interactionsTab.removeAll();
                                interactionsTab.addTab("Description", descriptionPanel);
                                if(interaction.getProperty("type").equals("DNS")) {
                                    TaboratorMessageEditorController taboratorMessageEditorController = new TaboratorMessageEditorController();
                                    description.setText("The Collaborator server received a DNS lookup of type " + interaction.getProperty("query_type") + " for the domain name " + interaction.getProperty("interaction_id") + "." + collaborator.getCollaboratorServerLocation() + ".\n\n" +
                                            "The lookup was received from IP address " + interaction.getProperty("client_ip") + " at " + interaction.getProperty("time_stamp"));
                                    IMessageEditor messageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                    messageEditor.setMessage(helpers.base64Decode(interaction.getProperty("raw_query")), false);
                                    if(originalRequests.containsKey(interaction.getProperty("interaction_id"))) {
                                        IHttpRequestResponse messageInfo = originalRequests.get(interaction.getProperty("interaction_id"));
                                        IHttpService httpService = messageInfo.getHttpService();
                                        taboratorMessageEditorController.setHttpService(httpService);
                                        IMessageEditor requestMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                        requestMessageEditor.setMessage(messageInfo.getRequest(), true);
                                        interactionsTab.addTab("Original request", requestMessageEditor.getComponent());
                                    }
                                    interactionsTab.addTab("DNS query", messageEditor.getComponent());
                                } else if(interaction.getProperty("type").equals("SMTP")) {
                                    byte[] conversation = helpers.base64Decode(interaction.getProperty("conversation"));
                                    String conversationString = helpers.bytesToString(conversation);
                                    String to = "";
                                    String from = "";
                                    String message = "";
                                    Matcher m = Pattern.compile("^RCPT TO:(.+?)$", Pattern.CASE_INSENSITIVE + Pattern.MULTILINE).matcher(conversationString);
                                    if(m.find()) {
                                        to = m.group(1).trim();
                                    }
                                    m = Pattern.compile("^MAIL From:(.+)?$", Pattern.CASE_INSENSITIVE + Pattern.MULTILINE).matcher(conversationString);
                                    if(m.find()) {
                                        from = m.group(1).trim();
                                    }
                                    m = Pattern.compile("^DATA[\\r\\n]+([\\d\\D]+)?[\\r\\n]+[.][\\r\\n]+", Pattern.CASE_INSENSITIVE + Pattern.MULTILINE).matcher(conversationString);
                                    if(m.find()) {
                                        message = m.group(1).trim();
                                    }
                                    TaboratorMessageEditorController taboratorMessageEditorController = new TaboratorMessageEditorController();
                                    description.setText(
                                            "The Collaborator server received a SMTP connection from IP address " + interaction.getProperty("client_ip") + " at " + interaction.getProperty("time_stamp") + ".\n\n" +
                                            "The email details were:\n\n" +
                                            "From: " + from + "\n\n" +
                                            "To: " + to + "\n\n" +
                                            "Message: \n" + message
                                    );
                                    IMessageEditor messageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                    messageEditor.setMessage(conversation, false);
                                    if(originalRequests.containsKey(interaction.getProperty("interaction_id"))) {
                                        IHttpRequestResponse messageInfo = originalRequests.get(interaction.getProperty("interaction_id"));
                                        IHttpService httpService = messageInfo.getHttpService();
                                        taboratorMessageEditorController.setHttpService(httpService);
                                        IMessageEditor requestMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                        requestMessageEditor.setMessage(messageInfo.getRequest(), true);
                                        interactionsTab.addTab("Original request", requestMessageEditor.getComponent());
                                    }
                                    interactionsTab.addTab("SMTP Conversation", messageEditor.getComponent());
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
                                    if(originalRequests.containsKey(interaction.getProperty("interaction_id"))) {
                                        IHttpRequestResponse messageInfo = originalRequests.get(interaction.getProperty("interaction_id"));
                                        IHttpService httpService = messageInfo.getHttpService();
                                        taboratorMessageEditorController.setHttpService(httpService);
                                        IMessageEditor requestMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                        requestMessageEditor.setMessage(messageInfo.getRequest(), true);
                                        interactionsTab.addTab("Original request", requestMessageEditor.getComponent());
                                    }
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
                                updateTab(false);
                            }
                        } else {
                            if(!readRows.contains(row)) {
                                c.setFont(c.getFont().deriveFont(Font.BOLD));
                            }
                        }

                        if(colours.containsKey(row) && isSelected) {
                            if(colours.get(row) == null) {
                                setBackground(colours.get(row));
                                colours.remove(row);
                                textColours.remove(row);
                            } else {
                                setBackground(colours.get(row).darker());
                            }
                            setForeground(textColours.get(row));
                            collaboratorTable.repaint();
                        } else if(colours.containsKey(row)) {
                            setBackground(colours.get(row));
                            setForeground(textColours.get(row));
                        } else if(isSelected) {
                            if(UIManager.getLookAndFeel().getID().equals("Darcula")) {
                                setBackground(Color.decode("0x0d293e"));
                                setForeground(Color.white);
                            } else {
                                setBackground(Color.decode("0xffc599"));
                                setForeground(Color.black);
                            }
                        } else {
                            setBackground(null);
                            setForeground(null);
                        }

                        return c;
                    }
                });
                Runnable collaboratorRunnable = new Runnable() {
                    public void run() {
                        stdout.println("Taborator running...");
                        while(running){
                            if(pollNow) {
                                List<IBurpCollaboratorInteraction> interactions = collaborator.fetchAllCollaboratorInteractions();
                                boolean hasInteractions = false;
                                for(int i=0;i<interactions.size();i++) {
                                    IBurpCollaboratorInteraction interaction =  interactions.get(i);
                                    int rowID = model.getRowCount()+1;
                                    model.addRow(new Object[]{rowID, interaction.getProperty("time_stamp"), interaction.getProperty("type"), interaction.getProperty("client_ip"), interaction.getProperty("interaction_id"), ""});
                                    unread++;
                                    interactionHistory.put(rowID, interaction);
                                    hasInteractions = true;
                                }
                                updateTab(hasInteractions);
                                pollNow = false;
                            }
                            try {
                                Thread.sleep(POLL_EVERY_MS);
                                pollCounter++;
                                if(pollCounter > 5) {
                                    if(createdCollaboratorPayload) {
                                        pollNow = true;
                                    }
                                    pollCounter = 0;
                                }
                            } catch (InterruptedException e) {
                                stdout.println("Taborator shutdown.");
                                return;
                            }
                        }
                        stdout.println("Taborator shutdown.");
                    }
                };
                pollThread = new Thread(collaboratorRunnable);
                pollThread.start();
            }
        });
    }
    @Override
    public Component getUiComponent() {
        return panel;
    }
    @Override
    public String getTabCaption() {
        return unread > 0 ? extensionName + " ("+unread+")" : extensionName;
    }

    private void changeTabColour(JTabbedPane tabbedPane, final int tabIndex, boolean hasInteractions) {
        if(hasInteractions) {
            tabbedPane.setBackgroundAt(tabIndex, new Color(0xff6633));
        } else {
            tabbedPane.setBackgroundAt(tabIndex, new Color(0x000000));
        }
    }

    private void updateTab(boolean hasInteractions) {
        if(running) {
            JTabbedPane tp = (JTabbedPane) BurpExtender.this.getUiComponent().getParent();
            int tIndex = getTabIndex(BurpExtender.this);
            if (tIndex > -1) {
                tp.setTitleAt(tIndex, getTabCaption());
                changeTabColour(tp, tIndex, hasInteractions);
            }
        }
    }

    private int getTabIndex(ITab your_itab) {
        if(running) {
            JTabbedPane parent = (JTabbedPane) your_itab.getUiComponent().getParent();
            for (int i = 0; i < parent.getTabCount(); ++i) {
                if (parent.getTitleAt(i).contains(extensionName)) {
                    return i;
                }
            }
        }
        return -1;
    }

    private JMenuItem generateMenuItem(JTable collaboratorTable, Color colour, String text, Color textColour) {
        JMenuItem item = new JMenuItem(text);
        item.setBackground(colour);
        item.setForeground(textColour);
        item.setOpaque(true);
        item.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int rowNum = collaboratorTable.getSelectedRow();
                if(rowNum > -1) {
                    colours.put(rowNum, colour);
                    textColours.put(rowNum, textColour);
                }
            }
        });
        return item;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(!messageIsRequest) {
            return;
        }
        switch(toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                break;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                break;
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                break;
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                break;
            default:
                return;
        }
        byte[] request = messageInfo.getRequest();
        if(helpers.indexOf(request,helpers.stringToBytes(COLLABORATOR_PLACEHOLDER), true, 0, request.length) > -1) {
            String requestStr = helpers.bytesToString(request);
            Matcher m = Pattern.compile(COLLABORATOR_PLACEHOLDER.replace("$","\\$")).matcher(requestStr);
            ArrayList<String> collaboratorPayloads = new ArrayList<>();
            while (m.find()) {
                String collaboratorPayloadID = collaborator.generatePayload(false);
                collaboratorPayloads.add(collaboratorPayloadID);
                requestStr = requestStr.replaceFirst(COLLABORATOR_PLACEHOLDER.replace("$","\\$"), collaboratorPayloadID+"."+collaborator.getCollaboratorServerLocation());
                pollNow = true;
                createdCollaboratorPayload = true;
            }
            request = helpers.stringToBytes(requestStr);
            request = fixContentLength(request);
            messageInfo.setRequest(request);
            for(int i=0;i<collaboratorPayloads.size();i++) {
                originalRequests.put(collaboratorPayloads.get(i), messageInfo);
            }
        }
    }

    public byte[] fixContentLength(byte[] request) {
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        if (countMatches(request, helpers.stringToBytes("Content-Length: ")) > 0) {
            int start = analyzedRequest.getBodyOffset();
            int contentLength = request.length - start;
            return setHeader(request, "Content-Length", Integer.toString(contentLength));
        }
        else {
            return request;
        }
    }

    public int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
        while (i < end) {
            int line_start = i;
            while (i < end && request[i++] != ' ') {
            }
            byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
            int headerValueStart = i;
            while (i < end && request[i++] != '\n') {
            }
            if (i == end) {
                break;
            }

            String header_str = helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }
        }
        return null;
    }

    public  byte[] setHeader(byte[] request, String header, String value) {
        int[] offsets = getHeaderOffsets(request, header);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write( Arrays.copyOfRange(request, 0, offsets[1]));
            outputStream.write(helpers.stringToBytes(value));
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.length));
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        } catch (NullPointerException e) {
            throw new RuntimeException("Can't find the header");
        }
    }

    int countMatches(byte[] response, byte[] match) {
        int matches = 0;
        if (match.length < 4) {
            return matches;
        }

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches += 1;
            start += match.length;
        }

        return matches;
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
                    pollNow = true;
                    createdCollaboratorPayload = true;
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
                    outputStream.write(helpers.stringToBytes(COLLABORATOR_PLACEHOLDER));
                    outputStream.write(Arrays.copyOfRange(message, bounds[1],message.length));
                    outputStream.flush();
                    invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                    pollNow = true;
                    createdCollaboratorPayload = true;
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
        pollThread.interrupt();
    }
}