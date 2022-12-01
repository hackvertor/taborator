package burp;

import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.ILogProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.BurpExtenderUtilities.ProjectSettingStore;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.text.Utilities;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.*;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener, IContextMenuFactory, IHttpListener {
    private String extensionName = "Taborator";
    private String extensionVersion = "2.1.5";
    private int maxHashMapSize = 10000;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stderr;
    private PrintWriter stdout;
    private JPanel panel;
    private volatile boolean running;
    private int unread = 0;
    private ArrayList<Integer> readRows = new ArrayList<>();
    private IBurpCollaboratorClientContext collaborator = null;
    private HashMap<Integer, HashMap<String, String>> interactionHistory = new HashMap<>();
    private HashMap<String, HashMap<String,String>> originalRequests = new LimitedHashMap<>(maxHashMapSize);
    private HashMap<String, String> originalResponses = new LimitedHashMap<>(maxHashMapSize);
    private JTabbedPane interactionsTab;
    private Integer selectedRow = -1;
    private HashMap<Integer, Color> colours = new HashMap<>();
    private HashMap<Integer, Color> textColours = new HashMap<>();
    private HashMap<Integer, String> comments = new HashMap<>();
    private static final String COLLABORATOR_PLACEHOLDER = "$collabplz";
    private Thread pollThread;
    private long POLL_EVERY_MS = 10000;
    private boolean pollNow = false;
    private boolean createdCollaboratorPayload = false;
    private int pollCounter = 0;
    private boolean shutdown = false;
    private boolean isSleeping = false;
    private Preferences prefs;
    private Integer rowNumber = 0;
    private DefaultTableModel model;
    private JTable collaboratorTable;
    private TableRowSorter<TableModel> sorter = null;
    private Color defaultTabColour;
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        shutdown = false;
        isSleeping = false;
        helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        callbacks.registerExtensionStateListener(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName(extensionName);
        defaultTabColour = getDefaultTabColour();
        DefaultGsonProvider gsonProvider = new DefaultGsonProvider();

        prefs = new Preferences("Taborator", gsonProvider, new ILogProvider() {
            @Override
            public void logOutput(String message) {
                //System.out.println("Output:"+message);
            }

            @Override
            public void logError(String errorMessage) {
                System.err.println("Error Output:"+errorMessage);
            }
        }, callbacks);
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                stdout.println(extensionName + " " + extensionVersion);
                stdout.println("To use Taborator right click in the repeater request tab and select \"Taborator->Insert Collaborator payload\". Use \"Taborator->Insert Collaborator placeholder\" to insert a placeholder that will be replaced by a Collaborator payload in every request. The Taborator placeholder also works in other Burp tools. You can also use the buttons in the Taborator tab to create a payload and poll now.");
                running = true;
                try {
                    prefs.registerSetting("config", new TypeToken<HashMap<String, Integer>>() {
                    }.getType(),new HashMap<>(),Preferences.Visibility.PROJECT);
                    prefs.registerSetting("readRows", new TypeToken<ArrayList<Integer>>() {
                    }.getType(), new ArrayList<Integer>(), Preferences.Visibility.PROJECT);
                    prefs.registerSetting("interactionHistory", new TypeToken<HashMap<Integer, HashMap<String, String>>>() {
                    }.getType(), new HashMap<>(), Preferences.Visibility.PROJECT);
                    prefs.registerSetting("originalRequests", new TypeToken<HashMap<String, HashMap<String, String>>>() {
                    }.getType(), new LimitedHashMap<>(maxHashMapSize), Preferences.Visibility.PROJECT);
                    prefs.registerSetting("originalResponses", new TypeToken<HashMap<String, String>>() {
                    }.getType(), new LimitedHashMap<>(maxHashMapSize), Preferences.Visibility.PROJECT);
                    prefs.registerSetting("comments", new TypeToken<HashMap<Integer, String>>() {
                    }.getType(), new HashMap<>(), Preferences.Visibility.PROJECT);
                    prefs.registerSetting("colours", new TypeToken<HashMap<Integer, Color>>() {
                    }.getType(), new HashMap<>(), Preferences.Visibility.PROJECT);
                    prefs.registerSetting("textColours", new TypeToken<HashMap<Integer, Color>>() {
                    }.getType(), new HashMap<>(), Preferences.Visibility.PROJECT);
                } catch(Throwable e) {
                    System.err.println("Error registering settings:"+e);
                }
                panel = new JPanel(new BorderLayout());
                JPanel topPanel = new JPanel();
                topPanel.setLayout(new GridBagLayout());
                JButton exportBtn = new JButton("Export");
                exportBtn.setPreferredSize(new Dimension(80,30));
                exportBtn.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        JFrame frame = new JFrame();
                        JFileChooser fileChooser = new JFileChooser();
                        fileChooser.setDialogTitle("Please choose where to save interactions");
                        int userSelection = fileChooser.showSaveDialog(frame);
                        if (userSelection == JFileChooser.APPROVE_OPTION) {
                            File fileToSave = fileChooser.getSelectedFile();
                            String filePath = fileToSave.getAbsolutePath();
                            ProjectSettingStore projectSettingStore = prefs.getProjectSettingsStore();
                            saveSettings();
                            String jsonStr = projectSettingStore.getJSONSettings();
                            FileWriter file = null;
                            try {
                                file = new FileWriter(filePath);
                                file.write(jsonStr);
                            } catch (IOException ex) {
                                ex.printStackTrace();
                            } finally {
                                try {
                                    file.flush();
                                    file.close();
                                } catch (IOException ex) {
                                    ex.printStackTrace();
                                }
                            }
                        }
                    }
                });
                JLabel searchText = new JLabel("Search (IP,Host):");
                JTextField keywordSearch = new JTextField();
                keywordSearch.setPreferredSize(new Dimension(160, 30));
                JComboBox filter = new JComboBox();
                filter.setPreferredSize(new Dimension(160, 30));
                filter.addItem("Show all types");
                filter.addItem("DNS");
                filter.addItem("HTTP");
                filter.addItem("SMTP");

                RowFilter rowFilter = new RowFilter<TableModel,Integer>() {
                    @Override
                    public boolean include(RowFilter.Entry<? extends TableModel,? extends Integer> row) {
                        String keyword = keywordSearch.getText();
                        Boolean hasFilter = filter.getSelectedIndex() > 0;
                        Boolean hasKeyword = !keyword.equals("");
                        if(!hasFilter && !hasKeyword) {
                            return true;
                        }
                        if(hasKeyword && hasFilter) {
                            return (row.getStringValue(3).contains(keyword) || row.getStringValue(4).contains(keyword)) && row.getValue(2).equals(filter.getSelectedItem().toString());
                        } else if(hasKeyword) {
                            return row.getStringValue(3).contains(keyword) || row.getStringValue(4).contains(keyword);
                        } else if(hasFilter) {
                            return row.getValue(2).equals(filter.getSelectedItem().toString());
                        } else {
                            return true;
                        }
                    }
                };
                filter.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        sorter.setRowFilter(rowFilter);
                    }
                });
                keywordSearch.getDocument().addDocumentListener(new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent e) {
                        sorter.setRowFilter(rowFilter);
                    }

                    @Override
                    public void removeUpdate(DocumentEvent e) {
                        sorter.setRowFilter(rowFilter);
                    }

                    @Override
                    public void changedUpdate(DocumentEvent e) {
                        sorter.setRowFilter(rowFilter);
                    }
                });
                JButton createCollaboratorPayloadWithTaboratorCmd = new JButton("Taborator commands & copy");
                createCollaboratorPayloadWithTaboratorCmd.setPreferredSize(new Dimension(200, 30));
                createCollaboratorPayloadWithTaboratorCmd.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        createdCollaboratorPayload = true;
                        String payload = collaborator.generatePayload(true) + "?TaboratorCmd=comment:Test;bgColour:0x000000;textColour:0xffffff";
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(payload),null);
                    }
                });
                JLabel generateMsg = new JLabel("Number to generate:");
                JButton pollButton = new JButton("Poll now");
                JTextField numberOfPayloads = new JTextField("1");
                numberOfPayloads.setPreferredSize(new Dimension(50, 30));
                JButton createCollaboratorPayload = new JButton("Create payload & copy");
                createCollaboratorPayload.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        createdCollaboratorPayload = true;
                        int amount = 1;
                        try {
                            amount = Integer.parseInt(numberOfPayloads.getText());
                        } catch (NumberFormatException ex) {
                            amount = 1;
                        }
                        StringBuilder payloads = new StringBuilder();
                        payloads.append(collaborator.generatePayload(true));
                        for(int i=1;i<amount;i++) {
                            payloads.append("\n");
                            payloads.append(collaborator.generatePayload(true));
                        }
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(payloads.toString()),null);
                    }
                });
                pollButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        pollNow = true;
                        if(isSleeping) {
                            pollThread.interrupt();
                        }
                    }
                });
                pollButton.setPreferredSize(new Dimension(100, 30));
                pollButton.setMaximumSize(new Dimension(180, 30));
                exportBtn.setMaximumSize(new Dimension(100, 30));
                topPanel.add(exportBtn, createConstraints(1, 2, 1, GridBagConstraints.NONE));
                topPanel.add(searchText, createConstraints(2, 2, 1, GridBagConstraints.NONE));
                topPanel.add(keywordSearch, createConstraints(3, 2, 1, GridBagConstraints.NONE));
                topPanel.add(filter, createConstraints(4, 2, 1, GridBagConstraints.NONE));
                topPanel.add(createCollaboratorPayloadWithTaboratorCmd, createConstraints(5, 2, 1, GridBagConstraints.NONE));
                topPanel.add(pollButton, createConstraints(6, 2, 1, GridBagConstraints.NONE));
                topPanel.add(generateMsg, createConstraints(7, 2, 1, GridBagConstraints.NONE));
                createCollaboratorPayload.setPreferredSize(new Dimension(180, 30));
                createCollaboratorPayload.setMaximumSize(new Dimension(180, 30));
                topPanel.add(numberOfPayloads, createConstraints(8,2,1, GridBagConstraints.NONE));
                topPanel.add(createCollaboratorPayload, createConstraints(9, 2, 1, GridBagConstraints.NONE));
                panel.add(topPanel, BorderLayout.NORTH);
                panel.addComponentListener(new ComponentAdapter() {
                    @Override
                    public void componentShown(ComponentEvent e) {
                        pollNow = true;
                    }
                });
                interactionsTab = new JTabbedPane();
                JSplitPane collaboratorClientSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                collaboratorClientSplit.setResizeWeight(.5d);
                final Class[] classes = new Class[]{Integer.class, Long.class, String.class, String.class, String.class, String.class};
                model = new DefaultTableModel() {
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
                collaboratorTable = new JTable(model);
                sorter = new TableRowSorter<>(model);
                collaboratorTable.setRowSorter(sorter);
                model.addColumn("#");
                model.addColumn("Time");
                model.addColumn("Type");
                model.addColumn("IP");
                model.addColumn("Hostname");
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
                            int realRowNum = collaboratorTable.convertRowIndexToModel(rowNum);
                            String comment = JOptionPane.showInputDialog("Please enter a comment");
                            collaboratorTable.getModel().setValueAt(comment, realRowNum, 5);
                            if(comment.length() == 0) {
                                if(comments.containsKey(realRowNum)) {
                                    comments.remove(realRowNum);
                                }
                            } else {
                                comments.put(realRowNum, comment);
                            }
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
                JMenuItem markReadMenuItem = new JMenuItem("Mark all as read");
                markReadMenuItem.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int answer = JOptionPane.showConfirmDialog(null,"This will mark all interactions as read, are you sure?");
                        TableModel model = (DefaultTableModel) collaboratorTable.getModel();
                        if(answer == 0) {
                            readRows = new ArrayList<>();
                            for(int i=0;i<model.getRowCount() + 1;i++) {
                                readRows.add(i);
                            }
                            unread = 0;
                            updateTab(false);
                            collaboratorTable.repaint();
                        }
                    }
                });
                JMenuItem clearMenuItem = new JMenuItem("Clear interactions");
                clearMenuItem.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int answer = JOptionPane.showConfirmDialog(null,"This will clear all interactions, are you sure?");
                        TableModel model = (DefaultTableModel) collaboratorTable.getModel();
                        if(answer == 0) {
                            interactionHistory = new HashMap<>();
                            readRows = new ArrayList<>();
                            unread = 0;
                            rowNumber = 0;
                            colours = new HashMap<>();
                            textColours = new HashMap<>();
                            comments = new HashMap<>();
                            ((DefaultTableModel) model).setRowCount(0);
                            interactionsTab.removeAll();
                            selectedRow = -1;
                            updateTab(false);
                        }
                        collaboratorTable.clearSelection();
                    }
                });
                JMenuItem clearOriginalReqResItem = new JMenuItem("Clear original requests/responses");
                clearOriginalReqResItem.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        int answer = JOptionPane.showConfirmDialog(null,"This will remove all req/res history from placeholder usage, are you sure?");
                        if(answer == 0) {
                            originalRequests = new LimitedHashMap<>(maxHashMapSize);
                            originalResponses = new LimitedHashMap<>(maxHashMapSize);
                        }
                        collaboratorTable.clearSelection();
                    }
                });
                popupMenu.add(clearOriginalReqResItem);
                popupMenu.add(clearMenuItem);
                popupMenu.add(markReadMenuItem);
                collaboratorTable.setComponentPopupMenu(popupMenu);

                JScrollPane collaboratorScroll = new JScrollPane(collaboratorTable);
                collaboratorTable.setFillsViewportHeight(true);
                collaboratorClientSplit.setTopComponent(collaboratorScroll);
                collaboratorClientSplit.setBottomComponent(new JPanel());
                panel.add(collaboratorClientSplit, BorderLayout.CENTER);
                callbacks.addSuiteTab(BurpExtender.this);
                collaborator = callbacks.createBurpCollaboratorClientContext();
                DefaultTableCellRenderer tableCellRender = new DefaultTableCellRenderer()
                {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)
                    {
                        final Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                        int modelRow = table.convertRowIndexToModel(row);
                        int id = (int) table.getModel().getValueAt(modelRow, 0);
                        putClientProperty("html.disable", Boolean.TRUE);
                        if(isSelected) {
                            if(!readRows.contains(id)) {
                                c.setFont(c.getFont().deriveFont(Font.PLAIN));
                                readRows.add(id);
                                unread--;
                            }
                            if(selectedRow != row && collaboratorTable.getSelectedRowCount() == 1) {
                                JPanel descriptionPanel = new JPanel(new BorderLayout());
                                HashMap<String, String> interaction = interactionHistory.get(id);
                                JTextArea description = new JTextArea();
                                description.setEditable(false);
                                description.setBorder(null);
                                interactionsTab.removeAll();
                                interactionsTab.addTab("Description", descriptionPanel);
                                if(interaction.get("type").equals("DNS")) {
                                    TaboratorMessageEditorController taboratorMessageEditorController = new TaboratorMessageEditorController();
                                    description.setText("The Collaborator server received a DNS lookup of type " + interaction.get("query_type") + " for the hostname " + interaction.get("hostname") + "\n\n" +
                                            "The lookup was received from IP address " + interaction.get("client_ip") + " at " + interaction.get("time_stamp"));
                                    IMessageEditor messageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                    messageEditor.setMessage(helpers.base64Decode(interaction.get("raw_query")), false);
                                    if(originalRequests.containsKey(interaction.get("interaction_id"))) {
                                        HashMap<String, String> requestInfo = originalRequests.get(interaction.get("interaction_id"));
                                        IHttpService httpService = helpers.buildHttpService(requestInfo.get("host"), Integer.decode(requestInfo.get("port")), requestInfo.get("protocol"));
                                        taboratorMessageEditorController.setHttpService(httpService);
                                        IMessageEditor requestMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                        if (requestInfo.get("request") != null) {
                                            requestMessageEditor.setMessage(helpers.stringToBytes(requestInfo.get("request")), true);
                                            interactionsTab.addTab("Original request", requestMessageEditor.getComponent());
                                        }
                                        if (originalResponses.containsKey(interaction.get("interaction_id"))) {
                                            taboratorMessageEditorController.setHttpService(httpService);
                                            IMessageEditor responseMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                            if (requestInfo.get("request") != null && originalResponses.get(interaction.get("interaction_id")) != null) {
                                                responseMessageEditor.setMessage(helpers.stringToBytes(originalResponses.get(interaction.get("interaction_id"))), true);
                                                interactionsTab.addTab("Original response", responseMessageEditor.getComponent());
                                            }
                                        }
                                    }
                                    interactionsTab.addTab("DNS query", messageEditor.getComponent());
                                } else if(interaction.get("type").equals("SMTP")) {
                                    byte[] conversation = helpers.base64Decode(interaction.get("conversation"));
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
                                            "The Collaborator server received a SMTP connection from IP address " + interaction.get("client_ip") + " at " + interaction.get("time_stamp") + ".\n\n" +
                                                    "The email details were:\n\n" +
                                                    "From: " + from + "\n\n" +
                                                    "To: " + to + "\n\n" +
                                                    "Message: \n" + message
                                    );
                                    IMessageEditor messageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                    messageEditor.setMessage(conversation, false);
                                    if(originalRequests.containsKey(interaction.get("interaction_id"))) {
                                        HashMap<String, String> requestInfo = originalRequests.get(interaction.get("interaction_id"));
                                        IHttpService httpService = helpers.buildHttpService(requestInfo.get("host"), Integer.decode(requestInfo.get("port")), requestInfo.get("protocol"));
                                        taboratorMessageEditorController.setHttpService(httpService);
                                        IMessageEditor requestMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                        if (requestInfo.get("request") != null) {
                                            requestMessageEditor.setMessage(helpers.stringToBytes(requestInfo.get("request")), true);
                                            interactionsTab.addTab("Original request", requestMessageEditor.getComponent());
                                        }
                                        if (originalResponses.containsKey(interaction.get("interaction_id"))) {
                                            taboratorMessageEditorController.setHttpService(httpService);
                                            IMessageEditor responseMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                            if (requestInfo.get("request") != null && originalResponses.get(interaction.get("interaction_id")) != null) {
                                                responseMessageEditor.setMessage(helpers.stringToBytes(originalResponses.get(interaction.get("interaction_id"))), true);
                                                interactionsTab.addTab("Original response", responseMessageEditor.getComponent());
                                            }
                                        }
                                    }
                                    interactionsTab.addTab("SMTP Conversation", messageEditor.getComponent());
                                    interactionsTab.setSelectedIndex(1);
                                } else if(interaction.get("type").equals("HTTP")) {
                                    TaboratorMessageEditorController taboratorMessageEditorController = new TaboratorMessageEditorController();
                                    URL collaboratorURL = null;
                                    try {
                                        collaboratorURL = new URL(interaction.get("protocol").toLowerCase()+"://"+collaborator.getCollaboratorServerLocation());
                                    } catch (MalformedURLException e) {
                                        stderr.println("Failed parsing Collaborator URL:"+e.toString());
                                    }
                                    if(collaboratorURL != null) {
                                        IHttpService httpService = helpers.buildHttpService(collaboratorURL.getHost(), collaboratorURL.getPort() == -1 ? collaboratorURL.getDefaultPort() : collaboratorURL.getPort(), interaction.get("protocol").equals("HTTPS"));
                                        taboratorMessageEditorController.setHttpService(httpService);
                                    }
                                    byte[] collaboratorResponse = helpers.base64Decode(interaction.get("response"));
                                    byte[] collaboratorRequest = helpers.base64Decode(interaction.get("request"));
                                    taboratorMessageEditorController.setRequest(collaboratorRequest);
                                    taboratorMessageEditorController.setResponse(collaboratorResponse);
                                    description.setText("The Collaborator server received an "+interaction.get("protocol")+" request.\n\nThe request was received from IP address "+interaction.get("client_ip")+" at "+interaction.get("time_stamp") + " for the hostname " + interaction.get("hostname"));
                                    if(originalRequests.containsKey(interaction.get("interaction_id"))) {
                                        HashMap<String, String> requestInfo = originalRequests.get(interaction.get("interaction_id"));
                                        IHttpService httpService = helpers.buildHttpService(requestInfo.get("host"), Integer.decode(requestInfo.get("port")), requestInfo.get("protocol"));
                                        taboratorMessageEditorController.setHttpService(httpService);
                                        IMessageEditor requestMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                        if (requestInfo.get("request") != null) {
                                            requestMessageEditor.setMessage(helpers.stringToBytes(requestInfo.get("request")), true);
                                            interactionsTab.addTab("Original request", requestMessageEditor.getComponent());
                                        }
                                        if (originalResponses.containsKey(interaction.get("interaction_id"))) {
                                            taboratorMessageEditorController.setHttpService(httpService);
                                            IMessageEditor responseMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                            if (requestInfo.get("request") != null && originalResponses.get(interaction.get("interaction_id")) != null) {
                                                responseMessageEditor.setMessage(helpers.stringToBytes(originalResponses.get(interaction.get("interaction_id"))), true);
                                                interactionsTab.addTab("Original response", responseMessageEditor.getComponent());
                                            }
                                        }
                                    }
                                    IMessageEditor requestMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                    requestMessageEditor.setMessage(collaboratorRequest, true);
                                    interactionsTab.addTab("Request to Collaborator", requestMessageEditor.getComponent());
                                    IMessageEditor responseMessageEditor = callbacks.createMessageEditor(taboratorMessageEditorController, false);
                                    responseMessageEditor.setMessage(collaboratorResponse, true);
                                    interactionsTab.addTab("Response from Collaborator", responseMessageEditor.getComponent());
                                    interactionsTab.setSelectedIndex(1);
                                }
                                description.setBorder(BorderFactory.createCompoundBorder(description.getBorder(), BorderFactory.createEmptyBorder(10, 10, 10, 10)));
                                descriptionPanel.add(description);
                                collaboratorClientSplit.setBottomComponent(interactionsTab);
                                selectedRow = row;
                                updateTab(false);
                                setDividerLocation(collaboratorClientSplit, 0.5);
                            }
                        } else {
                            if(!readRows.contains(id)) {
                                c.setFont(c.getFont().deriveFont(Font.BOLD));
                            }
                        }
                        if(colours.containsKey(id) && isSelected) {
                            if(colours.get(id) == null) {
                                setBackground(colours.get(id));
                                colours.remove(id);
                                textColours.remove(id);
                            } else {
                                setBackground(colours.get(id).darker());
                            }
                            setForeground(textColours.get(id));
                            table.repaint();
                            table.validate();
                        } else if(colours.containsKey(id)) {
                            setBackground(colours.get(id));
                            setForeground(textColours.get(id));
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
                };
                collaboratorTable.setDefaultRenderer(Object.class, tableCellRender);
                collaboratorTable.setDefaultRenderer(Number.class, tableCellRender);
                Runnable collaboratorRunnable = new Runnable() {
                    public void run() {
                        stdout.println("Taborator running...");
                        loadSettings();
                        for (Map.Entry<Integer, HashMap<String, String>> data : interactionHistory.entrySet()) {
                            int id = data.getKey();
                            HashMap<String, String> interaction = data.getValue();
                            insertInteraction(interaction, id);
                        }
                        if(unread > 0) {
                            updateTab(true);
                        }

                        while(running){
                            if(pollNow) {
                                List<IBurpCollaboratorInteraction> interactions = collaborator.fetchAllCollaboratorInteractions();
                                if(interactions.size() > 0) {
                                    insertInteractions(interactions);
                                }
                                pollNow = false;
                            }
                            try {
                                isSleeping = true;
                                pollThread.sleep(POLL_EVERY_MS);
                                isSleeping = false;
                                pollCounter++;
                                if(pollCounter > 5) {
                                    if(createdCollaboratorPayload) {
                                        pollNow = true;
                                    }
                                    pollCounter = 0;
                                }
                            } catch (InterruptedException e) {
                                if(shutdown) {
                                    stdout.println("Taborator shutdown.");
                                    return;
                                } else {
                                    continue;
                                }

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
    private void insertInteraction(HashMap<String,String> interaction, int rowID) {
        model.addRow(new Object[]{rowID,interaction.get("time_stamp"), interaction.get("type"), interaction.get("client_ip"), interaction.get("hostname"), ""});
        if(comments.size() > 0) {
            int actualID = getRealRowID(rowID);
            if(actualID > -1 && comments.containsKey(actualID)) {
                String comment = comments.get(actualID);
                model.setValueAt(comment, actualID, 5);
            }
        }
        if (interaction.get("type").equals("HTTP")) {
            byte[] collaboratorRequest = helpers.base64Decode(interaction.get("request"));
            if (helpers.indexOf(collaboratorRequest, helpers.stringToBytes("TaboratorCmd="), true, 0, collaboratorRequest.length) > -1) {
                IRequestInfo analyzedRequest = helpers.analyzeRequest(collaboratorRequest);
                List<IParameter> params = analyzedRequest.getParameters();
                for (int i = 0; i < params.size(); i++) {
                    if (params.get(i).getName().equals("TaboratorCmd")) {
                        String[] commands = params.get(i).getValue().split(";");
                        for (int j = 0; j < commands.length; j++) {
                            String[] command = commands[j].split(":");
                            if (command[0].equals("bgColour")) {
                                try {
                                    Color colour = Color.decode(helpers.urlDecode(command[1]));
                                    colours.put(rowID, colour);
                                } catch (NumberFormatException e) {

                                }
                            } else if (command[0].equals("textColour")) {
                                try {
                                    Color colour = Color.decode(helpers.urlDecode(command[1]));
                                    textColours.put(rowID, colour);
                                } catch (NumberFormatException e) {

                                }
                            } else if (command[0].equals("comment")) {
                                String comment = helpers.urlDecode(command[1]);
                                int actualID = getRealRowID(rowID);
                                if(actualID > -1) {
                                    model.setValueAt(comment, actualID, 5);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
    private int getRealRowID(int rowID) {
        int rowCount = collaboratorTable.getRowCount();
        for (int i = 0; i < rowCount; i++) {
            int id = (int) collaboratorTable.getValueAt(i, 0);
            if(rowID == id) {
                return collaboratorTable.convertRowIndexToView(i);
            }
        }
        return -1;
    }
    private void loadSettings() {
        try {
            HashMap<String,Integer> config = prefs.getSetting("config");
            if(config.size() > 0) {
                unread = config.get("unread");
                rowNumber = config.get("rowNumber");
            }
            interactionHistory = prefs.getSetting("interactionHistory");
            originalRequests = prefs.getSetting("originalRequests");
            originalResponses = prefs.getSetting("originalResponses");
            comments = prefs.getSetting("comments");
            colours = prefs.getSetting("colours");
            textColours = prefs.getSetting("textColours");
            readRows = prefs.getSetting("readRows");
        } catch(Throwable e) {
            System.err.println("Error reading settings:"+e);
        }
    }
    private void saveSettings() {
        try {
            HashMap<String,Integer> config = new HashMap<>();
            config.put("unread", unread);
            config.put("rowNumber", rowNumber);
            prefs.setSetting("config", config);
            prefs.setSetting("interactionHistory", interactionHistory);
            prefs.setSetting("originalRequests", originalRequests);
            prefs.setSetting("originalResponses", originalResponses);
            prefs.setSetting("readRows", readRows);
            prefs.setSetting("comments", comments);
            prefs.setSetting("colours", colours);
            prefs.setSetting("textColours", textColours);
        } catch (Throwable e) {
            System.err.println("Error saving settings:"+e);
        }
    }
    private void insertInteractions(List<IBurpCollaboratorInteraction> interactions) {
        boolean hasInteractions = false;
        for(int i=0;i<interactions.size();i++) {
            IBurpCollaboratorInteraction interaction =  interactions.get(i);
            HashMap<String, String> interactionHistoryItem = new HashMap<>();
            rowNumber++;
            int rowID = rowNumber;
            for (Map.Entry<String,String> interactionData : interaction.getProperties().entrySet()) {
                interactionHistoryItem.put(interactionData.getKey(), interactionData.getValue());
            }
            interactionHistoryItem.put("hostname", getHostnameFromInteraction(interactionHistoryItem));
            insertInteraction(interactionHistoryItem, rowID);
            unread++;
            interactionHistory.put(rowID, interactionHistoryItem);
            hasInteractions = true;
        }
        updateTab(hasInteractions);
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
            tabbedPane.setBackgroundAt(tabIndex, defaultTabColour);
        }
    }
    private Color getDefaultTabColour() {
        if(running) {
            JTabbedPane tp = (JTabbedPane) BurpExtender.this.getUiComponent().getParent();
            int tIndex = getTabIndex(BurpExtender.this);
            if (tIndex > -1) {
                return tp.getBackgroundAt(tIndex);
            }
            return new Color(0x000000);
        }
        return null;
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
                int[] rows = collaboratorTable.getSelectedRows();
                for(int i=0;i<rows.length;i++) {
                    int realRow = collaboratorTable.convertRowIndexToModel(rows[i]);
                    if (realRow > -1) {
                        int id = (int) collaboratorTable.getModel().getValueAt(realRow, 0);
                        colours.put(id, colour);
                        textColours.put(id, textColour);
                    }
                }
            }
        });
        return item;
    }

    public static JSplitPane setDividerLocation(final JSplitPane splitter, final double proportion) {
        if (splitter.isShowing()) {
            if ((splitter.getWidth() > 0) && (splitter.getHeight() > 0)) {
                splitter.setDividerLocation(proportion);
            } else {
                splitter.addComponentListener(new ComponentAdapter() {
                    @Override
                    public void componentResized(ComponentEvent ce) {
                        splitter.removeComponentListener(this);
                        setDividerLocation(splitter, proportion);
                    }
                });
            }
        } else {
            splitter.addHierarchyListener(new HierarchyListener() {
                @Override
                public void hierarchyChanged(HierarchyEvent e) {
                    if (((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0) && splitter.isShowing()) {
                        splitter.removeHierarchyListener(this);
                        setDividerLocation(splitter, proportion);
                    }
                }
            });
        }
        return splitter;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(messageIsRequest) {
            byte[] request = messageInfo.getRequest();
            if (helpers.indexOf(request, helpers.stringToBytes(COLLABORATOR_PLACEHOLDER), true, 0, request.length) > -1) {
                String requestStr = helpers.bytesToString(request);
                Matcher m = Pattern.compile(COLLABORATOR_PLACEHOLDER.replace("$", "\\$")).matcher(requestStr);
                ArrayList<String> collaboratorPayloads = new ArrayList<>();
                while (m.find()) {
                    String collaboratorPayloadID = collaborator.generatePayload(false);
                    collaboratorPayloads.add(collaboratorPayloadID);
                    requestStr = requestStr.replaceFirst(COLLABORATOR_PLACEHOLDER.replace("$", "\\$"), collaboratorPayloadID + "." + collaborator.getCollaboratorServerLocation());
                    pollNow = true;
                    createdCollaboratorPayload = true;
                }
                request = helpers.stringToBytes(requestStr);
                request = fixContentLength(request);
                messageInfo.setRequest(request);

                for (int i = 0; i < collaboratorPayloads.size(); i++) {
                    HashMap<String, String> originalRequestsInfo = new HashMap<>();
                    originalRequestsInfo.put("request", helpers.bytesToString(request));
                    originalRequestsInfo.put("host", messageInfo.getHttpService().getHost());
                    originalRequestsInfo.put("port", Integer.toString(messageInfo.getHttpService().getPort()));
                    originalRequestsInfo.put("protocol", messageInfo.getHttpService().getProtocol());
                    originalRequests.put(collaboratorPayloads.get(i), originalRequestsInfo);
                }
            }
        } else {
            byte[] response = messageInfo.getResponse();
            byte[] request = messageInfo.getRequest();
            for (Map.Entry<String, HashMap<String, String>> entry : originalRequests.entrySet()) {
                String payload = entry.getKey();
                if(!originalResponses.containsKey(payload) && helpers.indexOf(request,helpers.stringToBytes(payload), true, 0, request.length) > -1) {
                    originalResponses.put(payload, helpers.bytesToString(response));
                }
            }
        }
    }
    private GridBagConstraints createConstraints(int x, int y, int gridWidth, int fill) {
        GridBagConstraints c = new GridBagConstraints();
        c.fill = fill;
        c.weightx = 0;
        c.weighty = 0;
        c.gridx = x;
        c.gridy = y;
        c.ipadx = 0;
        c.ipady = 0;
        c.gridwidth = gridWidth;
        c.insets = new Insets(5,5,5,5);
        return c;
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

    private String getHostnameFromInteraction(HashMap<String, String> interaction) {
        String fallback = interaction.get("interaction_id") + "." + collaborator.getCollaboratorServerLocation();
        switch(interaction.get("type")) {
            case "DNS":
                return getHostnameFromDnsRequest(helpers.base64Decode(interaction.get("raw_query")), fallback);
            case "HTTP":
                return getHostnameFromHttpRequest(helpers.bytesToString(helpers.base64Decode(interaction.get("request"))), fallback);
            case "SMTP":
                return getHostnameFromSmtpConversation(helpers.bytesToString(helpers.base64Decode(interaction.get("conversation"))), fallback);
            default:
                return fallback;
        }
    }

    private static String getHostnameFromDnsRequest(byte[] rawQuery, String fallback) {
        StringBuilder hostname = new StringBuilder();
        HashSet<Integer> seenPtrs = new HashSet<Integer>();

        ByteBuffer bb = ByteBuffer.wrap(rawQuery);

        // Seek to QDCOUNT
        bb.position(4);

        // If there is a number of questions other than 1 in the query, something has gone wrong
        short num_questions = bb.getShort();
        if (num_questions != 1) {
            return fallback;
        }

        // Seek to Question section
        bb.position(12);

        // Read hostname
        try {
            while (true) {
                int token_prefix = bb.get();

                if (token_prefix == 0) {
                    // Reached the end of the hostname
                    break;
                }

                if ((token_prefix & 0xc0) == 0) {
                    // It's a length value. Grab the token and follow it up with a dot.
                    for (int i = 0; i < token_prefix; i++) {
                        hostname.append((char) bb.get());
                    }
                    hostname.append(".");
                } else {
                    // It's a special value
                    if ((token_prefix & 0xc0) != 0xc0) {
                        // It's an illegal (reserved) value
                        return fallback;
                    }
                    // It's a pointer value. See RFC1035 section 4.1.4
                    // This isn't necessarily a correct implementation. The Burp Collaborator server doesn't seem to
                    // support pointers anyway and we don't really expect to see pointers in DNS queries (?)

                    // Rewind pos and get the ptr as a short with the high two bits masked off
                    bb.position(bb.position() - 1);
                    int ptr = bb.getShort() & (0xff - 0xc0);

                    // Check for loops
                    if (seenPtrs.contains(ptr)) {
                        return fallback;
                    }
                    seenPtrs.add(ptr);

                    // Move to where the pointer points
                    bb.position(ptr);
                }
            }
        } catch (BufferUnderflowException | IllegalArgumentException e) {
            // OOB error in the ByteBuffer.get() or .position()
            return fallback;
        }

        if (hostname.length() == 0) {
            return hostname.toString();
        } else {
            // Remove the trailing "."
            return hostname.substring(0, hostname.length() - 1);
        }
    }

    private static String getHostnameFromHttpRequest(String request, String fallback) {
        String[] lines = request.split("\r\n");
        for (String line : lines) {
            if (line.isEmpty()) {
                break;
            } else if (line.toLowerCase(Locale.ROOT).startsWith("host: ")) {
                return line.split(" ", 2)[1];
            }
        }
        return fallback;
    }

    private static String getHostnameFromSmtpConversation(String conversation, String fallback) {
        String[] lines = conversation.split("\r\n");
        Pattern bracketedAddressPat = Pattern.compile("<(.*)>");
        for (String line : lines) {
            if (line.toLowerCase(Locale.ROOT).startsWith("rcpt to:")) {
                String recipient = line.split(":", 2)[1].trim();
                Matcher m = bracketedAddressPat.matcher(recipient);
                if (m.find()) {
                    // Parsing email addresses is hard but hopefully we've just found a bracketed email address
                    // e.g. <peter@example.com>
                    recipient = m.group(1).trim();
                }
                int pos = recipient.lastIndexOf("@");
                return recipient.substring(pos + 1);
            }
        }
        return fallback;
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
        shutdown = true;
        running = false;
        stdout.println(extensionName + " unloaded");
        pollThread.interrupt();
        saveSettings();
    }


}