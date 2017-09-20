/*
 * The MIT License
 *
 * Copyright 2017 Carl Sampson <chs@chs.us>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package search;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.*;
import java.util.Base64;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Vector;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author Carl Sampson <chs@chs.us>
 */
public class SearchComponent extends JPanel
{

    IBurpExtenderCallbacks callbacks;
    BurpExtender extender;
    private JCheckBox jCheckBoxHeader;
    private JCheckBox jCheckBoxBody;
    private JCheckBox jCheckBoxActive;
    private JList jListSearchTerms;
    private JTextField jTerm;
    private DefaultListModel<String> model;
    private final HashMap<String, ActiveParam> activeParams;
    private JTable jTableActive;
    private DefaultTableModel activeModel;
    private JButton jButtonLoad;
    private JButton jButtonSave;

    public SearchComponent(IBurpExtenderCallbacks callbacks, BurpExtender extender)
    {
        this.callbacks = callbacks;
        this.extender = extender;
        this.model = null;
        this.activeParams = new HashMap<>();

        initComponents();

        this.callbacks.customizeUiComponent(this.jCheckBoxHeader);
        this.callbacks.customizeUiComponent(this.jCheckBoxBody);
        this.callbacks.customizeUiComponent(this.jCheckBoxActive);
        this.callbacks.customizeUiComponent(this.jListSearchTerms);
        this.callbacks.customizeUiComponent(this.jTableActive);
        this.callbacks.customizeUiComponent(this.jButtonLoad);
        this.callbacks.customizeUiComponent(this.jButtonSave);
        restoreSavedSettings();
    }

    public void saveSettings()
    {
        //Enabled/Disabled for headers
        this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_HEADER_ENABLED", null);
        if (this.jCheckBoxHeader.isSelected())
        {
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_HEADER_ENABLED", "ENABLED");
        }

        //Enabled/Disabled for body        
        this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_BODY_ENABLED", null);
        if (this.jCheckBoxBody.isSelected())
        {
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_BODY_ENABLED", "ENABLED");
        }

        //Enabled/Disabled for Active
        this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_ACTIVE_ENABLED", null);
        if (this.jCheckBoxActive.isSelected())
        {
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_ACTIVE_ENABLED", "ENABLED");
        }

        //Write search terms to settings
        ListModel model = jListSearchTerms.getModel();
        if (model.getSize() == 0)
        {
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_TERMS", null);
        }
        else
        {
            ArrayList<String> items = new ArrayList<>();
            for (int i = 0; i < model.getSize(); i++)
            {
                String item = (String) model.getElementAt(i);
                items.add(Base64.getEncoder().encodeToString(item.getBytes()));
            }
            String values = String.join("|", items);
            this.callbacks.saveExtensionSetting("SEARCH_PLUGIN_TERMS", values);
        }
    }

    public void restoreSavedSettings()
    {
       //Enabled/Disabled for headers
        boolean enabledSel;
        enabledSel = getSetting("SEARCH_PLUGIN_HEADER_ENABLED");
        this.jCheckBoxHeader.setSelected(enabledSel);

        //Enabled/Disabled for headers
        enabledSel = getSetting("SEARCH_PLUGIN_BODY_ENABLED");
        this.jCheckBoxBody.setSelected(enabledSel);

        //Enabled/Disabled for ACtive
        enabledSel = getSetting("SEARCH_PLUGIN_ACTIVE_ENABLED");
        this.jCheckBoxActive.setSelected(enabledSel);
        
        //Get Strings
        if (this.callbacks.loadExtensionSetting("SEARCH_PLUGIN_TERMS") != null)
        {
            this.model = new DefaultListModel<>();
            String setting = this.callbacks.loadExtensionSetting("SEARCH_PLUGIN_TERMS");
            String[] values = setting.split("\\|");
            for (int i = 0; i < values.length; i++)
            {
                String val = values[i];
                String decoded = new String(Base64.getDecoder().decode(values[i]));
                model.addElement(decoded);
            }
            jListSearchTerms.setModel(this.model);
        }
    }
    
    private boolean getSetting(String name)
    {
        if (this.callbacks.loadExtensionSetting(name) != null)
        {
            return this.callbacks.loadExtensionSetting(name).equals("ENABLED") == true;
        }
        else
        {
            return false;
        }
    }

    private void initComponents()
    {
        JLabel jLabel1 = new JLabel();
        jLabel1.setFont(new Font("Tahoma", 1, 16));
        jLabel1.setForeground(new Color(229, 137, 0));
        jLabel1.setText("Passive Search Settings");
        jLabel1.setAlignmentX(CENTER_ALIGNMENT);

        //Headers
        this.jCheckBoxHeader = new JCheckBox();
        this.jCheckBoxHeader.setSelected(true);
        this.jCheckBoxHeader.setText("Header Search");
        this.jCheckBoxHeader.setAlignmentX(CENTER_ALIGNMENT);
        this.jCheckBoxHeader.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent evt)
            {
                SearchComponent.this.saveSettings();
            }
        });

        //Body
        this.jCheckBoxBody = new JCheckBox();
        this.jCheckBoxBody.setSelected(true);
        this.jCheckBoxBody.setText("Body Search");
        this.jCheckBoxBody.setAlignmentX(CENTER_ALIGNMENT);
        this.jCheckBoxBody.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent evt)
            {
                SearchComponent.this.saveSettings();
            }
        });

        JPanel jCheckPanel = new JPanel(new FlowLayout());
        jCheckPanel.add(jCheckBoxHeader);
        jCheckPanel.add(jCheckBoxBody);

        JLabel jLabel2 = new JLabel();
        jLabel2.setFont(new Font("Tahoma", 1, 13));
        jLabel2.setForeground(new Color(229, 137, 0));
        jLabel2.setText("Search Items");
        jLabel2.setAlignmentX(CENTER_ALIGNMENT);
        jLabel2.setToolTipText("Right Click to Delete");

        this.jListSearchTerms = new JList();
        jListSearchTerms.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        jListSearchTerms.setLayoutOrientation(JList.VERTICAL);
        jListSearchTerms.setVisibleRowCount(-1);
        JScrollPane jListScroller = new JScrollPane(jListSearchTerms);
        jListScroller.setPreferredSize(new Dimension(500, 160));
        jListScroller.setAlignmentX(CENTER_ALIGNMENT);

        jListSearchTerms.addMouseListener(new MouseAdapter()
        {
            public void mouseClicked(MouseEvent evt)
            {
                //Right click delete
                if (evt.getButton() == 3)
                {
                    int index = SearchComponent.this.jListSearchTerms.locationToIndex(evt.getPoint());
                    SearchComponent.this.model.removeElementAt(index);
                    SearchComponent.this.saveSettings();
                }
            }
        });

        BoxLayout layout = new BoxLayout(this, BoxLayout.Y_AXIS);
        setLayout(layout);
        this.add(jLabel1);
        this.add(Box.createRigidArea(new Dimension(0, 10)));
        this.add(jCheckPanel);
        this.add(Box.createRigidArea(new Dimension(0, 10)));
        this.add(jLabel2);
        this.add(jListScroller);

        //Add the next
        JLabel jLabel3 = new JLabel();
        jLabel3.setFont(new Font("Tahoma", 1, 13));
        jLabel3.setForeground(new Color(229, 137, 0));
        jLabel3.setText("Add Search Term: ");
        jLabel3.setAlignmentX(LEFT_ALIGNMENT);

        this.jTerm = new JTextField(20);
        this.jTerm.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                //Create if not there
                if (SearchComponent.this.model == null)
                {
                    SearchComponent.this.model = new DefaultListModel<>();
                    SearchComponent.this.jListSearchTerms.setModel(SearchComponent.this.model);
                }

                //Add Text
                SearchComponent.this.model.addElement(SearchComponent.this.jTerm.getText());
                SearchComponent.this.saveSettings();
            }
        });

        JPanel panel = new JPanel(new FlowLayout());
        panel.add(jLabel3);
        panel.add(jTerm);
        this.add(panel);
        this.add(new JLabel("  "));

        //Active Search Stuff
        this.add(new JSeparator());
        this.add(new JLabel("  "));

        JLabel jLabel4 = new JLabel();
        jLabel4.setFont(new Font("Tahoma", 1, 16));
        jLabel4.setForeground(new Color(229, 137, 0));
        jLabel4.setText("Active Search Settings");
        jLabel4.setAlignmentX(CENTER_ALIGNMENT);
        this.add(jLabel4);

        //Active
        this.add(new JLabel("  "));
        this.jCheckBoxActive = new JCheckBox();
        this.jCheckBoxActive.setSelected(true);
        this.jCheckBoxActive.setText("Active Search");
        this.jCheckBoxActive.setAlignmentX(CENTER_ALIGNMENT);
        this.jCheckBoxActive.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent evt)
            {
                SearchComponent.this.saveSettings();
            }
        });
        this.add(jCheckBoxActive);

        //Active Table
        this.add(new JLabel("  "));

        String[] cols =
        {
            "URL", "Field", "Value"
        };
        activeModel = new DefaultTableModel(5, cols.length)
        {
            @Override
            public boolean isCellEditable(int row, int column)
            {
                return false;
            }
        };

        activeModel.setColumnIdentifiers(cols);
        this.jTableActive = new JTable(activeModel);
        JScrollPane scrollPane = new JScrollPane(this.jTableActive, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS, JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        Dimension d = this.jTableActive.getPreferredSize();
        this.jTableActive.setPreferredScrollableViewportSize(new Dimension(d.width, this.jTableActive.getRowHeight() * 5));
        this.add(scrollPane);

        //Add Load/Save Buttons
        this.jButtonLoad = new JButton("Load");
        this.jButtonLoad.addActionListener((ActionEvent e)
                -> 
                {
                    JFileChooser jFileChooser = new JFileChooser();
                    int sf = jFileChooser.showOpenDialog(null);
                    if (sf == JFileChooser.APPROVE_OPTION)
                    {
                        String path = jFileChooser.getSelectedFile().getAbsolutePath();
                        try
                        {
                            FileInputStream fileIn = new FileInputStream(path);
                            ObjectInputStream input = new ObjectInputStream(fileIn);
                            Vector v = (Vector) input.readObject();
                            String[] headers =
                            {
                                "URL", "Field", "Value"
                            };
                            Vector headr = new Vector();
                            headr.addAll(Arrays.asList(headers));
                            activeModel.setDataVector(v, headr);
                            jTableActive.setModel(activeModel);
                            activeModel.fireTableDataChanged();
                        }
                        catch (FileNotFoundException ex)
                        {
                            extender.println(ex.getMessage());
                        }
                        catch (IOException ex)
                        {
                            extender.println(ex.getMessage());
                        }
                        catch (ClassNotFoundException ex)
                        {
                            extender.println(ex.getMessage());
                        }
                    }

        });

        this.jButtonSave = new JButton("Save");
        this.jButtonSave.addActionListener((ActionEvent e)
                -> 
                {
                    JFileChooser jFileChooser = new JFileChooser();
                    int sf = jFileChooser.showSaveDialog(null);
                    if (sf == JFileChooser.APPROVE_OPTION)
                    {
                        String path = jFileChooser.getSelectedFile().getAbsolutePath();
                        String filename = jFileChooser.getSelectedFile().getName();
                        File f = new File(path);
                        try
                        {
                            FileOutputStream fileOut = new FileOutputStream(path);
                            ObjectOutputStream output = new ObjectOutputStream(fileOut);
                            DefaultTableModel md = (DefaultTableModel) jTableActive.getModel();
                            output.writeObject(md.getDataVector());
                        }
                        catch (FileNotFoundException ex)
                        {
                            extender.println(ex.getMessage());
                        }
                        catch (IOException ex)
                        {
                            extender.println(ex.getMessage());
                        }
                    }
        });

        jCheckPanel = new JPanel(new FlowLayout());
        jCheckPanel.add(jButtonLoad);
        jCheckPanel.add(jButtonSave);
        this.add(jCheckPanel);
    }

    public DefaultListModel<String> getModel()
    {
        return model;
    }

    public boolean isPassiveHeaderEnabled()
    {
        return jCheckBoxHeader.isSelected();
    }

    public boolean isPassiveBodyEnabled()
    {
        return jCheckBoxBody.isSelected();
    }

    public boolean isActiveEnabled()
    {
        return jCheckBoxActive.isSelected();
    }

    public void addActiveParam(String value, ActiveParam param)
    {
        activeParams.put(value, param);
        this.activeModel.insertRow(0, new String[]
        {
            param.getURI(), param.getName(), value
        });
    }

    public HashMap<String, ActiveParam> getActiveParams()
    {
        return activeParams;
    }
}
