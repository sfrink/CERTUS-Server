package org.certus.server.server;

import java.io.File;
import org.w3c.dom.Document;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import org.certus.server.enumeration.*;

/**
 * @date : Feb 26, 2014
 * @author : Hirosh Wickramasuriya
 */

public class ReaderXml {
	private String  configFile = null;
    private Document doc = null;
    
    public ReaderXml(XmlFileIdentifier fileType)
    {  
        try
        {
            DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
           
            if (fileType == XmlFileIdentifier.SERVER_CONFIGURATION)
            {
            	
                configFile = getClass().getResource(".").getFile().toString() 
                					+ ".." + System.getProperty("file.separator")
                					+ ".." + System.getProperty("file.separator")
                					+ ".." + System.getProperty("file.separator")
                					+ ".." + System.getProperty("file.separator")
                					+ ".." + System.getProperty("file.separator")
                				
                                    + "config" 
                                    + System.getProperty("file.separator") + "server.xml";
                
                doc = docBuilder.parse(new File(configFile));
            }
                    
            // normalize text representation
            if (doc != null)
            {
            	doc.getDocumentElement().normalize();
            }

        }
        catch (SAXParseException ex)
        {
            System.out.println("XML Parsing Error " 
                    + ", line" + ex.getLineNumber() 
                    + ", uri" + ex.getSystemId());
            System.out.println(" " + ex.getMessage());
        }
        catch (SAXException ex)
        {
            ex.printStackTrace();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
            
    }
    
    
    private Node getFirstLevelNode(String nodeName)
    {
        Node node = null;
        if (doc != null)
        {
            NodeList nodeList = doc.getElementsByTagName(nodeName);
            if (nodeList.getLength() >0)
            {
                node = nodeList.item(0);
            }
        }
        return node;
    }
        
    private String getValue(Node parent, String nodeName) 
    {
        String nodeValue = null;
        
        NodeList nodeList = parent.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) 
        {
            if (nodeName.equals(nodeList.item(i).getNodeName()))
            {
                nodeValue = nodeList.item(i).getTextContent();
                break;
            }
        }
        return nodeValue;
    }
    
    public String getValue(String parent, String nodeName)
    {
        Node node = getFirstLevelNode(parent);
        return getValue(node, nodeName);
    }
	
}
