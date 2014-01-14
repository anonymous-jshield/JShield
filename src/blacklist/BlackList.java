package blacklist;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;
import org.apache.commons.httpclient.*;
import org.apache.commons.httpclient.methods.*;
import org.apache.commons.httpclient.params.*;
import java.net.*;

public class BlackList {
	private Vector<String> list;
	private String safe_browser_url = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=ABQIAAAA-CRxO_KqOjILpD38c4N99RQTVbRwRNk-lVdWO3biQkkwLT2pfw&appver=1.5.2&pver=3.0";
	private int limit_per_post = 450;
	private String dir = null;
	private Vector<String> white_list = new Vector<String>();
	public BlackList(){
		list = new Vector<String>();
		white_list = new Vector<String>();
	}
	private String getDomainName(String url){
		if(!url.startsWith("http") && !url.startsWith("https")){
			url = "http://" + url;
		} 
		//System.err.println("In getDomainName "+url);
		String domain = url;
		try{
			java.net.URI uri = new java.net.URI(url);  
			domain = uri.getHost();
		}
		catch(URISyntaxException e){
			System.err.println("Error getting domain: "+url);
		}
		catch(NullPointerException e){
			System.err.println("Error getting domain: "+url);
		}
		catch(Exception e){
			System.err.println("Error getting domain: "+url);
		}
		
		//System.err.println("In getDomainName "+domain);
		domain = domain==null ? url : domain;
		if(domain.startsWith("http")){
			domain = domain.replace("http://","");
		}
		else if(domain.startsWith("https")){
			domain = domain.replace("https://","");
		}
		if(domain.endsWith("/")){
			domain = domain.substring(0,domain.length()-1);
		}
		return domain.startsWith("www.") ? domain.substring(4) : domain;
	}
	public BlackList(String dir, String file_name){
		list = new Vector<String>();
		this.dir = dir;
		if(file_name==null){
			file_name = "blacklist.lst";
		}
		String line=null;
		try {
			FileInputStream fstream = new FileInputStream(dir+file_name);
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			//Read File Line By Line
			while ((line = br.readLine()) != null)   {
				String tmp = line.trim();
				//System.err.println("1"+tmp);
				tmp = getDomainName(tmp);
				//System.err.println("2"+tmp);
				if(!list.contains(tmp))
					list.add(tmp);
			}
			br.close();
			in.close();
			fstream.close();
		} catch (IOException e) {
			System.err.println("SEVERE ERROR:"+e);
		} catch (Exception e){
			System.err.println("ERROR:"+e+" "+line);
		}
		try {
			FileInputStream fstream = new FileInputStream(dir+"whitelist.lst");
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			//Read File Line By Line
			while ((line = br.readLine()) != null)   {
				String tmp = line.trim();
				tmp = getDomainName(tmp);
				if(!white_list.contains(tmp))
					white_list.add(tmp);
			}
			white_list.add("google.com");
			br.close();
			in.close();
			fstream.close();
		} catch (IOException e) {
			System.err.println("SEVERE ERROR:"+e);
		} catch (Exception e){
			System.err.println("ERROR:"+e);
		}
		//System.err.println("Current Blacklist's Size:"+list.size());
		//System.err.println(list);
	}

	public Vector<String> detectURLsInBlackList(Vector<String> urls, boolean detectBlackList){
		String body = "";
		Vector<String> rs = new Vector<String>();
		Iterator<String> it=urls.iterator();
		int i = 0;
		int handled_urls = 0;

		Vector<String> batch = new Vector<String>();
		while(it.hasNext()){
			String url = it.next();
			url = url.trim();
			url = getDomainName(url);
			//if(!url.startsWith("http")){
			//	url = "http://"+url;
			//	System.err.println("Constructed Url: "+url);
			//}
			//Detect it in existing blacklist
			if(list.contains(url)){
				rs.add(url);
				continue;
			}
			//System.err.println("4");
			if(white_list.contains(url)){
				continue;
			}
			//System.err.println("5");
			//Detect it from Google Safe Browsing
			if(!batch.contains(url)){
				batch.add(url);
			}
			if(batch.size()>= limit_per_post){
				body = String.valueOf(batch.size())+"\n";
				Iterator<String> iter = batch.iterator();
				while(iter.hasNext()){
					body += iter.next()+"\n";
				}
				String temp = initiatePostRequest(safe_browser_url,new HashMap(),body);
				if(temp==null){
				}
				else{
					String[] resps = temp.split("[\n]");
					for(int j=0; j<resps.length; j++){
						if(resps[j].contains("malware") || resps[j].contains("phishing")){
							url = batch.get(j);
							rs.add(url);
						}
						else{
							white_list.add(batch.get(j));
						}
					}
				}
				body = "";
				batch.clear();
			}			
		}
		if(batch.size()>0){
			body = String.valueOf(batch.size())+"\n";
			Iterator<String> iter = batch.iterator();
			while(iter.hasNext()){
				body += iter.next()+"\n";
			}
			String temp = initiatePostRequest(safe_browser_url,new HashMap(),body);
			if(temp==null){
			}
			else{
				String[] resps = temp.split("[\n]");
				for(int j=0; j<resps.length; j++){
					if(resps[j].contains("malware") || resps[j].contains("phishing")){	 
						rs.add(batch.get(j));
					}
					else{
						white_list.add(batch.get(j));
					}
				}
			}
		}
		if(rs!=null && rs.size()>0){
			outputBlackList(null);
		}
		return rs;
	}

	public String initiatePostRequest(String url, Map<String, String> params, String body){
		String response = null; 
        HttpClient client = new HttpClient(); 
        PostMethod method = new PostMethod(url); 
       // method.get
        RequestEntity ent=null;
		try {
			ent = new StringRequestEntity(body,"text/html","UTF-8");
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
        method.setRequestHeader("Content-Length", String.valueOf(body.length()));
        method.setRequestEntity(ent);
        method.setRequestHeader("User-Agent", "firefox");

        if (params != null) { 
                HttpMethodParams p = new HttpMethodParams(); 
                for (Map.Entry<String, String> entry : params.entrySet()) { 
                        p.setParameter(entry.getKey(), entry.getValue()); 
                } 
                method.setParams(p); 
        } 
        try { 
                client.executeMethod(method); 
                if (method.getStatusCode() == HttpStatus.SC_OK) { 
                        response = method.getResponseBodyAsString(); 
                        
                } 
               // System.err.println(method.getResponseBodyAsString());
        } catch (IOException e) { 
                System.err.println("HTTP Post Error:" + url + ""); 
        } finally { 
                method.releaseConnection(); 
        } 
        return response; 
	}
	public void updateBlackList(Vector<String> vs){
		Iterator<String> it = vs.iterator();
		while(it.hasNext()){
			String url = it.next();
			try{
				if(!list.contains(url)){
					list.add(url);
				}
			}
			catch(Exception e){
				System.err.println("Error in Splitting Host: "+url);
			}
		}
		System.err.println("After updated, there are "+list.size()+" items in blacklist");
	}
	public void outputBlackList(String fileName){
    	try{
    		if(fileName==null)
    			fileName = "blacklist.lst";
	    	FileWriter fos=new FileWriter(dir+fileName); 
			BufferedWriter bw=new BufferedWriter(fos); 
			Iterator<String> it = list.iterator();
			while(it.hasNext()){
				bw.write(it.next()+"\n");
			}
			
			bw.close();
			fos.close();
    	}
    	catch(IOException e){
    		System.err.println("IOException in outputError Info "+e);
    	}
    }

	public Vector<String> detectFile(String addr){
		Vector<String> rs = new Vector<String>();
		Vector<String> batch = new Vector<String>();
		try {
			FileInputStream fstream = new FileInputStream(addr);
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			String line;
			//Read File Line By Line
			String cur_file = "";
			int i = 0;
			while ((line = br.readLine()) != null)   {
				String tmp = line.trim();
				String[] strs = tmp.split("[ ]");
				if(strs[0].equals(cur_file)){
					batch.add(strs[1]);
				}
				else{
					i++;
					System.err.println("Handling "+i+" file "+strs[0]+" "+batch.size());
					if(batch.size() != 0){
						Vector<String> r = detectURLsInBlackList(batch,true);
						if(r !=null && r.size()>0){
							rs.add(cur_file);
							System.err.println("file "+cur_file+" Bad");
						}
						else{
							System.err.println("file "+cur_file+" Good");
						}
					}
					batch.clear();
					cur_file = strs[0];	
					batch.add(strs[1]);
				}		
			}
			System.err.println("There are "+i+" files");
			
			br.close();
			in.close();
			fstream.close();
		} catch (IOException e) {
			System.err.println(e);
		}
		return rs;
	}
	
	public int testBlackList(){
		System.err.println("check list size:"+list.size());
		Vector<String> rs = detectURLsInBlackList(list,true);
		return rs.size();
	}
	public Vector<String> readIntoVecor(String dir){
		Vector<String> result = new Vector<String>();
		try {
			FileInputStream fstream = new FileInputStream(dir);
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			String line;
			//Read File Line By Line
			while ((line = br.readLine()) != null)   {
				String tmp = line.trim();
				String[] strs = line.split("[ ]");
				result.add(strs[1]);
			}
			
			br.close();
			in.close();
			fstream.close();
		} catch (IOException e) {
			System.err.println(e);
		}
		return result;
	}
	public static void changeStandardOutput(String str){
		File ff = new File(str);
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(ff);
			PrintStream ps = new PrintStream(fos);
			System.setOut(ps);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	public static void main(String[] args) {
		//Use new BlackList("/",null)
		//	Use detectFile to a file of links
		//	Or Use detectURLsInBlackList(Vector<String> urls,true) to detect the urls in the vector
		//Use updateBlackList to update Blakclist
		//Use outputBlackList to save black list in disk
		
		BlackList bl = new BlackList("//home//xpan//JShield_files//ast_blacklist//blacklist//",null);
		Vector<String> rs = bl.detectFile("/home/xpan/JShield_files/ast_blacklist//links");
		System.err.println("mal files:"+rs.size());
		
		System.err.println("Test: "+bl.testBlackList());
	
	}
}
