package svm;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Vector;

import org.eclipse.wst.jsdt.core.dom.AST;
import org.eclipse.wst.jsdt.core.dom.ASTParser;
import org.eclipse.wst.jsdt.core.dom.JavaScriptUnit;
//import org.eclipse.jface.text.*;
//org.eclipse.jdt.core

public class JSProcessor implements Runnable{
	long starttime = 0;
	int isMalicious = 0;
	private String dir = null;
	//String outFolder = "output";
	private File folder = null;
    private File[] entries = null;
    private Vector<String> contents = null;
    HashSet<String> set = null;
    private Connection conn = null;
    private HashSet<String> handled_files = null;
    
    FeaturesDBHandler2 fdbh = null;
    public void setHandled_files(SharedStringSet set){
    	handled_files = set.handled_files;
    }
    
    public JSProcessor(FeaturesDBHandler2 db, int malicious){
    	this.dir = "//Users//ap//Documents//js";
    	this.fdbh = db;
    	this.isMalicious = malicious;
    	init();
    	
    }
    public JSProcessor(String dir, FeaturesDBHandler2 db, int malicious){
    	this.dir = dir;
    	this.fdbh = db;
    	this.isMalicious = malicious;
    	init();
    }
    public void run(){
    	System.out.println(Thread.currentThread().getName()+" start to process");
    	try {
    		System.out.println("Start to get handled Files");

    		if(handled_files == null){
    			System.err.println("handled_files set has not initiated yet");
    			return ;
    		}
    		
    		System.err.println("Start to add Features");
			addFeatures();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
    }
    
    //The entries should be set
    public void addFeatures() throws IOException{
    	if(entries == null){
    		System.err.println("Entries have not been set");
    		return ;
    	}
    	int i = 0;
    	for(File file:entries){
    		i++;
 	    	// System.out.println(file.getName());
 	       /* if (!file.getName().endsWith(".src") && !file.getName().contains(".src")){
 	        	continue;
 	        }
 	        */
    		String file_name = null;
    		if(file.getName().endsWith(".src")){
    			file_name = file.getName();
    		}
    		else if(file.getName().contains(".src")){
    			int index = file.getName().lastIndexOf(".src");
    			file_name = file.getName().substring(0,index+4);
    			
    			//System.out.println("This is a part of file "+file_name);
    		}
    		else{
    			continue;
    		}
 	        
    		//ATTENTION: handled_files set contain full filename, 
    		//i.e. xxxx.com.src1
 	        if(handled_files.contains(file_name)){
 	        	System.out.println(file_name+" has been handled");
 	        	continue;
 	        }
 	       
 	        System.out.println(Thread.currentThread().getName()+":"+file.getName()+" File Number"+i);
 	 		starttime = System.currentTimeMillis();
 	        //Extract the Source Codes from file
 	 		contents = extractSourceCodeFromJSFile(file);
 	 		//Extract the Features from source code
 	 		//System.out.println("Extract Features");
 	 		set = extractFeatureFromSourceCode(contents, file.getName());
 	 		System.out.println("Start to insert Set. Set size:"+set.size());		
 	 		Iterator<String> it=set.iterator();
 	 		while(it.hasNext()){
 	 			System.out.println(it.next());
 	 		}
 	 		
 	 		try{
 	 			//outputFeaturesToFiles(it,dir+"//output//",file);
 	 			System.err.println(Thread.currentThread().getName()+":"+file.getName());
 	 			fdbh.insertSet(set, isMalicious,file_name);
 	 			
 	 		}
 	 		catch(Exception e){
 	 			System.err.println("Error in outputing "+e);
 	 			e.printStackTrace();
 	 			//System.exit(1);
 	 		}
 	 		
 	 		long endtime = System.currentTimeMillis();
 	 		
 	 		System.out.println("File ["+i+"] Run time: "+(endtime-starttime)+" "+file.getName()+" has feature "+set.size());
 	 	//	set = null;
 	 	//	System.out.println(set);
 	        System.gc();
 	        
 	    }//for file
    	System.out.println("Malicious Features: "+fdbh.getMalFeatures());
    	System.out.println("Benign Features: "+fdbh.getBenFeatures());
    	System.out.println("Malicious Files: "+fdbh.getMalFiles());
    	System.out.println("Benign Files: "+fdbh.getBenFiles());
    	
    }//addFeatures
    
    //This function is called only after dir has been set
    private boolean init(){
    	File folder=new File(dir);
        entries=folder.listFiles();
        contents = new Vector<String>();
        set = new HashSet<String>();
        conn = null;
        //fdbh = new FeaturesDBHandler();
	    
	    return true;
    }
    
    //The Source Codes extracted from the file
    public Vector<String> extractSourceCodeFromJSFile(File file) throws IOException{
    	//Vector<String> contents = new Vector<String>();	
    	contents.clear();
 		try {	
 			FileReader fr = new FileReader(file);
 			BufferedReader in = new BufferedReader(fr);
 			String line = null;
 			Boolean start = false;
 			StringBuffer cur_codes = new StringBuffer("");
 			while (null != (line = in.readLine())) {
 				if(start){
 					//find [Source Code End]
 					if(line.contains("[Source Code End]")){
 						start = false;			
 						contents.add(cur_codes.toString());
 						cur_codes.setLength(0);
 					}
 					else{
 						cur_codes.append(line.toLowerCase()+"\n");
 					}
 				}
 				else{
 					//if(line.contains("[Source Code Start]")){
 					if(line.contains("[Source Code Start]")){	
 						start = true;
 					}
 				}
 			}	
 			in.close();
 			fr.close();		
 		}//try
 		catch(IOException e){
 			System.err.println("IOException in extractSourceCodeFromJSFile "+e);
 			//System.exit(1);
 		}
 		catch(Exception e){
 			System.err.println("Unexpected Error:"+e);
 			e.printStackTrace();
 			System.in.read();
 		}
	 	return contents;
    }//extractSourceCodeFromJSFile
    
    public HashSet<String> extractFeatureFromSourceCode(Vector<String> contents, String fileName){
    	int count = 0;
 		ASTParser parser = null;
 		JSVisitor2 jsv = null;
 		JavaScriptUnit result = null;
 		//HashSet<String> set = new HashSet<String>();
 		//System.out.println("There are "+contents.size()+" conetexts in file "+file.getName());
 		set.clear();
 	
 		
 		for(int i=0; i<contents.size(); i++){
 			
 			//System.out.print(contents.size()+"  "+i);
 			//System.out.println(contents.elementAt(i));
 			parser = ASTParser.newParser(AST.JLS3);  
	 		parser.setSource(contents.elementAt(i).toCharArray());
 			
	 		jsv=null;
	 		result=null;
	 		
	 		try{
	 			//System.out.print(" 11 "+contents.elementAt(i));
	 			result = (JavaScriptUnit) parser.createAST(null);
	 			jsv = new JSVisitor2("text");
	 			result.accept(jsv);
	 			
	 			
	 			//System.gc();
	 		}
	 		catch(Exception e){
	 			count++;
	 			System.err.println("Exception in extracting features:"+e);
	 			//e.printStackTrace();
	 			//System.err.println("Source Code Error: "+contents.elementAt(i));
	 			//System.out.println(buffer.toString());
	 		}	
	 		catch (NoClassDefFoundError err){
				System.err.println("An Error!!!:"+err);
			}
	    	
	 		//System.out.print(" 33 ");
	 		if(jsv==null){
	 			System.err.println("Failing Extracting Features count:"+count+" i:"+i);
	 			//outputErrorInfo(contents.elementAt(i),fileName);
	 			continue;
	 		}
	 		HashSet<String> temp_set = jsv.getFeatureSet();
	 		Iterator<String> iter= temp_set.iterator();
	 		
	 		//System.out.print(" 44 ");
	 		
	 		while(iter.hasNext() ){
	 			set.add(iter.next());
	 		}	
	 		//System.out.println("===="+i);
	 		//System.out.println(temp_set.size()+"=="+set.size());
 		}//for
 		//outputErrorInfo(set.toString(),"xx");
 		//System.out.println(set.size()+" Error source code counts:"+count);
 		//contents = null;
 		return set;
    }
    
    private void outputFeaturesToFiles(Iterator<String> it, String dir, File file){
    	try{
	    	FileWriter fos=new FileWriter(dir+"//"+file.getName()+".out"); 
			BufferedWriter bw=new BufferedWriter(fos); 
			while(it.hasNext()){
	 			String str = it.next();
	 			bw.write(str+"\n");
	 			//System.out.println(str+file.getName());
	 		}
			bw.close();
			fos.close();
    	}
    	catch(IOException e){
    		System.err.println("IOException in outputFeaturesToFiles");
    	}

    }
    
    private void outputErrorInfo(String message,String fileName){
    	try{
	    	FileWriter fos=new FileWriter(dir+"//err//"+fileName+".out",true); 
			BufferedWriter bw=new BufferedWriter(fos); 
			bw.write(message);
			bw.close();
			fos.close();
    	}
    	catch(IOException e){
    		System.err.println("IOException in outputError Info "+e);
    	}

    }
}
