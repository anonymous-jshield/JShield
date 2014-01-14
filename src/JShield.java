import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import nb_ast.NBClassifier;

import org.eclipse.wst.jsdt.core.dom.AST;
import org.eclipse.wst.jsdt.core.dom.ASTParser;
import org.eclipse.wst.jsdt.core.dom.JavaScriptUnit;


public class JShield {
	public static void changeStandardOutput(String str){
		File ff = new File(str);
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(ff);
			PrintStream ps = new PrintStream(fos);
			//System.setOut(ps);
			System.setErr(ps);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		//System.out.println("All the debugging or error information will be output to file jshield.log");
		changeStandardOutput("../logs/jshield.log");
		//USAGE: (train/classify dir)
		Properties prop = new Properties();
		String db_url=null;
		String db_name = null;
		String db_user = null;
		String db_passwd = null;
		String feature_dir = null;
		String tfiles_dir = null;
		String blist_dir = null;
    	try {
    		prop.load(new FileInputStream("../config.properties"));
    		//prop.load(new FileInputStream("/home/xpan/JShield_files/ast_blacklist/config.properties"));
    		db_url = prop.getProperty("db_url");
    		db_name = prop.getProperty("db_name");
    		db_user = prop.getProperty("db_user");
    		db_passwd = prop.getProperty("db_password");
    		feature_dir = prop.getProperty("feature_dir");
    		tfiles_dir = prop.getProperty("tfiles_dir");
    		blist_dir = prop.getProperty("blist_dir");
           // System.out.println(prop.getProperty("tfiles_dir"));
    		//System.out.println(prop.getProperty("feature_dir"));
    		//System.out.println(prop.getProperty("db_name"));
 
    	} catch (IOException ex) {
    		ex.printStackTrace();
        }
    	int func = -1;
    	try{
    		func = Integer.parseInt(args[0]);
    		if(func != 1 && func != 2 && func !=3 && func != 4 && func != 5){
    			System.out.println("Usage: [1|2] (train or test) [address]");
        		System.exit(1);
    		}
    	}
    	catch(Exception e){
    		System.out.println("Usage: [1|2] (train or test) [address]");
    		System.exit(1);
    	}
    	blacklist.BlackList black_list = new blacklist.BlackList(blist_dir, null);
    	
    	// func thread_number addr1 flag1 addr2 flag2 ben_valid mal_valid
    	if (func == 1){
    		System.out.println("Start to train: ");
    		System.out.println("Thread number "+args[1]);
    		int thread_num = -1;
    		try{
    			thread_num = Integer.parseInt(args[1]);
    		}catch(Exception ee){
    			System.err.println("USAGE");
    			System.exit(1);
    		}
    		String b_valid_dir = args[args.length-2];
    		String m_valid_dir = args[args.length-1];
    		nb_ast.FeaturesDBHandler fdbh = new nb_ast.FeaturesDBHandler(db_url, db_user, db_passwd, db_name,tfiles_dir, feature_dir);
    		fdbh.initConnection();
    		nb_ast.SharedStringSet sv = new nb_ast.SharedStringSet();
    		sv.handled_files = fdbh.getHandledFiles();
    		System.err.println("Get Handled Files: Size "+sv.handled_files.size());
    		nb_ast.JSProcessor[] jsps = new nb_ast.JSProcessor[thread_num];
    		Thread[] ts = new Thread[thread_num];
    		for(int i=2, j=0; j<thread_num; i+=2,j++){
    			jsps[j] = new nb_ast.JSProcessor(args[i],fdbh,Integer.parseInt(args[i+1]));
    			jsps[j].setHandled_files(sv);
    			ts[j] = new Thread(jsps[j]);
			ts[j].start();
    			System.out.println("Thread "+j+" handle folder "+args[i]+" "+args[i+1]);
    		}
    		boolean next_step = false;
    		while(!next_step){
    			next_step = true;
    			for(int j=0; j<ts.length;j++){
    				if(ts[j].isAlive()){
    					next_step = false;
    					break;
    				}
    			}
    			try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
    		}
    		System.out.println("Finished extracting features");
    		System.out.println("Start to select features");
    		fdbh.selectFeature();
    		fdbh.optimizeFeatureSets(b_valid_dir, m_valid_dir);
    		System.out.println("Finished training");
    	}
    	else if(func == 2){
    		System.out.println("Start to test "+args[1]);
    		nb_ast.FeaturesDBHandler fdbh = new nb_ast.FeaturesDBHandler(db_url, db_user, db_passwd, db_name,tfiles_dir, feature_dir);
    		
    		nb_ast.NBClassifier cla= new nb_ast.NBClassifier(fdbh,black_list);
    		cla.initForClassifying();
    	 	File folder=new File(args[1]);
            File[] entries=folder.listFiles();
            int mal = 0;
            int ben = 0;
            int emp = 0;
            int i=0;
            String rs_name = null;
            for (File file: entries){
            	i++;
            	System.err.println("#"+i+": "+file.getName()+" start...");
            	int rs = cla.startToClassify(file);
            	if(rs==1){ 
            		mal++;
            		rs_name = "Malicious";
            	}
            	else if(rs==0){
            		ben++;
            		rs_name = "Benign";
            	}
            	else{
            		emp++;
            		rs_name = "Unable to classify";
            	}
            	
            	System.out.println(file.getName()+" result:"+rs_name);
            }
            cla.getBlackList().outputBlackList(null);
            System.out.println("Malicious Files:"+mal+"  Benign Files:"+ben+"  Broken Files"+emp);
    	}
	else if(func == 3){
    		//System.out.println("Start to test "+args[1]);
    		nb_ast.FeaturesDBHandler fdbh = new nb_ast.FeaturesDBHandler(db_url, db_user, db_passwd, db_name,tfiles_dir, feature_dir);
    		nb_ast.NBClassifier cla= new nb_ast.NBClassifier(fdbh,black_list);
    		cla.initForClassifying();
    	 	File file=new File(args[1]);
		if(!file.exists()){
			System.out.println("File "+args[1]+" doesn't exist");
			return;
		}
		int rs = cla.startToClassify(file);
		String rs_name = "Unknown";
            	if(rs==1){ 
            		rs_name = "Malicious";
            	}
            	else if(rs==0){
            		rs_name = "Benign";
            	}
            	else{
            		rs_name = "Unable to classify";
            	}
            	System.out.println(file.getName()+" result:"+rs_name);
            	cla.getBlackList().outputBlackList(null);
	}
    	else if(func == 4){ 
    		System.out.println("Start to insert features into database: ");//System.out.println("Thread number "+args[1]);
    		int flag = -1;
    		try{
    			flag = Integer.parseInt(args[1]);
    		}catch(Exception ee){
    			System.err.println("USAGE flag dir");
    			System.exit(1);
    		}
    		nb_ast.FeaturesDBHandler fdbh = new nb_ast.FeaturesDBHandler(db_url, db_user, db_passwd, db_name,tfiles_dir, feature_dir);
    		fdbh.initConnection();
    		nb_ast.JSProcessor jsp = new nb_ast.JSProcessor(args[2],fdbh,flag);
			try{
				jsp.addFeatures();
				System.out.println("Finish addind fetures, now start writing features");
				fdbh.outputFeaturesInOrder(flag);
			}
			catch(Exception e){
				System.err.println("addFeatures:");
				e.printStackTrace();
			}
    		System.out.println("Finished extracting and adding features");
    	}
		else if(func == 5){ 
    		System.out.println("Start to select features: ");//System.out.println("Thread number "+args[1]);
    		int flag = -1;
  
    		nb_ast.FeaturesDBHandler fdbh = new nb_ast.FeaturesDBHandler(db_url, db_user, db_passwd, db_name,tfiles_dir, feature_dir);
    		fdbh.initConnection();

    		fdbh.selectFeature();
    	 
	   	}
		else{
		System.out.println("Parameters Error");
	}
	}
	
	
}
