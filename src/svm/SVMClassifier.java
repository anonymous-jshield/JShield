package svm;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Vector;


public class SVMClassifier {
	FeaturesDBHandler2 fdbh = null;
	HashMap<String,Feature> feature_priority = null;
	HashMap<String,Feature> secondary_feature_priority = null;
	HashMap<String,Feature> third_feature_priority = null;
	JSProcessor jsp = null;
	Vector<String> combined_features = null;
	//This is used to debug 
	public HashMap<String,Integer> common_features = new HashMap<String,Integer>();
	
	public SVMClassifier(){
		fdbh = new FeaturesDBHandler2();
		jsp = new JSProcessor(fdbh,0);
		
	}
	public SVMClassifier(FeaturesDBHandler2 f){
		fdbh = f;
		jsp = new JSProcessor(fdbh,0);
		
	}
	
	public void init(){
		try {
			fdbh.calculateDBInfo();
			feature_priority = fdbh.getSelectedFeaturesMap();
		
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public void commonFeatures(String dir){
		
		File folder=new File(dir);
        File[] entries=folder.listFiles();
        int i = 0;
        for (File file: entries){
        	i++;
        	Vector<String> source_code = null;
			try {
				source_code = jsp.extractSourceCodeFromJSFile(file);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			HashSet<String> feat = jsp.extractFeatureFromSourceCode(source_code,file.getName());
			Iterator<String> it = feat.iterator();
        	while(it.hasNext()){
        		System.out.println(it.next());
        	}
        }
	}
	
	public int generateSVMDataFile(String dir_name, int malicious, String file_name){
		File folder=new File(dir_name);
        File[] entries=folder.listFiles();
        feature_priority = fdbh.getSelectedFeaturesMap();
        //svm.JSProcessor jsp = new svm.JSProcessor(fdbh,0);
        try{
        
        	FileWriter fos=new FileWriter("//Users//ap//Documents//JS_SOURCE_CODE//svm_data//"+file_name,true); 
        	BufferedWriter bw=new BufferedWriter(fos);
		
	        for (File file: entries){
	        	Vector<String> source_code;
				try {
					int flag=1;
					char sign = (malicious==0?'-':'+');
					bw.write(sign+"1 ");
					source_code = jsp.extractSourceCodeFromJSFile(file);
					HashSet<String> feat = jsp.extractFeatureFromSourceCode(source_code,file.getName());
				
					Iterator<String> it_features = feature_priority.keySet().iterator();
					int i = 0;
					while(it_features.hasNext()){
						i++;
						String str = it_features.next();
						if(feat.contains(str)){
							flag = 1;
						}
						else{
							flag = 0;
						}
						bw.write(i+":"+flag+" ");
					}
					bw.write("\n");
					Vector<String> vs = new Vector<String>();
					if(feat.size()==0){
						return -1;
					}
					
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					return -1;
				}	
	        }
	        bw.close();
	        fos.close();
        }
	    catch(IOException e){
	    	System.err.println("IOError in generate DATA file outside");
	    	e.printStackTrace();
	    }
        
        return 0;
	}
	
	public int startToClassify(File f){
		try{
			feature_priority = fdbh.getSelectedFeaturesMap();
			
			Vector<String> source_code = jsp.extractSourceCodeFromJSFile(f);
			HashSet<String> feat = jsp.extractFeatureFromSourceCode(source_code,f.getName());
			Iterator<String> it = feat.iterator();
			Vector<String> vs = new Vector<String>();
			if(feat.size()==0){
				return -1;
			}
			Vector<String> mal_vec = new Vector<String>();
			Vector<String> ben_vec = new Vector<String>();
			//System.out.println("Finished Analyzing Pages "+feat.size());
			if(feature_priority==null){
				System.out.println("NULL");
				return -1;
			}
			//System.out.println(feature_priority.size());
			while(it.hasNext()){
				String str = it.next();
				if(feature_priority.containsKey(str)){
					vs.add(str);
				}
			}
			double benign = 1.0, malicious = 1.0;
			int mal_feature_count = 0;
			
			it = vs.iterator();
			while(it.hasNext()){
				//System.out.println("1");
				Feature fea = feature_priority.get(it.next());
				//System.out.println(fea);
				if(fea.ben_ratio<fea.mal_ratio){
					mal_feature_count++;
					mal_vec.add(fea.str);
				}
				else{
					ben_vec.add(fea.str);
				}
				benign *= fea.ben_ratio;
				malicious *= fea.mal_ratio;
			}
			
			System.out.println("File "+f.getName()+" has feature:"+vs.size()+"  malicious feature:"+mal_feature_count );
			if(benign>malicious){
				Iterator<String> temp = ben_vec.iterator();
				while(temp.hasNext()){
					System.out.println(temp.next());
				}
				//System.out.println("{"+vs+"}");
			}
			return benign>=malicious?0:1;
			
		}
		catch(Exception e){
			System.err.println("error in startToClassify: "+e);
			e.printStackTrace();
			System.exit(1);
			return -1;
		}
	}
	
	
	public int countCommonFeatures(File f){
		try{
			//feature_priority = fdbh.getSelectedFeaturesMap();
			Vector<String> source_code = jsp.extractSourceCodeFromJSFile(f);
			HashSet<String> feat = jsp.extractFeatureFromSourceCode(source_code,f.getName());
			Iterator<String> it = feat.iterator();
			Vector<String> vs = new Vector<String>();
			if(feat.size()==0){
				return -1;
			}
			while(it.hasNext()){
				String str = it.next();
				if(common_features.containsKey(str)){
					Integer val = common_features.get(str);
					val += 1;
					common_features.put(str,val);
				}
				else{
					common_features.put(str, new Integer(1));
				}
			}
			return 0;
			
		}
		catch(Exception e){
			System.err.println("error in startToClassify: "+e);
			e.printStackTrace();
			System.exit(1);
			return -1;
		}
	}
}
