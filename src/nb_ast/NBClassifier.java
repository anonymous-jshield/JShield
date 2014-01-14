package nb_ast;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Vector;
import java.util.Collections;


public class NBClassifier {
	FeaturesDBHandler fdbh = null;
	HashMap<String,Feature> feature_priority = null;
	HashMap<String,Feature> secondary_feature_priority = null;
	HashMap<String,Feature> third_feature_priority = null;
	JSProcessor jsp = null;
	boolean isInitialized = false;
	blacklist.BlackList black_list = null;
	//This is used to debug 
	public HashMap<String,Integer> common_features = new HashMap<String,Integer>();
	
/*	public NBClassifier(){
		fdbh = new FeaturesDBHandler();
		jsp = new JSProcessor(fdbh,0);
		fdbh.initConnection();
	}
	*/
	public NBClassifier(FeaturesDBHandler f, blacklist.BlackList bl){
		fdbh = f;
		jsp = new JSProcessor(fdbh,0);
		fdbh.initConnection();
		black_list = bl;
	}
	public FeaturesDBHandler getFeatureDBHandler(){
		return fdbh;
	}
	
	public void init(){
		try {
			fdbh.initConnection();
			fdbh.calculateDBInfo();
			feature_priority = fdbh.getSelectedFeaturesMap();
		
		} catch (Exception e) {
			System.err.println("Init Error");
			e.printStackTrace();
		}
		
	}
	public void commonFeatures(String dir){
		
		File folder=new File(dir);
        File[] entries=folder.listFiles();
        int i = 0;
        Vector<String> links = new Vector<String>();
        for (File file: entries){
        	i++;
        	Vector<String> source_code = null;
			try {
				source_code = jsp.extractSourceCodeFromJSFile(file,links);
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
	
	public void initForClassifying(){
		//Initiation Part
		int ben_features = fdbh.getBenFeatures();
		int mal_features = fdbh.getMalFeatures();
	 	int mal_files = fdbh.getMalFiles();
	 	int ben_files = fdbh.getBenFiles();
		//System.out.println("DEBUG BEN_FEATURES: "+ben_features);
		//System.out.println("DEBUG MAL_FEATURES: "+mal_features);
	 	fdbh.setStat(ben_features, mal_features, mal_files, ben_files);
		fdbh.setModifiedFlag(false);	
		
		fdbh.initFeatureSets();
		
		feature_priority = fdbh.getSelectedFeaturesMap();
		secondary_feature_priority = fdbh.getSecondarySelectedFeaturesMap();
		third_feature_priority = fdbh.getThirdSelectedFeaturesMap();
		if(feature_priority==null||secondary_feature_priority==null||third_feature_priority==null){
			System.err.println("Error in getting feature set");
		}
		isInitialized = true;
	}
	public blacklist.BlackList getBlackList(){
		return black_list;
	}
	public int startToClassify(File f){
		try{
			if(!isInitialized){
				System.err.println("Please initialize the classifier before execute this function");
				return -1;
			}
			Vector<String> links = new Vector<String>();
			Vector<String> source_code = jsp.extractSourceCodeFromJSFile(f,links);
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
			Vector<String> mal_scripts = new Vector<String>();
 			System.out.print("MAL FEATURE: ");
			while(it.hasNext()){
				Feature fea = feature_priority.get(it.next());
				if(fea.ben_ratio<fea.mal_ratio){
					mal_feature_count++;
					mal_vec.add(fea.str);
					//System.out.print(fea.str);
					mal_scripts.add(fea.str);
				}
				else{
				//	System.out.println("DEBUG: Benign Feature[1 level]"+fea.str);
					ben_vec.add(fea.str);
				}
				benign *= fea.ben_ratio;
				malicious *= fea.mal_ratio;
			}
			//If the file doesn't contain any features in priority feature set
			//Use secondary feature set to classify
			if(vs.size()==0){	
				//System.out.print("Start to Use Second Feature Set    ");
				it = feat.iterator();
				while(it.hasNext()){
					String str = it.next();
					if(secondary_feature_priority.containsKey(str)){
						vs.add(str);
					}
				}
				it = vs.iterator();
				while(it.hasNext()){
					Feature fea = secondary_feature_priority.get(it.next());
					if(fea.ben_ratio<fea.mal_ratio){
						mal_feature_count++;
						mal_vec.add(fea.str+" B"+fea.ben_ratio+" M"+fea.mal_ratio);	
						//System.out.print(fea.str);
						mal_scripts.add(fea.str);
					}
					else{
					//	System.out.println("DEBUG: Benign Feature[2 level]"+fea.str);
						ben_vec.add(fea.str);
					}
					benign *= fea.ben_ratio;
					malicious *= fea.mal_ratio;
				}
			}
			
			if(vs.size()==0){	
				//System.out.print("Start to Use Third Feature Set    ");
				it = feat.iterator();
				while(it.hasNext()){
					String str = it.next();
					if(third_feature_priority.containsKey(str)){
						vs.add(str);
					}
				}
				it = vs.iterator();
				while(it.hasNext()){
					//System.out.println("1");
					Feature fea = third_feature_priority.get(it.next());
					//System.out.println(fea);
					if(fea.ben_ratio<fea.mal_ratio){
						mal_feature_count++;
						mal_vec.add(fea.str+" B"+fea.ben_ratio+" M"+fea.mal_ratio);	
						//System.out.print(fea.str);
						mal_scripts.add(fea.str);
					}
					else{
						ben_vec.add(fea.str);
					}
					benign *= fea.ben_ratio;
					malicious *= fea.mal_ratio;
				}				
			}
			Collections.sort(mal_scripts);
			System.out.println(mal_scripts);
			//System.out.println("File "+f.getName()+" has feature:"+vs.size()+"  malicious feature:"+mal_feature_count );
			/*
			if(benign>malicious){
				Iterator<String> temp = ben_vec.iterator();
				while(temp.hasNext()){
					System.out.println(temp.next());
				}
				//System.out.println("{"+vs+"}");
			}
			*/
			int isMalicious = benign>=malicious?0:1;
			
			//No Black List
			/*
			if(isMalicious==0){
				Vector<String> temp = black_list.detectURLsInBlackList(links, true);
				if(temp.size()>0){
					isMalicious = 1;
					black_list.updateBlackList(temp);
				}
			}
			*/
			return isMalicious;
		}
		catch(Exception e){
			System.err.println("error in startToClassify: "+e);
			e.printStackTrace();
			System.exit(1);
			return -1;
		}
	}
	
	public int extractNegativeFeatures(File f, Vector<String> first, Vector<String> second, int flag){
		try{
			if(!isInitialized){
				System.out.println("Please initialize the classifier before execute this function");
				return -1;
			}
			Vector<String> links = new Vector<String>();
			Vector<String> source_code = jsp.extractSourceCodeFromJSFile(f,links);
			HashSet<String> feat = jsp.extractFeatureFromSourceCode(source_code,f.getName());
			Iterator<String> it = feat.iterator();
			Vector<String> vs = new Vector<String>();
			if(feat.size()==0){
				return -1;
			}

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
				Feature fea = feature_priority.get(it.next());
				if(fea.ben_ratio<fea.mal_ratio){
					mal_feature_count++;
					if(flag==0) first.add(fea.str); 
				}
				else{
					if(flag==1) first.add(fea.str);
				}
				benign *= fea.ben_ratio;
				malicious *= fea.mal_ratio;
			}
			
			if(vs.size()==0){	
				it = feat.iterator();
				while(it.hasNext()){
					String str = it.next();
					if(secondary_feature_priority.containsKey(str)){
						vs.add(str);
					}
				}
				it = vs.iterator();
				while(it.hasNext()){
					Feature fea = secondary_feature_priority.get(it.next());
					if(fea.ben_ratio<fea.mal_ratio){
						mal_feature_count++;
						if(flag==0) second.add(fea.str); 
					}
					else{
						if(flag==1) second.add(fea.str);
					}
					benign *= fea.ben_ratio;
					malicious *= fea.mal_ratio;
				}
			}
			
			if(vs.size()==0){	
				//System.out.print("Start to Use Third Feature Set    ");
				it = feat.iterator();
				while(it.hasNext()){
					String str = it.next();
					if(third_feature_priority.containsKey(str)){
						vs.add(str);
					}
				}
				it = vs.iterator();
				while(it.hasNext()){
					//System.out.println("1");
					Feature fea = third_feature_priority.get(it.next());
					//System.out.println(fea);
					if(fea.ben_ratio<fea.mal_ratio){
						mal_feature_count++;
					}
					benign *= fea.ben_ratio;
					malicious *= fea.mal_ratio;
				}				
			}
			
			int isMalicious = benign>=malicious?0:1;
			if(isMalicious != flag)
				return 0;
			else
				return 1;
		}
		catch(Exception e){
			System.err.println("error in extractNegativeFeatures: "+e);
			e.printStackTrace();
			System.exit(1);
			return -1;
		}
	}
	
	public int countCommonFeatures(File f){
		try{
			//feature_priority = fdbh.getSelectedFeaturesMap();
			Vector<String> links = new Vector<String>();
			Vector<String> source_code = jsp.extractSourceCodeFromJSFile(f,links);
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
