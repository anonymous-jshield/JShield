package nb_ast;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Vector;


public class FeaturesDBHandler {
	private String url;
	private String user;
	private String pass;
	private String malicious_file_names;
	private String benign_file_names;
	private String db_name;
	private String feature_dir;
	
	private int mal_features = 0;
	private int ben_features = 0;
	private int mal_files = 0;
	private int ben_files = 0;
	private boolean init_flag = false;
	private int total_number = 0;
	
	
	public boolean isInited(){
		return init_flag;
	}
	public void setStat(int mfea, int bfea, int mfile, int bfile){
		mal_features = mfea;
		ben_features = bfea;
		mal_files = mfile;
		ben_files = bfile;
		
	}
	
	Connection conn=null;
	Statement stmt;
	PreparedStatement pstmt_insert_files;
	PreparedStatement pstmt_insert;
	PreparedStatement pstmt_search;
	PreparedStatement pstmt_update;
	PreparedStatement ps_mf;
	PreparedStatement pstmt_search_times;
	boolean is_modified = true;
	HashMap<String,Double> feature_priority = new HashMap<String,Double>(); 
	HashMap<String,Feature> selected_features;
	HashMap<String,Feature> secondary_selected_features;
	HashMap<String,Feature> third_features;
	HashSet<String> handled_m_files = null;
	HashSet<String> handled_b_files = null;
	
	
/*	public FeaturesDBHandler(){
		url = "localhost";
		user = "xpan";
		pass = "123456";
		db_name = "JShield_DB";
		malicious_file_names = "//Users//ap//Documents//JS_SOURCE_CODE//malicious_filenames";
		benign_file_names = "//Users//ap//Documents//JS_SOURCE_CODE//benign_filenames";
		feature_dir = "//Users//ap//Documents//JS_SOURCE_CODE//feature_sets//";
	}
	*/
	public FeaturesDBHandler(String url, String user, String pass, String db,String trained_files_dir,String feature_dir){
		this.url = url;
		this.user = user;
		this.pass = pass;
		this.malicious_file_names = trained_files_dir +"malicious_filenames" ;
		this.benign_file_names = trained_files_dir +"benign_filenames";
		this.db_name =db;
		this.feature_dir = feature_dir;
		
	}
	public void setModifiedFlag(boolean flag){
		is_modified = flag;
	}

	public int getMalFeatures(){
		if(!is_modified){
			return mal_features;
		}
		else{
			try{
				Statement s = conn.createStatement();
			 	s.executeQuery ("SELECT sum(times) FROM features where malicious=1");
			 	ResultSet rs = s.getResultSet ();
			 	//rs.last();
			 	//int count = rs.getRow();
			 	int count = 0;
			 	if(rs.next()){
			 		count = rs.getInt(1);
			 	}
			 	rs.close ();
			 	s.close ();
			 	mal_features = count;
			 	return count;
			}
			catch(SQLException sqle){
				System.err.println("Error getting malicious features: "+sqle);
				return -1;
			}
			
		}
	}
	public int getBenFeatures(){
		if(!is_modified){
			return ben_features;
		}
		else{
			try{
				Statement s = conn.createStatement();
			 	s.executeQuery ("SELECT sum(times) FROM features where malicious=0");
			 	ResultSet rs = s.getResultSet ();
			 	int count = 0;
			 	if(rs.next()){
			 		count = rs.getInt(1);
			 	}
			 	rs.close ();
			 	s.close ();
			 	ben_features = count;
			 	return count;
			}
			catch(SQLException sqle){
				System.err.println("Error getting malicious features: "+sqle);
				return -1;
			}	
		}
	}
	public int getMalFiles(){
		if(handled_m_files==null){
			this.getHandledMFiles();
		}
		return handled_m_files.size();
	}
	public int getBenFiles(){
		if(handled_b_files==null){
			this.getHandledBFiles();
		}
		return handled_b_files.size();
	}
	
	//This function is used to extract filenames from database
	//Note the suffix of filenames is src
	//The file_names in malicious/benign_file_names also ends with src
	//This function is used called initFileNames
	private void extractFileNamesFromDB(){
		try{
			Statement s = conn.createStatement();
			s.executeQuery("SELECT file_name FROM files where malicious = 1 group by file_name");
			ResultSet ts = s.getResultSet();
			
			FileWriter fos=new FileWriter(malicious_file_names);
			BufferedWriter bw=new BufferedWriter(fos); 
			while(ts.next()){
				//String str = ts.getString(1);
				String file_name = ts.getString(1);
	    		if(file_name.endsWith(".src")){		
	    		}
	    		else if(file_name.contains(".src")){
	    			int index = file_name.lastIndexOf(".src");
	    			file_name = file_name.substring(0,index+4);			
	    			//System.out.println("This is a part of file "+file_name);
	    		}
	    		else{
	    			System.err.println(file_name+" is not a file name");
	    			continue;
	    		}
				bw.write(file_name+"\n");
			}
			bw.close();
			fos.close();

			s.executeQuery("SELECT file_name FROM files where malicious = 0 group by file_name");
			ts = s.getResultSet();
			fos=new FileWriter(benign_file_names);
			bw=new BufferedWriter(fos); 
			while(ts.next()){
				String file_name = ts.getString(1);
	    		if(file_name.endsWith(".src")){	
	    		}
	    		else if(file_name.contains(".src")){
	    			int index = file_name.lastIndexOf(".src");
	    			file_name = file_name.substring(0,index+4);
	    		}
	    		else{
	    			System.err.println(file_name+" is not a file name");
	    			continue;
	    		}
				bw.write(file_name+"\n");
			}
			bw.close();
			fos.close();
		}
		catch(Exception e){
			System.err.println("Error in getHandleedFiles: "+e);
		}
	}
	
	//Get all the handled file names
	//It will invoke function getHandledMFiles() and getHandledBFiles()
	public HashSet<String> getHandledFiles(){
		if(handled_m_files==null)
			getHandledMFiles();
		if(handled_b_files==null)
			getHandledBFiles();
		
		if(handled_m_files==null || handled_b_files==null){
			System.err.println("Handled Files Reading Error");
			return null;
		}
		
		HashSet<String> handled_files = getHandledBFiles();
		
		Iterator<String> it = handled_m_files.iterator();
		while(it.hasNext()){
			handled_files.add(it.next());
		}
		it = handled_b_files.iterator();
		while(it.hasNext()){
			handled_files.add(it.next());
		}
		return handled_files;
		
	}
	
	
	public boolean initConnection() {
		boolean rs = false;
		if(conn != null){
			init_flag = true;
			return true;
		}
		try{
			Class.forName("com.mysql.jdbc.Driver");
			conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/"+db_name,user,pass);		
			if(conn != null){
				pstmt_search = conn.prepareStatement("select feature_id,times, priority from features where name=? and malicious=?",ResultSet.TYPE_SCROLL_SENSITIVE,
			            ResultSet.CONCUR_UPDATABLE);
				pstmt_search_times = conn.prepareStatement("select times from features where name=? and malicious=?");
				pstmt_insert = conn.prepareStatement("insert into features (name,times,malicious) values (?,1,?)") ;
				pstmt_insert_files = conn.prepareStatement("insert into files (feature_name,file_name,malicious) values (?,?,?)") ;
				pstmt_update = conn.prepareStatement("update features set times = ? where feature_id = ?") ;
				ps_mf = conn.prepareStatement("select times, priority from features where name=? and malicious=?");
				init_flag = true;
				return true;
			}
			return false;
		}
		catch(Exception e){
			System.err.println("Error in init connection");
			return false;	
		}
		
	}
	private void updateString(String str, int isMalicious, ResultSet rs) throws SQLException{
		rs = pstmt_search.executeQuery();
		if(rs==null){
			System.err.println("Insert failed\n");
			System.err.println(str);
			System.exit(1);
		}
		if(rs.next()){
			int id = rs.getInt(1);
			int times = rs.getInt(2);
			//System.out.println(id+" "+str+" "+times);
			times++;
			rs.updateInt("times", times);
			rs.updateRow();
		}
		else{
			pstmt_insert.setString(1, str);
			pstmt_insert.setInt(2,isMalicious);
			pstmt_insert.executeUpdate();
		}
	}
	
	private HashSet<String> getHandledMFiles(){
		handled_m_files = new HashSet<String>();
		FileInputStream fstream = null;
		DataInputStream in = null;
		BufferedReader br = null;
		try {
			fstream = new FileInputStream(malicious_file_names);
			in = new DataInputStream(fstream);
			br = new BufferedReader(new InputStreamReader(in));
			String line;
			//Read File Line By Line
			while ((line = br.readLine()) != null)   {
				  handled_m_files.add(line.trim());
			}
			mal_files = handled_m_files.size();
			br.close();
			in.close();
			fstream.close();
		} catch (IOException e) {
			System.err.println(e);
		}

		return handled_m_files;
	}
	
	private HashSet<String> getHandledBFiles(){
		handled_b_files = new HashSet<String>();
		FileInputStream fstream = null;
		DataInputStream in = null;
		BufferedReader br = null;
		try {
			fstream = new FileInputStream(benign_file_names);
			in = new DataInputStream(fstream);
			br = new BufferedReader(new InputStreamReader(in));
			String line;
			
			while ((line = br.readLine()) != null)   {
				  handled_b_files.add(line.trim());
			}
			ben_files = handled_b_files.size();
			br.close();
			in.close();
			fstream.close();
		} catch (IOException e) {
			System.err.println(e);
		}

		return handled_b_files;
	}
	
	
	//Used to insert the features and update malicious_file_names and benign_file_names if these files are new
	public synchronized void insertSet(HashSet<String> set, int isMalicious, String fileName) throws IOException{
		String str = null;
		is_modified = true;
		try
		{
			//System.out.println("In insert");
			Iterator<String> it = set.iterator();
			ResultSet rs = null;
			int i=0;
			FileWriter fos=null; 
			HashSet<String> handled_files = null;
			if(isMalicious==1){
				fos = new FileWriter(malicious_file_names,true);
				handled_files = handled_m_files;
			}
			else{
				fos = new FileWriter(benign_file_names,true);
				handled_files = handled_b_files;
			}	
			BufferedWriter bw=new BufferedWriter(fos); 
			
			boolean is_first_item = true;
			while(it.hasNext()){
				i++;
				str = it.next();
				//Prepare for updateString()
				pstmt_search.setString(1, str);
				pstmt_search.setInt(2, isMalicious);
				if(handled_files==null){
					System.err.println("Hanlded Files Set is not ready");
					getHandledMFiles();
					getHandledBFiles();
				}
				if(is_first_item && handled_files.contains(fileName)){
					System.err.println("Error file:"+fileName+" has been handled");
					return;
				}
				else if(is_first_item){
					handled_files.add(fileName);
					bw.write(fileName+"\n");
					is_first_item = false;
				}
			
				//Syncronized is needed
				updateString(str,isMalicious,rs);
				
			}
			if(bw!=null) bw.close();
			if(fos != null) fos.close();		
			if(rs != null) rs.close();
			//System.out.println("Out insert");
		}
		catch(SQLException sqle){
			System.err.println(str+str.length()+"SQLException in insertSet: "+sqle);
		}
		catch(IOException ioe){
			System.err.println("Failed writting filename to files: "+ioe+" "+str);
		}
	}

	
	public HashMap<String,Feature> getSelectedFeaturesMap(){
		return selected_features;
	}
	public HashMap<String,Feature> getSecondarySelectedFeaturesMap(){
		return secondary_selected_features;
	}
	public HashMap<String,Feature> getThirdSelectedFeaturesMap(){
		return third_features;
	}
	
	public void initFeatureSets(){
		initFeatureSet();
		initSecondaryFeatureSet();
		initThirdFeature();
	}
	
	private void initThirdFeature(){
		third_features = new HashMap<String,Feature>();
		
		try{
			  FileInputStream fstream = new FileInputStream(feature_dir+"third_features.out");
			  DataInputStream in = new DataInputStream(fstream);
			  BufferedReader br = new BufferedReader(new InputStreamReader(in));
			  String line;
			 
			  //Read File Line By Line
			  while ((line = br.readLine()) != null)   {
				  int begin = line.indexOf('[');
				  int end = line.lastIndexOf(']');
				  if(begin==-1 || end==-1){
					  continue;
				  }
				  String str = new String(line.substring(begin, end+1));
				 
				  float mal_times= 0;
				  float ben_times = 0;
				 
				  begin = line.indexOf("A:(");
				  end = line.indexOf(")",begin);
				  mal_times = Float.parseFloat(line.substring(begin+3,end));
				  
				  begin = line.indexOf("B:(");
				  end = line.indexOf(")",begin);
				  ben_times = Float.parseFloat(line.substring(begin+3,end));
							
				  mal_times += 1;
				  ben_times += 1;
				  
				  double mal_ratio = (float)(mal_times)/(float)(mal_files)*1000.0;
				  double ben_ratio = (float)(ben_times)/(float)(ben_files)*1000.0;
				  third_features.put(str, (new Feature(str,ben_ratio,mal_ratio)));
			  }	
			  in.close();
		 }
		catch (Exception e){//Catch exception if any
			  System.err.println("Error:" + e.getMessage());
			  e.printStackTrace();
		 }
	}
	
	private void initFeatureSet(){
		selected_features = new HashMap<String,Feature>();
		
		try{
			  FileInputStream fstream = new FileInputStream(feature_dir+"features.out");
			  DataInputStream in = new DataInputStream(fstream);
			  BufferedReader br = new BufferedReader(new InputStreamReader(in));
			  String line;
			  ResultSet rs = null;
			  int ben_count = 0;
			  int mal_count = 0;
			  double mal_val= 0.0;
			  double ben_val = 0.0;
			  //Read File Line By Line
			  while ((line = br.readLine()) != null)   {
				  int begin = line.indexOf('[');
				  int end = line.lastIndexOf(']');
				  if(begin==-1 || end==-1){
					  continue;
				  }
				  String str = new String(line.substring(begin, end+1));
				 
				  float mal_times= 0;
				  float ben_times = 0;
				 
				  begin = line.indexOf("A:(");
				  end = line.indexOf(")",begin);
				  mal_times = Float.parseFloat(line.substring(begin+3,end));
				  
				  begin = line.indexOf("B:(");
				  end = line.indexOf(")",begin);
				  ben_times = Float.parseFloat(line.substring(begin+3,end));
							
				  mal_times += 1;
				  ben_times += 1;
				  
				  double mal_ratio = (float)(mal_times)/(float)(mal_files)*1000.0;
				  double ben_ratio = (float)(ben_times)/(float)(ben_files)*1000.0;
				  
				  mal_val += mal_ratio;
				  ben_val += ben_ratio;
				  
				  if(mal_ratio>ben_ratio)
					  mal_count++;
				  else
					  ben_count++;
				  //double mal_times = 
				  selected_features.put(str, (new Feature(str,ben_ratio,mal_ratio)));
			  }
			  //Collection<Feature> arr = selected_features.values();
			  Iterator<Feature> it = selected_features.values().iterator();
			 double rm = ben_val/mal_val;
		  	in.close();
		 }
		catch (Exception e){//Catch exception if any
			  e.printStackTrace();
		 }
	}
	
	//This is used to select secondary features
	//For the pages without features in the feature set
	//We use the feature set acquired by this function to classify those functions
	private void initSecondaryFeatureSet(){
		secondary_selected_features = new HashMap<String,Feature>();	
		try{
			  int ben_threathold = 8000;
			  
			  FileInputStream fstream = new FileInputStream(feature_dir+"secondary_features.out");
			  // Get the object of DataInputStream
			  DataInputStream in = new DataInputStream(fstream);
			  BufferedReader br = new BufferedReader(new InputStreamReader(in));
			  String line;
			  ResultSet rs = null;
			  
			  //These four variables are used to test
			  int ben_count = 0;
			  int mal_count = 0;
			  double mal_val= 0.0;
			  double ben_val = 0.0;
			  
			  //Read File Line By Line
			  while ((line = br.readLine()) != null)   {
				  int begin = line.indexOf('[');
				  int end = line.lastIndexOf(']');
				  if(begin==-1 || end==-1){
					  System.err.println("Error:"+line);
					  continue;
				  }
				  String str = new String(line.substring(begin, end+1));
				 
				  float mal_times= 0;
				  float ben_times = 0;
				 
				  begin = line.indexOf("A:(");
				  end = line.indexOf(")",begin);
				  mal_times = Float.parseFloat(line.substring(begin+3,end));
				  
				  begin = line.indexOf("B:(");
				  end = line.indexOf(")",begin);
				  ben_times = Float.parseFloat(line.substring(begin+3,end));
				
				  mal_times += 1;
				  ben_times += 1;
				  
				  double mal_ratio = (float)(mal_times)/(float)(mal_files)*1000.0;
				  double ben_ratio = (float)(ben_times)/(float)(ben_files)*1000.0;
				 //confine the number
				   if(ben_ratio>mal_ratio){
					  if(ben_threathold<=0){
						  continue;
					  }
					  ben_threathold--;	  
				  }
				  
				  mal_val += mal_ratio;
				  ben_val += ben_ratio;
				  
				  if(mal_ratio>ben_ratio)
					  mal_count++;
				  else
					  ben_count++;
				  
				  secondary_selected_features.put(str, (new Feature(str,ben_ratio,mal_ratio)));
			  } 
			  in.close();

		 }
		catch (Exception e){//Catch exception if any
			  System.err.println("Error:" + e.getMessage());
			  e.printStackTrace();
		 }
	}
	private void saveFeatures(Vector<String> first_features, Vector<String> second_features){
		System.out.println("First Feature Size:"+first_features.size()+" Second Feature Size:"+second_features.size());
		try{
			File f = new File(feature_dir+"features.out");
			
			if(f.exists()) f.delete();
			
			FileWriter fos=new FileWriter(feature_dir+"features.out"); 
			BufferedWriter bw=new BufferedWriter(fos); 
			Iterator<String> it = first_features.iterator();
			while(it.hasNext()){
				bw.write(it.next()+"\n");
			}
			bw.close();
			fos.close();
			
			fos = new FileWriter(feature_dir+"secondary_features.out");
			bw = new BufferedWriter(fos);
			it = second_features.iterator();
			while(it.hasNext()){
				bw.write(it.next()+"\n");
			}
			bw.close();
			fos.close();
		}
		catch(Exception e){
			System.err.println("Saving Features failed: "+e);
		
		}
	}
	
	private ArrayList<Entry<String, Integer>>[] getBadFeaturesFromValidationSets(NBClassifier nbc,
			String dir, int flag ){
		HashMap<String, Integer> features1_removed = new HashMap<String,Integer>();
		HashMap<String, Integer> features2_removed = new HashMap<String,Integer>();
		 ArrayList<Entry<String, Integer> > l = null;
		if(nbc.isInitialized==false){
			System.err.println("Should initiate NBClassifier first");
			return null;
		}
		//First test benign files and find those classified as malicious
		Vector<String> first = new Vector<String>();
		Vector<String> second = new Vector<String>();
		File folder=new File(dir);
        File[] entries=folder.listFiles();
        int k=0;
        for (File file: entries){
        	//System.out.println("# "+ k++ +": "+file.getName()+" start...");
        	//if(k++ >100)  break;
        	first.clear();
        	second.clear();
        	int rs = nbc.extractNegativeFeatures(file, first, second, flag);
        	
        	if(rs == 0){
        		Iterator<String> iter = first.iterator();
        		while(iter.hasNext()){
        			String feature = iter.next();
        			//System.out.println("First:"+feature);
        			if(features1_removed.containsKey(feature)){
        				int times = features1_removed.get(feature)+1;
        				features1_removed.put(feature, times);
        			}
        			else{
        				features1_removed.put(feature, 1);
        			}
        		}
        		iter = second.iterator();
        		while(iter.hasNext()){
        			String feature = iter.next();
        			//System.out.println("Second:"+iter.next());
        			if(features2_removed.containsKey(feature)){
        				int times = features2_removed.get(feature)+1;
        				features2_removed.put(feature, times);
        			}
        			else{
        				features2_removed.put(feature, 1);
        			}	
        		}
        	}	
        	//System.out.println(file.getName()+" result:"+rs);
        }
        int[] s = new int[2];
        ArrayList<Entry<String, Integer>>[] rs = new ArrayList[2];
        rs[0] = sortStrIntHashMap(features1_removed);
        for(Entry<String,Integer> e : rs[0]) {   
            System.err.println(e.getKey() + "::::" + e.getValue());   
        } 
        System.err.println("Secondary feature set");
        rs[1] = sortStrIntHashMap(features2_removed);
        for(Entry<String,Integer> e : rs[1]) {   
            System.err.println(e.getKey() + "::::" + e.getValue());   
        } 
        return rs;
	}
	// This function works on file new_features.out
	// It will split the file into two feature sets
	// First level feature set's size is about 3000 and Second level is about 15000
	// Remove the features in third_features.out
	// Use two validation sets to modify the two level sets
	public void optimizeFeatureSets(String ben_valid_set_dir, String mal_valid_set_dir){
		try{
			System.out.println("Optimize Feature Sets");
			//Read features belonging to first feature and second feature
			FileInputStream fstream = new FileInputStream(feature_dir+"new_features.out");
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			String line = null;
			int i = 0, j=0;
			Vector<String> first_features = new Vector<String>();
			Vector<String> second_features = new Vector<String>();
			while ((line = br.readLine()) != null)   {
				line = line.trim();
				if(i<3000){				first_features.add(line);	}
				else if(i<15000+3000){	second_features.add(line);	}
				else{					break;						}
				i++;
			}
			if(br!=null) br.close();
			if(in != null) in.close();		
			if(fstream != null) fstream.close();
			
			//Remove the features in 
			fstream = new FileInputStream(feature_dir+"third_features.out");
			in = new DataInputStream(fstream);
			br = new BufferedReader(new InputStreamReader(in));
			i = 0;
			j =0;
			while ((line = br.readLine()) != null)   {
				line = line.trim();
				if(first_features.contains(line)){
					first_features.remove(line);
					i++;
				}
				else if(second_features.contains(line)){
					second_features.remove(line);
					j++;
				}
			}
		
			//Save the features to disk
			saveFeatures(first_features,second_features);
			
			//Start to use benign validation set
			NBClassifier nbc = new NBClassifier(this,null);
			nbc.initForClassifying();	
			ArrayList<Entry<String, Integer>>[] ts_al = getBadFeaturesFromValidationSets(nbc,ben_valid_set_dir, 0 );
			ArrayList<Entry<String, Integer>> l_first = ts_al[0];
			ArrayList<Entry<String, Integer>> l_second = ts_al[1];
			System.out.println("Sizeof ben:"+l_first.size()+" "+l_second.size());
			//Delete from feature sets
			System.out.println("Ben Before deleting first, Size:"+first_features.size());
			for(int k=0; k<l_first.size() && k<800 ; k++){
				Iterator<String> it_f = first_features.iterator();
				if(l_first.get(k).getValue()<10) continue;
				while(it_f.hasNext()){
					String temp = it_f.next();
					if(temp.contains(l_first.get(k).getKey())){
						first_features.remove(temp);
						System.err.println("Remove feature "+temp);
						break;
					}
				}
			}
			System.out.println("Ben After deleting first, Size:"+first_features.size());
			
			System.out.println("Ben Before deleting second, Size:"+second_features.size());
			for(int k=0; k<l_second.size() && k<3000 ; k++){
				if(l_second.get(k).getValue()<10) continue;
				Iterator<String> it_f = second_features.iterator();
				while(it_f.hasNext()){
					String temp = it_f.next();
					if(temp.contains(l_second.get(k).getKey())){
						second_features.remove(temp);
						System.err.println("Remove feature "+temp);
						break;
					}
				}
			}
			System.out.println("Ben After deleting second, Size:"+second_features.size());
			saveFeatures(first_features,second_features);
			
			nbc = new NBClassifier(this,null);
			nbc.initForClassifying();	
			ts_al = getBadFeaturesFromValidationSets(nbc,mal_valid_set_dir, 1 );
			l_first = ts_al[0];
			l_second = ts_al[1];
			System.out.println("Sizeof ben:"+l_first.size()+" "+l_second.size());
			//Delete from feature sets
			System.out.println("Mal Before deleting first, Size:"+first_features.size());
			for(int k=0; k<l_first.size() && k<800 ; k++){
				Iterator<String> it_f = first_features.iterator();
				if(l_first.get(k).getValue()<10) continue;
				while(it_f.hasNext()){
					String temp = it_f.next();
					if(temp.contains(l_first.get(k).getKey())){
						first_features.remove(temp);
						System.err.println("Remove feature "+temp);
						break;
					}
				}
			}
			System.out.println("Mal After deleting first, Size:"+first_features.size());
			
			System.out.println("Mal Before deleting second, Size:"+second_features.size());
			for(int k=0; k<l_second.size() && k<3000 ; k++){
				if(l_second.get(k).getValue()<10) continue;
				Iterator<String> it_f = second_features.iterator();
				while(it_f.hasNext()){
					String temp = it_f.next();
					if(temp.contains(l_second.get(k).getKey())){
						second_features.remove(temp);
						System.err.println("Remove feature "+temp);
						break;
					}
				}
			}
			System.out.println("Mal After deleting second, Size:"+second_features.size());
			//Save the features to disk
			saveFeatures(first_features,second_features);
		}
		catch(IOException e){
			System.err.println(e);
		}
	}
	
	private ArrayList<Entry<String, Integer> > sortStrIntHashMap(HashMap<String, Integer> hm){
		ArrayList<Entry<String,Integer>> l = new ArrayList<Entry<String,Integer>>(hm.entrySet());     
        Collections.sort(l, new Comparator<Map.Entry<String, Integer>>() {     
        public int compare(Map.Entry<String, Integer> o1, Map.Entry<String, Integer> o2) {     
                     return (o2.getValue() - o1.getValue());     }     });   
       
        return l;
	}

	public void outputFeaturesInOrder(int flag){
		int isMalicious=flag;
		HashSet<String> features = new HashSet<String>();
		Statement s;
		System.out.println("Start to output feature sets ");
		String sql_stat = "SELECT name,times FROM features where malicious = " + isMalicious + " order by times DESC limit 1000000";
		try{
	    	FileWriter fos=new FileWriter(feature_dir+"feature_output"); 
			BufferedWriter bw=new BufferedWriter(fos); 
			try {
				s = conn.createStatement();
				s.executeQuery(sql_stat);
			 	ResultSet rs = s.getResultSet ();
			 	while(rs.next()){
			 		if(total_number % 10000==0){
			 			System.err.println("Total Number: "+total_number);
			 		}
			 		String str = rs.getString(1);
					String time = rs.getString(2);
					String sent = new String(str+" || "+time+"\n");
					bw.write(sent);
			 	}
				bw.close();
				fos.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}	
			bw.close();
			fos.close();
		}
    	catch(IOException e){
    		System.err.println("IOException in outputFeaturesToFiles");
    	}
	}

	public HashMap<String,Double> selectFeature(){
		HashSet<String> features = new HashSet<String>();
		long endtime = System.currentTimeMillis();
		Statement s;
		System.out.println("Start to optimize feature sets ");
		getBenFeatures();
		getBenFiles();
		getMalFeatures();
		getMalFiles();
		System.err.println("Benign_features:"+this.ben_features+" Benign_files:"+this.ben_files+" Malicious_features:"+this.mal_features+" Malicious_files:"+this.mal_files);

		is_modified = false;
		
		try{
	    	FileWriter fos=new FileWriter(feature_dir+"new_features.out"); 
			BufferedWriter bw=new BufferedWriter(fos); 
				
			try {
				s = conn.createStatement();
				s.executeQuery ("SELECT name FROM features order by times DESC limit 1000000");
			 	ResultSet rs = s.getResultSet ();
			 	while(rs.next()){
			 		if(total_number % 10000==0){
			 			System.err.println("Total Number: "+total_number);
			 		}
			 		String str = rs.getString(1);
			 		double val = calculateChiTest(str,bw); 		
			 	}
			 	
			} catch (SQLException e) {
				e.printStackTrace();
			}	
			bw.close();
			fos.close();
			
		}
    	catch(IOException e){
    		System.err.println("IOException in outputFeaturesToFiles");
    	}
		//return features;
		return feature_priority;
	}
	
	private double calculateChiTest(String str, BufferedWriter bw){
		double m_feature = 1;					//A
		double m_without_feature = 1;			//C
		double b_feature = 1;					//B
		double b_without_feature = 1;			//D
		boolean flag = false;
		double benign_scripts = 0.0;
		double malicious_scripts = 0.0;
		try {	
			ps_mf.setString(1, str);
			ps_mf.setInt(2,1);
			ResultSet rs = ps_mf.executeQuery();
			if(rs.next()){
				m_feature = rs.getInt(1);
			}
			else{
				m_feature = 0;
			//	flag = true;
			}
			malicious_scripts = getMalFiles();
			m_without_feature = malicious_scripts - m_feature;
			
			ps_mf.setInt(2,0);
			rs = ps_mf.executeQuery();
			if(rs.next()){
				b_feature = rs.getInt(1);
			}
			else{
				b_feature = 0;
			//	flag = true;
			}
			benign_scripts = getBenFiles();
			b_without_feature =benign_scripts - b_feature;
			
		} catch (SQLException e) {
			System.err.println("Error in calculating chi test:"+e);
		}
		
		double temp1 = (m_feature*b_without_feature-m_without_feature*b_feature);
		temp1 *= temp1;
		double temp2 = (m_feature+m_without_feature)*(b_feature+b_without_feature)*(m_feature+b_feature)*(m_without_feature+b_without_feature);
		temp1 = temp1/temp2;
		
		if(temp1>10.83) flag = true;
		if(b_feature+m_feature<100.0) flag = false;
		if(flag==false){
			double x1 = b_feature/benign_scripts;
			double x2 = m_feature/malicious_scripts;
			double little = x1>x2?x2:x1;
			double large = x1>x2?x1:x2;
			
			if((large-little)/little>100) flag = true;
		}
	
		if(flag == false)
				return temp1;
		
		try{			
			String s = new String(str+"  "+"A:("+m_feature+")  B:("+b_feature+")\n");
			if(bw!=null){
				bw.write(s);
			}
		}
		catch(Exception e){
    		System.err.println("IOException in outputFeaturesToFiles");
    	}
		total_number++;
		
		return temp1;
	//	double chi_val = 	
	}

	public void calculateDBInfo(){
		getMalFeatures();
		getBenFeatures();
		getMalFiles();
		getBenFiles();
		is_modified = false;
	}

	
}
