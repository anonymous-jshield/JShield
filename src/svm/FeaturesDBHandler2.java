package svm;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
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
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

public class FeaturesDBHandler2 {
	private String url;
	private String user;
	private String pass;
	private int mal_features = 0;
	private int ben_features = 0;
	private int mal_files = 0;
	private int ben_files = 0;
	private boolean init_flag = false;
	private int total_number = 0;
	private String table_name = "special_features";
	private String handled_bfile_name = "zero_feature_benign_files";
	private String handled_mfile_name = "zero_feature_malicious_files";
	
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
	//PreparedStatement pstmt_insert_files;
	PreparedStatement pstmt_insert;
	PreparedStatement pstmt_search;
	PreparedStatement pstmt_update;
	//PreparedStatement ps_mf;
	PreparedStatement pstmt_search_times;
	boolean is_modified = true;
	HashMap<String,Double> feature_priority = new HashMap<String,Double>(); 
	HashMap<String,Feature> selected_features;

	HashSet<String> handled_m_files = null;
	HashSet<String> handled_b_files = null;
	
	public void setModifiedFlag(boolean flag){
		is_modified = flag;
	}
	
	//get counts
	//These functions will update mal_features, ben_features, mal_files and ben_files
	//These functions will also return the results
	//public int getFeatures(){}
	public int getMalFeatures(){
		if(!is_modified){
			return mal_features;
		}
		else{
			try{
				Statement s = conn.createStatement();
			 	s.executeQuery ("SELECT sum(times) FROM special_features where malicious=1");
			 	ResultSet rs = s.getResultSet ();

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
			 	s.executeQuery ("SELECT sum(times) FROM special_features where malicious=0");
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
		mal_files = handled_m_files.size();
		return handled_m_files.size();
	}
	public int getBenFiles(){
		if(handled_b_files==null){
			this.getHandledBFiles();
		}
		ben_files = handled_b_files.size();
		return handled_b_files.size();
	}
	private HashSet<String> getHandledMFiles(){
		handled_m_files = new HashSet<String>();
		FileInputStream fstream = null;
		DataInputStream in = null;
		BufferedReader br = null;
		try {
			fstream = new FileInputStream("//Users//ap//Documents//JS_SOURCE_CODE//"+handled_mfile_name);
			in = new DataInputStream(fstream);
			br = new BufferedReader(new InputStreamReader(in));
			String line;
			//Read File Line By Line
			while ((line = br.readLine()) != null)   {
				  handled_m_files.add(line.trim());
			}
			br.close();
			in.close();
			fstream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.err.println(e);
		}

		return handled_m_files;
	}
	private HashSet<String> getHandledBFiles(){
		handled_b_files = new HashSet<String>();
		System.err.println("in function getHandledBFiles");
		FileInputStream fstream = null;
		DataInputStream in = null;
		BufferedReader br = null;
		try {
			fstream = new FileInputStream("//Users//ap//Documents//JS_SOURCE_CODE//"+handled_bfile_name);
			in = new DataInputStream(fstream);
			br = new BufferedReader(new InputStreamReader(in));
			String line;
			//Read File Line By Line
			while ((line = br.readLine()) != null)   {
				  handled_b_files.add(line.trim());
			}
			br.close();
			in.close();
			fstream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.err.println(e);
		}
		
		return handled_b_files;
	}
	public HashSet<String> getHandledFiles(){
		if(handled_m_files==null)
			getHandledMFiles();
		if(handled_b_files==null)
			getHandledBFiles();
		getMalFiles();
		getBenFiles();
		
		
		System.err.println("malicious files:"+mal_files);
		System.err.println("benign files:"+ben_files);
		
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
	
	public FeaturesDBHandler2(){
		url = "localhost";
		user = "xpan";
		pass = "123456";
		try{
			if(!initConnection()){
				System.err.println("init error1 ");
				System.exit(1);
			}
		}
		catch(Exception e){
			System.err.println("init error2 "+e);
			System.exit(1);
		}
	}
	
	private boolean initConnection() throws SQLException{
		boolean rs = false;
		if(conn != null){
			init_flag = true;
			return true;
		}
		try{
			Class.forName("com.mysql.jdbc.Driver");
			conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/JShield_DB",user,pass);		
			if(conn != null){
				pstmt_search = conn.prepareStatement("select id,times from "+table_name +" where name=? and malicious=?",ResultSet.TYPE_SCROLL_SENSITIVE,
			            ResultSet.CONCUR_UPDATABLE);
				pstmt_search_times = conn.prepareStatement("select times from "+table_name +" where name=? and malicious=?");
				pstmt_insert = conn.prepareStatement("insert into "+table_name +" (name,times,malicious) values (?,1,?)") ;
				pstmt_update = conn.prepareStatement("update "+table_name +" set times = ? where feature_id = ?") ;
				//ps_mf = conn.prepareStatement("select times, priority from features where name=? and malicious=?");
				init_flag = true;
				return true;
			}
			return false;
		}
		catch(Exception e){
			System.out.println("Error in init connection");
			return false;	
		}
		
	}
	private void updateString(String str, int isMalicious, ResultSet rs) throws SQLException{
		//System.err.println(" B Inserted\n");
		rs = pstmt_search.executeQuery();
		//System.err.println("Inserted\n");
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

	public synchronized void insertSet(HashSet<String> set, int isMalicious, String fileName) throws IOException{
		String str = null;
		is_modified = true;
		try
		{
			/*
			 * pstmt_search = conn.prepareStatement("select feature_id,times from "+table_name +" where name=? and malicious=?",ResultSet.TYPE_SCROLL_SENSITIVE,
			            ResultSet.CONCUR_UPDATABLE);
				pstmt_search_times = conn.prepareStatement("select times from "+table_name +" where name=? and malicious=?");
				pstmt_insert = conn.prepareStatement("insert into "+table_name +" (name,times,malicious) values (?,1,?)") ;
				pstmt_update = conn.prepareStatement("update "+table_name +" set times = ? where feature_id = ?") ;
			 */
			
			System.err.println("In insert "+set.size());
			Iterator<String> it = set.iterator();
			ResultSet rs = null;
			int i=0;
			FileWriter fos=null; 
			HashSet<String> handled_files = null;
			if(isMalicious==1){
				fos = new FileWriter("//Users//ap//Documents//JS_SOURCE_CODE//"+handled_mfile_name,true);
				handled_files = handled_m_files;
			}
			else{
				fos = new FileWriter("//Users//ap//Documents//JS_SOURCE_CODE//"+handled_bfile_name,true);
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
					System.err.println("ERROROROR file:"+fileName+" has been handled");
					return;
				}
				else if(is_first_item){
					handled_files.add(fileName);
					//System.err.println("write to handled files:"+fileName);
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
			System.out.println(str+str.length()+"SQLException in insertSet: "+sqle);
		}
		catch(IOException ioe){
			System.err.println("Failed writting filename to files: "+ioe+" "+str);
		}
	}

	public HashMap<String,Feature> getSelectedFeaturesMap(){
		return selected_features;
	}
	
	public void initFeatureSet(){
		selected_features = new HashMap<String,Feature>();
		
		try{
		  FileInputStream fstream = new FileInputStream("//Users//ap//Documents//JS_SOURCE_CODE//feature_sets//special_features.out");
			
		  DataInputStream in = new DataInputStream(fstream);
		  BufferedReader br = new BufferedReader(new InputStreamReader(in));
		  String line;
		  ResultSet rs = null;
		  int ben_count = 0;
		  int mal_count = 0;
		  int i=0;
		  double mal_val= 0.0;
		  double ben_val = 0.0;
		  //Read File Line By Line
		  while ((line = br.readLine()) != null)   {
			  i++;
		
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
			  
			  mal_val += mal_ratio;
			  ben_val += ben_ratio;
			  
			  if(mal_ratio>ben_ratio)
				  mal_count++;
			  else
				  ben_count++;
			  
			  selected_features.put(str, (new Feature(str,ben_ratio,mal_ratio)));
		  }
			  
		  //Close the input stream
		  System.err.println("benign features:"+ben_count+" malicious features:"+mal_count);
		  System.err.println("Malval:"+mal_val+" Benval:"+ben_val);
		  in.close();
	 }
	 catch (Exception e){//Catch exception if any
		  System.err.println("Error:" + e.getMessage());
		  e.printStackTrace();
	 }
	}
	
	public HashMap<String,Double> selectFeature(double t){
		HashSet<String> features = new HashSet<String>();
		long endtime = System.currentTimeMillis();
	 		//System.out.println("Run time: "+(endtime-starttime)+" "+file.getName()+" has feature "+set.size());
		Statement s;
		System.out.print("Calculating...");
		getBenFeatures();
		System.out.print("...");
		getBenFiles();
		System.out.print("...");
		getMalFeatures();
		System.out.print("...");
		getMalFiles();
		System.out.println("...");
		System.out.println(this.ben_features);
		System.out.println(this.ben_files);
		System.out.println(this.mal_features);
		System.out.println(this.mal_files);
		is_modified = false;
		//return null;
		try{
	    	FileWriter fos=new FileWriter("//Users//ap//Documents//JS_SOURCE_CODE//"+"special_new_features.out"); 
			BufferedWriter bw=new BufferedWriter(fos); 
				
			double threthold = t;
			try {
				s = conn.createStatement();
				s.executeQuery ("SELECT name FROM "+table_name +" order by times DESC limit 1000000");
			 	ResultSet rs = s.getResultSet ();
			 	while(rs.next()){
			 		if(total_number % 10000==0){
			 			System.out.println("Total Number: "+total_number);
			 		}
			 		String str = rs.getString(1);
			 		double val = calculateChiTest(str,bw);
			 	
			 		if(val<=threthold) continue;
			 		//feature_priority.put(str, new Double(val));
			 	}
			 	
			} catch (SQLException e) {
				// TODO Auto-generated catch block
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
	
	public double calculateChiTest(String str, BufferedWriter bw){
		double m_feature = 1;					//A
		double m_without_feature = 1;			//C
		double b_feature = 1;					//B
		double b_without_feature = 1;			//D
		boolean flag = false;
		double benign_scripts = 0.0;
		double malicious_scripts = 0.0;
		try {
			
			pstmt_search_times.setString(1, str);
			pstmt_search_times.setInt(2,1);
			ResultSet rs = pstmt_search_times.executeQuery();
			if(rs.next()){
				m_feature = rs.getInt(1);
			}
			else{
				m_feature = 0;
			//	flag = true;
			}
			malicious_scripts = getMalFiles();
			m_without_feature = malicious_scripts - m_feature;
			
			pstmt_search_times.setInt(2,0);
			rs = pstmt_search_times.executeQuery();
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
			// TODO Auto-generated catch block
			//e.printStackTrace();
			System.err.println("Error in calculating chi test:"+e);
		}
		
		double temp1 = (m_feature*b_without_feature-m_without_feature*b_feature);
		temp1 *= temp1;
		double temp2 = (m_feature+m_without_feature)*(b_feature+b_without_feature)*(m_feature+b_feature)*(m_without_feature+b_without_feature);
		temp1 = temp1/temp2;
		
		if(temp1>10.83) flag = true;
		//if(b_feature+m_feature<100.0) flag = false;
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
			System.out.println(s);
			//System.out.print("Chi Test: ["+str+" "+temp1+"]  ");
			//System.out.println("A:"+m_feature+"  C"+m_without_feature+"  B"+b_feature+"  D"+b_without_feature);
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
