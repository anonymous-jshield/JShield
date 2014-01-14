package nb_ast;

public class Feature {
	public String str;
	public double ben_ratio;
	public double mal_ratio;
	public Feature(String s,double ben, double mal){
		ben_ratio = ben;
		mal_ratio = mal;
		str = s;
	}
	public void updateFeature(double rb,double rm){
		ben_ratio *= rb;
	//	System.out.println("ori:"+mal_ratio);
		mal_ratio *= rm;
	//	System.out.println("aft:"+mal_ratio);
	}
	public String toString(){
		String s = String.format("%s: ben_ratio:[%.3f] mal_ratio:[%.3f]", str,ben_ratio,mal_ratio);
		return s;
	}
}
