package nb_ast;
import java.util.HashSet;
import java.util.Vector;
import java.util.Stack;
import javax.swing.tree.DefaultMutableTreeNode;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

//import org.eclipse.swt.widgets.Tree;
import org.eclipse.wst.jsdt.core.dom.*;
public class JSVisitor extends ASTVisitor{
	private Stack stack;
	private DefaultMutableTreeNode root;
	//Vector<Vector<String>> features;
	Vector<String> cur_feature;

	static String StringLiteral = new String("StringLiteral");
	static String LoopString = new String("LoopStatement");
	HashSet<String> contexts = new HashSet<String>(); 
	HashSet<String> LoopStatement = new HashSet<String>();
	HashSet<String> finalFeatureSet = new HashSet<String>();
	Vector<String> vec = new Vector<String>();
	Pattern specialStringPattern1 = Pattern.compile("([a-zA-Z0-9]+[-+,!|]){100,}");
	Pattern specialStringPattern2 = Pattern.compile("([-0-9]+[+,!|]){100,}");
	JSVisitor(String str) {
		super(true);
	//	this.features = new Vector<Vector<String>>();
		this.cur_feature = new Vector<String>();
		this.stack = new Stack();
		this.root = new MyTreeNode(str,null);
		//frame = new JFrame();
		this.stack.push((Object)root);

		//Loop
		LoopStatement.add(new String("ForInStatement"));
		LoopStatement.add(new String("WhileStatement"));
		LoopStatement.add(new String("ForStatement"));

		//Set the contexts
		contexts.add(new String("ForInStatement"));
		contexts.add(new String("WhileStatement"));
		contexts.add(new String("ForStatement"));
		contexts.add(new String("ArrayAccess"));
		contexts.add(new String("FunctionInvocation"));
		contexts.add(new String("StringLiteral"));
		contexts.add(new String("FunctionDeclaration"));
		contexts.add(new String("SwitchStatement"));
		contexts.add(new String("TryStatement"));
		contexts.add(new String("CatchClause"));
		contexts.add(new String("IfStatement"));						
	}
	public HashSet<String> getFeatureSet(){
		return finalFeatureSet;
	}
	
	public void postVisit(ASTNode node) {
		//System.out.println("In postVisitor");
		//System.out.println("1");
		DefaultMutableTreeNode d = (DefaultMutableTreeNode)stack.peek();

		if(d.isLeaf()){
			cur_feature.add(node.toString());
			//Vector<String> vec = new Vector<String>();
			vec.clear();
			//Don' add StringLiteral since it contains little information
			//Change all the items of Loop into an uniformed String
			for(int i = cur_feature.size()-2; i>=0; i--){
				//cur_feature.elementAt(i) = cur_feature.elementAt(i).trim();
				if(contexts.contains(cur_feature.elementAt(i))){
					if(cur_feature.elementAt(i).equals(StringLiteral) ){
						continue;
					}
					else if(LoopStatement.contains(cur_feature.elementAt(i))){
						//features.lastElement().add(LoopString);
						vec.add(LoopString);
					}
					else{
						//features.lastElement().add(cur_feature.elementAt(i));
						//System.out.println(cur_feature.elementAt(i));
						vec.add(cur_feature.elementAt(i));
						
					}
					break;
				}
			}
			
			//Add the last element in the set
			if(isSpecialString(cur_feature.lastElement())){
//				System.out.println("Found a Special String: "+cur_feature.lastElement());
				vec.add("SpecialString_Obfuscated_codes");
			}
			else{
				String str = cur_feature.lastElement().trim();
				if(str.length()>200)
					str = str.substring(0,200);
				vec.add(str);
			}
			
			cur_feature.remove(cur_feature.size()-1);
			String tempStr = vec.toString();
			if(tempStr.contains("\n")){
				tempStr=tempStr.replaceAll("\\n", "");
			}
			
			//int tempNum = features.lastElement().size();
			finalFeatureSet.add(tempStr);
			//System.out.println(tempStr);		
		}
		cur_feature.remove(cur_feature.size()-1);
		
		this.stack.pop();
		//System.out.println("size: "+this.stack.size());
		//System.out.println("Out postVisitor");
		//System.out.println("2");
	}
	
	public void preVisit(ASTNode node){
		//System.out.println("In preVisitor");
		MyTreeNode cur = new MyTreeNode(node.getClass().getSimpleName(),node);
		((DefaultMutableTreeNode)stack.peek()).add(cur);

		cur_feature.add(new String(cur.name));
		
		stack.push(cur);	
		//System.out.println("out preVisitor");
	}
	
	private boolean isSpecialString(String str){
		//return false if the string is not long enough
		//System.out.println("isSpecialString");
		try{
			if(str.length()<200){
				return false;
			}
			//System.out.println("isSpecialString1");
			str = str.substring(0, 1000>str.length()?str.length():1000);
			Matcher match = specialStringPattern1.matcher(str);
			//System.out.println("isSpecialString2 "+str.length()+str );
	
			if(match.find()){
				//System.out.println("isSpecialString2.0");
				return true;
			}
			else{
				//System.out.println("isSpecialString2");
				match = specialStringPattern2.matcher(str);
				if(match.find())
					return true;
			}
		}
		catch(Exception e){
			System.err.println("Error::"+e);
			System.err.println(str);
		}
		return false;
	
	}
	
	
}
