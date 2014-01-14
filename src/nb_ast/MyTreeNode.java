package nb_ast;
import javax.swing.tree.DefaultMutableTreeNode;


public class MyTreeNode extends DefaultMutableTreeNode{
	String name;
	
	public MyTreeNode() {
		super();
		// TODO Auto-generated constructor stub
	}

	public MyTreeNode(Object userObject, boolean allowsChildren) {
		super(userObject, allowsChildren);
		// TODO Auto-generated constructor stub
	}

	public MyTreeNode(String name,Object userObject) {
		super(userObject);
		// TODO Auto-generated constructor stub
		this.name = name;
	}

	@Override
	public String toString() {
		return "[" + name + "]";
	}
	
	
}
