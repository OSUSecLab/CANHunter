package edu.osu.seclab.backwardslicing;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Stack;

import edu.osu.seclab.base.GlobalStatistics;
import edu.osu.seclab.base.ParameterTransferStmt;
import edu.osu.seclab.base.StmtPoint;
import edu.osu.seclab.graph.ValuePoint;
import org.json.JSONObject;

import edu.osu.seclab.forwardexec.StmtPath;
import edu.osu.seclab.graph.DGraph;
import edu.osu.seclab.graph.HeapObject;
import edu.osu.seclab.main.Config;
import edu.osu.seclab.utility.BlockGenerator;
import edu.osu.seclab.utility.Logger;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JNewExpr;
import soot.jimple.internal.JimpleLocal;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.CompleteBlockGraph;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BackwardContext extends AbstractStmtSwitch implements StmtPath, ICollecter {

	ValuePoint startPoint;
	DGraph dg;

	ArrayList<SootMethod> methodes;
	ArrayList<Block> blockes;
	Unit currentInstruction;

	HashSet<Value> intrestedVariable;
	ArrayList<Stmt> execTrace;

	HashSet<HeapObject> dependentHeapObjects;
	Stack<CallStackItem> callStack;

	boolean finished = false;

	@SuppressWarnings("unchecked")
	public BackwardContext(BackwardContext oldBc) {
		startPoint = oldBc.getStartPoint();
		dg = oldBc.getDg();
		methodes = (ArrayList<SootMethod>) oldBc.getMethodes().clone();
		blockes = (ArrayList<Block>) oldBc.getBlockes().clone();
		currentInstruction = oldBc.getCurrentInstruction();
		intrestedVariable = (HashSet<Value>) oldBc.getIntrestedVariable().clone();
		execTrace = (ArrayList<Stmt>) oldBc.getExecTrace().clone();
		dependentHeapObjects = (HashSet<HeapObject>) oldBc.getDependentHeapObjects().clone();
		callStack = (Stack<CallStackItem>) oldBc.getCallStack().clone();
	}

	public BackwardContext(ValuePoint startPoint, DGraph dg) {
		this.startPoint = startPoint;
		this.dg = dg;

		methodes = new ArrayList<SootMethod>();
		methodes.add(0, startPoint.getMethod_location());

		blockes = new ArrayList<Block>();
		blockes.add(0, startPoint.getBlock_location());

		intrestedVariable = new HashSet<Value>();
		execTrace = new ArrayList<Stmt>();
		dependentHeapObjects = new HashSet<HeapObject>();
		callStack = new Stack<CallStackItem>();

		currentInstruction = startPoint.getInstruction_location();

		execTrace.add(0, (Stmt) currentInstruction);

		// init
		Value tmp;
		for (int index : startPoint.getTargetRgsIndexes()) {
			if (index == -1) {// set heap object
				if (currentInstruction instanceof JAssignStmt) {
					tmp = ((JAssignStmt) currentInstruction).getRightOp();
				}
				else if (currentInstruction instanceof JInvokeStmt) {
					if (((JInvokeStmt) currentInstruction).getInvokeExpr() instanceof VirtualInvokeExpr) {
						InvokeExpr invokeExpr = ((JInvokeStmt) currentInstruction).getInvokeExpr();
						tmp = ((VirtualInvokeExpr) invokeExpr).getBase();
					}
					else
						tmp = ((Stmt) currentInstruction).getInvokeExpr().getArg(index);
				}
				else {
					tmp = ((Stmt) currentInstruction).getInvokeExpr().getArg(index);
				}
			} else {
				tmp = ((Stmt) currentInstruction).getInvokeExpr().getArg(index);
			}

			if (tmp instanceof JimpleLocal) {
				Logger.printI("Target Variable is" + tmp.getClass() + " " + currentInstruction);
				this.addIntrestedVariable(tmp);
			} else if (tmp instanceof StringConstant || tmp instanceof IntConstant) {
			} else {
				Logger.printW("Target Variable is" + tmp.getClass() + " " + currentInstruction);
			}
		}
	}

	public boolean backWardHasFinished() {
		// return intrestedVariable.size() == 0;
		return finished || intrestedVariable.size() == 0 || this.getMethodes().size() > Config.MAXMETHODCHAINLEN;
	}

	public List<BackwardContext> oneStepBackWard() {

		Unit nextInstrct = this.getCurrentBlock().getPredOf(currentInstruction);
		// Logger.print(this.hashCode() + "oneStepBackWard");
		if (nextInstrct != null) {
			return oneStepBackWard(nextInstrct);
		} else {
			// current function ends, jump to the caller

			List<BackwardContext> newBc = new ArrayList<BackwardContext>();
			BackwardContext tmp;
			// Logger.print(this.hashCode() +
			// this.getCurrentMethod().toString());
			// Logger.print(this.hashCode() +
			// this.getCurrentMethod().retrieveActiveBody().toString());
			// Logger.print(this.hashCode() +
			// this.getCurrentBlock().toString());
			CompleteBlockGraph cbg = BlockGenerator.getInstance().generate(this.getCurrentMethod().retrieveActiveBody());

			// add condition to eliminate circle function invocation here
			if (cbg.getHeads().contains(this.getCurrentBlock())) {
				// to next function
				GlobalStatistics.getInstance().countBackWard2Caller();
				if (this.getCallStack().isEmpty()) {
					// Logger.print("111111");
					boolean allisParameterRef = true;
					String ostr = "";
					for (Value var : this.getIntrestedVariable()) {
						ostr += var + ",";
						if (!(var instanceof ParameterRef)) {
							allisParameterRef = false;
						}
					}
					if (!allisParameterRef) {
						Logger.printW(String.format("[%s] [Not all the intresteds are ParameterRef]: %s", this.hashCode(), ostr));
						finished = true;
						return newBc;
					}

					return oneStepBackWard2Caller();
				} else {// back call
					// Logger.print("22222");
					getBackFromACall();
					return newBc;
				}
			} else {
				// to next block
				// Logger.print("33333");
				List<Block> bs = new ArrayList<Block>();
				bs.addAll(cbg.getPredsOf(this.getCurrentBlock()));
				BlockGenerator.removeCircleBlocks(bs, this.getCurrentBlock(), cbg);

				if (bs.size() == 0) {
					Logger.printW(String.format("[%s] [No PredsOf]: %s", this.hashCode(), this.getCurrentInstruction()));
					finished = true;
					return newBc;
				}

				this.setCurrentBlock(bs.get(0));

				for (Block tb : bs) {
					if (tb == this.getCurrentBlock())
						continue;

					tmp = this.clone();
					tmp.setCurrentBlock(tb);
					newBc.addAll(tmp.oneStepBackWard(tb.getTail()));
					newBc.add(tmp);
				}

				newBc.addAll(this.oneStepBackWard(this.getCurrentBlock().getTail()));
				return newBc;
			}
		}
	}

	private String extractVar(String s) {
		Pattern pattern = Pattern.compile("\\$r\\d+");
		Matcher matcher = pattern.matcher(s);
		if(matcher.find())
			return matcher.group(0);
		else
			return s;
	}

	private boolean partOfArray(HashSet<Value> v1, Value v2) {
		for (Value v: v1) {
			if(v.toString().contains(extractVar(v2.toString())))
				return true;
		}
		return false;
	}

	public List<BackwardContext> oneStepBackWard(Unit nextInstrct) {
		List<BackwardContext> newBc = new ArrayList<BackwardContext>();
		currentInstruction = nextInstrct;

		boolean containsIntrestedThings = false;
		for (ValueBox box : currentInstruction.getDefBoxes()) {
			if (intrestedVariable.contains(box.getValue()) || partOfArray(intrestedVariable, box.getValue())) {
				containsIntrestedThings = true;
				break;
			}
//			else if (box.getValue() instanceof ArrayRef && intrestedVariable.contains(((ArrayRef) box.getValue()).getBase())) {
//				containsIntrestedThings = true;
//				break;
//			}
		}

		String ostr = this.getIntrestedVariableString();
		Logger.printI(String.format("[%s] [Next Ins]: %s (%s)", this.hashCode(), currentInstruction, containsIntrestedThings ? "Y" : "N"));

		if (!containsIntrestedThings) {
			return newBc;
		}

		Stmt stmt = (Stmt) currentInstruction;
		this.getExecTrace().add(0, stmt);

		this.clear();
		stmt.apply(this);
		newBc.addAll(this.retrieve());
		this.clear();

		String nstr = this.getIntrestedVariableString();
		Logger.printI(String.format("                 %s -> %s ", ostr, nstr));

		return newBc;
	}

	private boolean checkDuplicateFuncCall(SootMethod current) {
		for(SootMethod method: this.getMethodes()) {
			if(current.getSignature().equals(method.getSignature()) ) // duplicate method in call stack
				return true;
		}
		return false;
	}

	public List<BackwardContext> oneStepBackWard2Caller() {
		List<BackwardContext> newBc = new ArrayList<BackwardContext>();
		List<StmtPoint> sps = new ArrayList<>();
		try {
			sps = StmtPoint.findCaller(this.getCurrentMethod().toString());
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (sps.size() <= 0) {
			Logger.printW(String.format("[%s] [No Caller]: %s ", this.hashCode(), this.getCurrentMethod().toString()));
			finished = true;
			return newBc;
		}

		int len = sps.size();
		for (int i = 1; i < len; i++) {
			// add condition to eliminate circle function invocation here
			if(!checkDuplicateFuncCall(this.getCurrentMethod())) {
				newBc.add(0, this.clone());
			}
		}
		newBc.add(0, this);

		BackwardContext tmpBC;
		StmtPoint tmpSP;
		for (int i = 0; i < newBc.size(); i++) {
			tmpBC = newBc.get(i);
			tmpSP = sps.get(i);

			tmpBC.oneStepBackWard2Caller(tmpSP);
		}
		newBc.remove(0);

		return newBc;
	}

	public void oneStepBackWard2Caller(StmtPoint tmpSP) {

		this.setCurrentMethod(tmpSP.getMethod_location());
		this.setCurrentBlock(tmpSP.getBlock_location());
		this.setCurrentInstruction(tmpSP.getInstruction_location());

		String ostr = this.getIntrestedVariableString();
		Logger.printI(String.format("[%s] [Next Ins]: %s (caller:%s)", this.hashCode(), this.getCurrentInstruction(), this.getCurrentMethod()));

		HashMap<Integer, Value> regs = new HashMap<Integer, Value>();
		for (Value var : this.getIntrestedVariable()) {
			regs.put(((ParameterRef) var).getIndex(), var);
		}
		this.getIntrestedVariable().clear();

		InvokeExpr inve = ((Stmt) tmpSP.getInstruction_location()).getInvokeExpr();
		ParameterTransferStmt tmp;
		for (int j : regs.keySet()) {
			if (inve.getArg(j) instanceof Constant) {
				// do not have to taint
			} else {
				this.addIntrestedVariable(inve.getArg(j));
			}
			tmp = new ParameterTransferStmt(regs.get(j), inve.getArg(j));
			this.getExecTrace().add(0, tmp);
		}

		String nstr = this.getIntrestedVariableString();
		Logger.printI(String.format("                 %s -> %s ", ostr, nstr));
	}

	public void getBackFromACall() {
		CallStackItem citem = this.getCallStack().pop();

		Stmt retStmt = (Stmt) citem.getCurrentInstruction();

		Value opsite;
		for (Value param : this.getCurrentMethod().getActiveBody().getParameterRefs()) {
			if (this.getIntrestedVariable().contains(param)) {

				opsite = retStmt.getInvokeExpr().getArg(((ParameterRef) param).getIndex());

				this.removeIntrestedVariable(param);
				if (opsite instanceof Local) {
					this.addIntrestedVariable(opsite);
				}
				this.getExecTrace().add(0, new ParameterTransferStmt(param, opsite));
			}
		}

		this.setCurrentMethod(citem.getSmethd());
		// Logger.print(this.hashCode() + "back to " + citem.getSmethd());
		this.setCurrentBlock(citem.getBlcok());
		this.setCurrentInstruction(citem.getCurrentInstruction());

	}

	public ValuePoint getStartPoint() {
		return startPoint;
	}

	public void setStartPoint(ValuePoint startPoint) {
		this.startPoint = startPoint;
	}

	public DGraph getDg() {
		return dg;
	}

	public void setDg(DGraph dg) {
		this.dg = dg;
	}

	public SootMethod getCurrentMethod() {
		return getMethodes().get(0);
	}

	public void setCurrentMethod(SootMethod currentMethod) {
		this.getMethodes().add(0, currentMethod);
	}

	public Block getCurrentBlock() {
		return getBlockes().get(0);
	}

	public void setCurrentBlock(Block currentBlock) {
		getBlockes().add(0, currentBlock);
	}

	public ArrayList<SootMethod> getMethodes() {
		return methodes;
	}

	public ArrayList<Block> getBlockes() {
		return blockes;
	}

	public Unit getCurrentInstruction() {
		return currentInstruction;
	}

	public void setCurrentInstruction(Unit currentInstruction) {
		this.currentInstruction = currentInstruction;
	}

	public String getIntrestedVariableString() {
		String ostr = "";
		for (Value var : this.getIntrestedVariable()) {
			ostr += var + ",";
		}
		return ostr;
	}

	public HashSet<Value> getIntrestedVariable() {
		return intrestedVariable;
	}

	public void addIntrestedVariable(Value v) {
		intrestedVariable.add(v);
	}

	public void removeIntrestedVariable(Value v) {
		intrestedVariable.remove(v);
	}

	public void setIntrestedVariable(HashSet<Value> intrestedVariable) {
		this.intrestedVariable = intrestedVariable;
	}

	public ArrayList<Stmt> getExecTrace() {
		return execTrace;
	}

	public void setExecTrace(ArrayList<Stmt> execTrace) {
		this.execTrace = execTrace;
	}

	public void printExceTrace() {
		Logger.print("[Start]:" + this.getStartPoint().getInstruction_location());
		for (Stmt var : this.getExecTrace()) {
			Logger.print("        " + var);

		}
	}

	public void setDependentHeapObjects(HashSet<HeapObject> dependentHeapObjects) {
		this.dependentHeapObjects = dependentHeapObjects;

	}

	public HashSet<HeapObject> getDependentHeapObjects() {
		return dependentHeapObjects;
	}

	public Stack<CallStackItem> getCallStack() {
		return callStack;
	}

	public BackwardContext clone() {
		BackwardContext tmp = new BackwardContext(this);
		return tmp;
	}

	////////////////////////////////////////////////////////
	//////////////////////// StmtSwitch/////////////////////

	@Override
	public void caseAssignStmt(AssignStmt stmt) {
		// TODO Auto-generated method stub
		// Logger.printW("[caseAssignStmt]");
		this.removeIntrestedVariable(stmt.getLeftOp());
		Value value = stmt.getRightOp();
		if (value instanceof InvokeExpr) {// 11.6_VirtualInvokeExpr->InvokeExpr
			// Logger.printW("[VirtualInvokeExpr]");
			InvokeExpr tmp = (InvokeExpr) value;
			String mthSig = tmp.getMethod().toString();
			// Logger.printW(String.format("[%s]",mthSig));
			if (mthSig.equals("<java.lang.StringBuilder: java.lang.String toString()>")) {
				// tmp.getBase()
				this.addIntrestedVariable(((VirtualInvokeExpr) tmp).getBase());
			} else if (mthSig.equals("<java.lang.String: java.lang.String trim()>")) {
				// tmp.getBase()
				this.addIntrestedVariable(((VirtualInvokeExpr) tmp).getBase());
			} else if (mthSig.equals("<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>")) {
				this.addIntrestedVariable(((VirtualInvokeExpr) tmp).getBase());
				if (tmp.getArg(0) instanceof Local) {
					this.addIntrestedVariable(tmp.getArg(0));
				}
			} else if (mthSig.equals("<android.content.Context: java.lang.String getString(int)>")) {
				if (tmp.getArg(0) instanceof Local) {
					this.addIntrestedVariable(tmp.getArg(0));
				}
			} else if (mthSig.equals("<android.content.res.Resources: java.lang.String getString(int)>")) {
				if (tmp.getArg(0) instanceof Local) {
					this.addIntrestedVariable(tmp.getArg(0));
				}
			} else if (mthSig.equals("<java.lang.String: java.lang.String format(java.lang.String,java.lang.Object[])>")) {
				for (Value arg : tmp.getArgs()) {
					if (arg instanceof Local) {
						this.addIntrestedVariable(arg);
					}
				}
			} else if (mthSig.equals("<android.content.res.Resources: int getIdentifier(java.lang.String,java.lang.String,java.lang.String)>")) {
				for (Value arg : tmp.getArgs()) {
					if (arg instanceof Local) {
						this.addIntrestedVariable(arg);
					}
				}
			} else if (mthSig.equals("<java.lang.String:java.lang.String format(java.lang.String, java.lang.Object[])>")) {
				for (Value arg : tmp.getArgs()) {
					if (arg instanceof Local) {
						this.addIntrestedVariable(arg);
					}
				}
			} else if (mthSig.equals("<java.lang.String: byte[] getBytes()>")) {
				if(((VirtualInvokeExpr) tmp).getBase() instanceof Local)
					this.addIntrestedVariable(((VirtualInvokeExpr) tmp).getBase());
			}
			else if (mthSig.equals("<java.lang.Integer: java.lang.Integer valueOf(int)>")) {
				if (tmp.getArg(0) instanceof Local) {
					this.addIntrestedVariable(tmp.getArg(0));
				}
			}
			else if (mthSig.equals("<java.lang.Byte: byte byteValue()>")) {
				// General: try to involve all local variables
				if(((VirtualInvokeExpr) tmp).getBase() instanceof Local)
					this.addIntrestedVariable(((VirtualInvokeExpr) tmp).getBase());

				for (Value arg : tmp.getArgs()) {
					if (arg instanceof Local) {
						this.addIntrestedVariable(arg);
					}
				}
			}
			else {
				try {
					for(Value arg: tmp.getArgs()) {
						if (arg instanceof Local) {
							this.addIntrestedVariable(arg);
						}
					}

					if(tmp instanceof VirtualInvokeExpr) {
						if (((VirtualInvokeExpr) tmp).getBase() instanceof Local)
							this.addIntrestedVariable(((VirtualInvokeExpr) tmp).getBase());
					}
//					else if(tmp instanceof StaticInvokeExpr) {
//						for (Value arg : tmp.getArgs()) {
//							if (arg instanceof Local) {
//								this.addIntrestedVariable(arg);
//							}
//						}
//					}
				}
				catch (Exception e) {
					if (!diveIntoMethodCall(stmt.getLeftOp(), tmp)) {
						Logger.printW(String.format("[%s] [Can't Handle caseAssignStmt->VirtualInvokeExpr]: %s (%s)", this.hashCode(), stmt, value.getClass()));
					}
				}
			}
		} else if (value instanceof JNewExpr) {
			JNewExpr tjne = (JNewExpr) value;
			String clasName = tjne.getBaseType().toString();
			if (clasName.equals("java.lang.StringBuilder")) {

			} else {
				Logger.printW(String.format("[%s] [Can't Handle caseAssignStmt->JNewExpr]: %s (%s)", this.hashCode(), stmt, value.getClass()));
			}

		} else if (value instanceof NewArrayExpr) {
			NewArrayExpr arraye = (NewArrayExpr) value;
			Value sizeValue = arraye.getSizeBox().getValue();
			if (sizeValue instanceof Local)
				this.addIntrestedVariable(sizeValue);
//			if (arraye.getBaseType().toString().equals("java.lang.Object")) {
//
//			} else {
//				Logger.printW(String.format("[%s] [Can't Handle caseAssignStmt->NewArrayExpr]: %s (%s)", this.hashCode(), stmt, value.getClass()));
//			}

		} else if (value instanceof FieldRef) {// dependent
			// Logger.print(((FieldRef) value).toString());
			// Logger.print(((FieldRef) value).getField().toString());
			// Logger.print(((FieldRef)
			// value).getField().getClass().toString());

			HeapObject ho = HeapObject.getInstance(dg, ((FieldRef) value).getField());
			if (!this.getDependentHeapObjects().contains(ho)) {
				this.getDependentHeapObjects().add(ho);
				dg.addNode(ho);
			}

			//List<ValueBox> leftboxes = value.getUseBoxes();
			//for(ValueBox v: leftboxes) {
			//	if(v.getValue() instanceof Local)
			//		this.addIntrestedVariable(v.getValue());
			//}

		} else if (value instanceof JimpleLocal) {
			this.getIntrestedVariable().add(value);
		} else if (value instanceof CastExpr) {
			this.getIntrestedVariable().add(((CastExpr) value).getOp());
		} else if (value instanceof StringConstant) {

		} else if (value instanceof Constant) {

		}
		else {
			Value left = stmt.getLeftOp();
			Value right = stmt.getRightOp();

			List<ValueBox> leftboxes = left.getUseBoxes();
			for(ValueBox v: leftboxes) {
				if(v.getValue() instanceof Local)
					this.addIntrestedVariable(v.getValue());
			}

			List<ValueBox> rightboxes = right.getUseBoxes();
			for(ValueBox v: rightboxes) {
				if(v.getValue() instanceof Local)
					this.addIntrestedVariable(v.getValue());
			}
//			Logger.printW(String.format("[%s] [Can't Handle caseAssignStmt->RightOp]: %s (%s)", this.hashCode(), stmt, value.getClass()));
		}

	}

	@Override
	public void caseInvokeStmt(InvokeStmt stmt) {
		// TODO Auto-generated method stub
		super.caseInvokeStmt(stmt);
	}

	@Override
	public void caseIdentityStmt(IdentityStmt stmt) {
		// TODO Auto-generated method stub
		if (this.getIntrestedVariable().contains(stmt.getLeftOp())) {
			this.removeIntrestedVariable(stmt.getLeftOp());
			if (stmt.getRightOp() instanceof ParameterRef) {
				this.addIntrestedVariable(stmt.getRightOp());
			} else {
				Logger.printW(String.format("[%s] [Can't Handle caseIdentityStmt->RightOpUnrecognized]: %s (%s)", this.hashCode(), stmt, stmt.getLeftOp().getClass()));
			}
		} else {
			Logger.printW(String.format("[%s] [Can't Handle caseIdentityStmt->LeftOpNotIntrested]: %s (%s)", this.hashCode(), stmt, stmt.getLeftOp().getClass()));
		}
	}

	@Override
	public void defaultCase(Object obj) {
		// TODO Auto-generated method stub
		Logger.printW(String.format("[%s] [Can't Handle]: %s (%s)", this.hashCode(), obj, obj.getClass()));
	}

	public boolean diveIntoMethodCall(Value leftOp, InvokeExpr ive) {
		GlobalStatistics.getInstance().countDiveIntoMethodCall();
		// Logger.print(this.hashCode() + "diveIntoMethodCall");
		if (!ive.getMethod().getDeclaringClass().isApplicationClass() || !ive.getMethod().isConcrete())
			return false;

		this.getExecTrace().remove(this.getCurrentInstruction());
		CallStackItem citem = new CallStackItem(this.getCurrentMethod(), this.getCurrentBlock(), this.getCurrentInstruction(), leftOp);
		this.getCallStack().push(citem);
		GlobalStatistics.getInstance().updateMaxCallStack(this.getCallStack().size());

		CompleteBlockGraph cbg = BlockGenerator.getInstance().generate(ive.getMethod().retrieveActiveBody());
		List<Block> tails = new ArrayList<Block>();
		for (Block block : cbg.getTails()) {
			if (block.getTail() instanceof ReturnStmt) {
				tails.add(block);
			}
		}
		if (tails.size() == 0) {
			Logger.printW(String.format("[%s] [All Tail not ReturnStmt]: %s (%s)", this.hashCode(), this.getCurrentInstruction(), this.getCurrentInstruction().getClass()));
		}

		List<BackwardContext> bcs = new ArrayList<BackwardContext>();
		int len = tails.size();
		// Logger.print(this.hashCode() + "tails.size" + len);

		for (int i = 1; i < len; i++) {
			bcs.add(this.clone());
		}
		bcs.add(0, this);

		BackwardContext tbc;
		Block tblock;
		ReturnStmt rets;
		ParameterTransferStmt tmp;
		for (int i = 0; i < len; i++) {
			tbc = bcs.get(i);
			tblock = tails.get(i);

			if (!(tblock.getTail() instanceof ReturnStmt)) {
				Logger.printW(String.format("[%s] [Tail not ReturnStmt]: %s (%s)", this.hashCode(), tblock.getTail(), tblock.getTail().getClass()));
			}
			rets = (ReturnStmt) tblock.getTail();

			tmp = new ParameterTransferStmt(leftOp, rets.getOp());
			tbc.getExecTrace().add(0, tmp);

			if (rets.getOp() instanceof Local) {// ?? parameter
				tbc.addIntrestedVariable(rets.getOp());
			}

			tbc.setCurrentMethod(ive.getMethod());
			tbc.setCurrentBlock(tblock);
			tbc.setCurrentInstruction(rets);
		}
		bcs.remove(0);

		bcs.forEach(bc -> {
			this.put(bc);
		});
		bcs.clear();

		return true;
	}

	////////////////////////////////////////////////////////
	//////////////////////// StmtPath //////////////////////
	@Override
	public Unit getStmtPathHeader() {
		// TODO Auto-generated method stub
		return this.getExecTrace().get(0);
	}

	@Override
	public Unit getSuccsinStmtPath(Unit u) {
		// TODO Auto-generated method stub
		if (u == null)
			return null;
		Unit told = null;
		for (Stmt tnew : this.getExecTrace()) {
			if (u == told) {
				return tnew;
			}
			told = tnew;
		}

		return null;
	}

	@Override
	public Unit getPredsinStmtPath(Unit u) {
		// TODO Auto-generated method stub
		if (u == null)
			return null;
		Unit told = null;
		for (Stmt tnew : this.getExecTrace()) {
			if (u == tnew) {
				return told;
			}
			told = tnew;
		}

		return null;
	}

	@Override
	public Unit getStmtPathTail() {
		// TODO Auto-generated method stub
		return this.getExecTrace().get(this.getExecTrace().size() - 1);
	}

	@Override
	public List<Stmt> getStmtPath() {
		return this.getExecTrace();
	}

	////////////////////////////////////////////////////////
	//////////////////////// ICollecter ////////////////////
	List<BackwardContext> newGeneratedContext = new ArrayList<BackwardContext>();

	@Override
	public void clear() {
		// TODO Auto-generated method stub
		newGeneratedContext.clear();
	}

	@Override
	public void put(BackwardContext bc) {
		newGeneratedContext.add(bc);
	}

	@Override
	public List<BackwardContext> retrieve() {
		// TODO Auto-generated method stub
		return newGeneratedContext;
	}

	////////////////////////////////////////////////////////

	public JSONObject toJson() {
		JSONObject result = new JSONObject();
		for (SootMethod sm : methodes) {
			result.append("methodes", sm.toString());
		}
		for (Block blk : blockes) {
			result.append("blockes", blk.hashCode());
		}
		for (Stmt stmt : execTrace) {
			result.append("execTrace", stmt.toString());
		}

		JSONObject execTraceDetails = new JSONObject();
		HashSet<ValueBox> boxes = new HashSet<ValueBox>();
		for (Stmt stmt : execTrace) {
			boxes.addAll(stmt.getUseAndDefBoxes());
		}
		JSONObject tmp;
		for (ValueBox vb : boxes) {
			tmp = new JSONObject();
			tmp.put("class", vb.getValue().getClass().getSimpleName());
			tmp.put("str", vb.getValue().toString());
			tmp.put("hashCode", vb.getValue().hashCode() + "");

			execTraceDetails.put(vb.getValue().hashCode() + "", tmp);
		}
		result.put("ValueBoxes", execTraceDetails);

		return result;
	}
}
