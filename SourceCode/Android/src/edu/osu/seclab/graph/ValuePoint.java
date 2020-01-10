package edu.osu.seclab.graph;

import java.util.*;

import edu.osu.seclab.base.GlobalStatistics;
import edu.osu.seclab.base.StmtPoint;
import edu.osu.seclab.main.ApkContext;
import edu.osu.seclab.main.Common;
import edu.osu.seclab.utility.MethodUtility;
import edu.osu.seclab.utility.OtherUtility;
import org.json.JSONArray;
import org.json.JSONObject;

import edu.osu.seclab.backwardslicing.BackwardContext;
import edu.osu.seclab.backwardslicing.BackwardController;
import edu.osu.seclab.forwardexec.SimulateEngine;
import edu.osu.seclab.utility.Logger;
import soot.*;
import soot.jimple.*;
import soot.tagkit.Tag;
import soot.toolkits.graph.Block;

public class ValuePoint implements IDGNode {

	DGraph dg;

	SootMethod method_location;
	Block block_location;
	Unit instruction_location;
	HashSet<Integer> target_regs = new HashSet<Integer>();
	List<BackwardContext> bcs = null;
	HashSet<BackwardContext> solvedBCs = new HashSet<BackwardContext>();
	ArrayList<String> path = new ArrayList<>();
	String ui = null;
	HashSet<String> arguments = new HashSet<>();
	ArrayList<String> ui_keywords = new ArrayList<>(List.of("onClick"));
	String model = null;
	int globalStackCount;

	Object appendix = "";

	ArrayList<HashMap<Integer, HashSet<String>>> result = new ArrayList<HashMap<Integer, HashSet<String>>>();

	boolean inited = false;
	boolean solved = false;

	public ValuePoint(DGraph dg, SootMethod method_location, Block block_location, Unit instruction_location, List<Integer> regIndex) {
		this.dg = dg;
		this.method_location = method_location;
		this.block_location = block_location;
		this.instruction_location = instruction_location;
		for (int i : regIndex) {
			target_regs.add(i);
		}
		if(dg.nodes.size() < 200000)
			dg.addNode(this);
	}

	public DGraph getDg() {
		return dg;
	}

	public List<BackwardContext> getBcs() {
		return bcs;
	}

	public SootMethod getMethod_location() {
		return method_location;
	}

	public Block getBlock_location() {
		return block_location;
	}

	public Unit getInstruction_location() {
		return instruction_location;
	}

	public Set<Integer> getTargetRgsIndexes() {
		return target_regs;
	}

	public void setAppendix(Object str) {
		appendix = str;
	}

	@Override
	public Set<IDGNode> getDependents() {
		// TODO Auto-generated method stub

		HashSet<IDGNode> dps = new HashSet<IDGNode>();
		for (BackwardContext bc : bcs) {
			for (IDGNode node : bc.getDependentHeapObjects()) {
				dps.add(node);
			}
		}
		return dps;
	}

	@Override
	public int getUnsovledDependentsCount() {
		// TODO Auto-generated method stub
		int count = 0;
		for (IDGNode node : getDependents()) {
			if (!node.hasSolved()) {
				count++;
			}
		}
//		Logger.print(this.hashCode() + "[]" + count + " " + bcs.size());
		return count;
	}

	@Override
	public boolean hasSolved() {

		return solved;
	}

	@Override
	public boolean canBePartiallySolve() {
		boolean can = false;
		boolean dsolved;
		SimulateEngine tmp;
		for (BackwardContext bc : bcs) {
			if (!solvedBCs.contains(bc)) {
				dsolved = true;
				for (HeapObject ho : bc.getDependentHeapObjects()) {
					if (!ho.hasSolved()) {
						dsolved = false;
						break;
					}
				}
				if (dsolved) {
					solvedBCs.add(bc);
					can = true;
					tmp = new SimulateEngine(dg, bc);
					tmp.simulate();
					mergeResult(bc, tmp);
				}
			}
		}
		if (can) {
			solved = true;
		}

		return can;
	}

	private ArrayList<Value> extractStringArgs(Stmt stmt) {
		ArrayList<Value> res = new ArrayList<>();
		if(stmt instanceof AssignStmt) {
			Value right = ((AssignStmt) stmt).getRightOp();
			if (right instanceof InvokeExpr) {
				for (Value arg : ((InvokeExpr) right).getArgs())
					if(arg instanceof Constant)
						res.add(arg);
//			} else if (right instanceof StaticInvokeExpr) {
//				for (Value arg : ((StaticInvokeExpr) right).getArgs()) {
//					if(arg instanceof Constant)
//						res.add(arg);
//				}
			} else if (right instanceof StringConstant) {
				res.add(right);
			} else if(right instanceof Constant) {
				res.add(right);
			}
		}
		else {
			try {
				if (!stmt.containsInvokeExpr())
					return res;
				for (Value arg : stmt.getInvokeExpr().getArgs()) {
					if (arg instanceof Constant)
						res.add(arg);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return res;
	}

	private ArrayList<Value> extractIntArgs(Stmt stmt) {
		ArrayList<Value> res = new ArrayList<>();
		if (stmt instanceof AssignStmt) {
			Value right = ((AssignStmt) stmt).getRightOp();
			if (right instanceof InvokeExpr) {
				for (Value arg : ((InvokeExpr) right).getArgs())
					if (arg instanceof IntConstant || arg.getType().toString().equals("int"))
						res.add(arg);
			} else if (right instanceof IntConstant || right.getType().toString().equals("int")) {
				res.add(right);
			}
		}
		else {
				try {
					if (!stmt.containsInvokeExpr())
						return res;
					for (Value arg : stmt.getInvokeExpr().getArgs()) {
						if (arg instanceof IntConstant || arg.getType().toString().equals("int"))
							res.add(arg);
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			return res;
		}

	@Override
	public void solve() {
		solved = true;
		Logger.print("[SOLVING ME]" + this.hashCode());
		SimulateEngine tmp;
		for (BackwardContext var : this.getBcs()) {
//			tmp = new SimulateEngine(dg, var);
//			tmp.simulate();
//			mergeResult(var, tmp);
			ArrayList<Stmt> traces = var.getExecTrace();
//			Logger.printJSON("Solving Content:");
//			for (SootMethod method: var.getMethodes())
//				Logger.printJSON(method.toString());
//			Logger.printJSON("Final trace: " + traces.get(traces.size()-1).toString());

			GlobalStatistics.getInstance().countInstr(traces.size());
			for(Stmt st: traces) {
				path.add(st.toString());

				// extract arguments for semantics
				ArrayList<Value> a = extractStringArgs(st);
				if(a.size() > 0) {
					for(Value arg: a) {
//						if(MethodUtility.hexFilter(arg.toString()) != null)
//							args.add(MethodUtility.hexFilter(arg.toString()));
						if(arg.getType().toString().equals("java.lang.String"))
							arguments.add(arg.toString());
					}
				}
			}

			// find car model
			for(SootMethod method: var.getMethodes()) {
				String model = Common.findModel(method.toString());
				if (model != null) {
					this.model = model;
					break;
				}
			}

			if(arguments.size() > 0)
				GlobalStatistics.getInstance().countArgument();
			if(model != null)
				GlobalStatistics.getInstance().countModel();

			// UI trace
			globalStackCount = 0;
			String u = traceUI(var.getMethodes().get(var.getMethodes().size()-1), new Stack<String>());
			if(u != null) {
				GlobalStatistics.getInstance().countUI();
				ui = u;
			}

			printResult();

			GlobalStatistics.getInstance().countTotal();
			GlobalStatistics.getInstance().countBranch(1);

			path.clear();
			arguments.clear();
			ui = null;
			model = null;
		}
	}

	private SootMethod getConstructor(SootMethod method) { // return the first constructor
		for (SootMethod lsm: method.getDeclaringClass().getMethods()){
			if(lsm.isConstructor())
				return lsm;
		}
		return null;
	}

	private String getIDFromOnClickMethod(SootMethod method) {
		SootMethod onClickListenerConstructor = getConstructor(method);
		List<StmtPoint> st = StmtPoint.findCaller(onClickListenerConstructor.getSignature());

		if (st == null)
			return null;

		for (StmtPoint s: st) {
			Unit ins = s.getInstruction_location();
			Value buttonArg = null;

			if (ins instanceof Stmt) {
				if (((Stmt) ins).containsInvokeExpr()) {
					InvokeExpr invokeExpr = ((Stmt) ins).getInvokeExpr();
					buttonArg = ((SpecialInvokeExpr)invokeExpr).getBase();
				}
				else
					continue;
			}
			else
				continue;

			ValuePoint vp = null;
			DGraph dg = new DGraph();
			PatchingChain<Unit> units = s.getMethod_location().getActiveBody().getUnits();
			for (Unit unit: units) {
				if (unit instanceof Stmt) {
					if (((Stmt) unit).containsInvokeExpr()) {
						InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
						if (invokeExpr.getMethod().getSignature().contains("setOnClickListener")) { // find button instance
							if (invokeExpr.getArg(0).toString().equals(buttonArg.toString())) {
								vp = new ValuePoint(dg, s.getMethod_location(), s.getBlock_location(), unit, List.of(-1));
								break;
							}
						}
					}
				}
			}

			if (vp == null)
				continue;

			// do backward slicing
			ArrayList<ValuePoint> vps = new ArrayList<>();
			vps.add(vp);
			IDGNode tnode;
			dg.initAllIfNeed();
			while (true) {
				dg.initAllIfNeed();

				tnode = dg.getNextSolvableNode();

				if (dg.hasInitedAllTarget()) {
					Logger.print("[DONE]: Inited All Targets!");
					break;
				}

				if (tnode == null) {
					Logger.print("[DONE]: No Solvable Node Left!");
					break;
				}

				if (tnode instanceof HeapObject) {
					tnode.solve();
				}
			}
			// dg.solve(List.of(vp));


			// find id
			for (IDGNode idgNode: dg.getNodes()) {
				if (idgNode instanceof ValuePoint) {
					ValuePoint valuePoint = (ValuePoint) idgNode;
					for (BackwardContext bc: valuePoint.getBcs()) {
						for (Stmt stmt: bc.getExecTrace()) {
							List<Value> intArgs = extractIntArgs(stmt);
							for (Value intVal: intArgs) {
								if (intVal instanceof IntConstant) {
									ApkContext.getInstance().findResource(((IntConstant) intVal).value);
								}
								else if (intVal instanceof SootField) {
									if (((FieldRef) intVal).getField().getDeclaringClass().getName().contains("R$id")) {
										for (Tag tag: ((FieldRef) intVal).getField().getTags()) {
											int id = OtherUtility.byteArrayToInt(tag.getValue());
											return ApkContext.getInstance().findResource(id);
										}
									}
								}
							}
						}
					}
				}
				else {
					HeapObject heapObject = (HeapObject) idgNode;
					if (heapObject.sootField.getType().toString().equals("int")) {
						if (heapObject.sootField.getDeclaringClass().getName().contains("R$id")) {
							for (Tag tag: heapObject.sootField.getTags()) {
								int id = OtherUtility.byteArrayToInt(tag.getValue());
								return ApkContext.getInstance().findResource(id);
							}
						}
					}
				}
			}

			// System.out.println(id);
		}
		return null;
	}


	private String traceUI(SootMethod method, Stack<String> callstack) {
		String res = null;
		SootMethod me = null;
		String signature = method.getSignature();
		if(callstack.size() >= 500)
			return null;
		else if(globalStackCount >= 500)
			return null;
		else if(callstack.contains(signature))
			return null;
		else if(MethodUtility.isLibFunction(method.getSignature()))
			return null;

		if (isUIFunction(signature)) { // reach ui
			me = method;
		}
		else {
			try {
				callstack.push(signature);
				globalStackCount++;

				if(signature.contains("void run()")) { // deal with thread calls
					SootMethod constructor = getConstructor(method);
					if(constructor != null)
						signature = constructor.getSignature();
				}

				List<StmtPoint> st = StmtPoint.findCaller(signature);

				for (StmtPoint s : st) {
					SootMethod next = s.getMethod_location();
					Stack<String> newStack = (Stack<String>)callstack.clone();
					res = traceUI(next, newStack);    // always return the first ui element
					if(res != null)
						break;
				}
			} catch (Exception e) {
				Logger.print("Exception" + e.toString() + " ui=" + signature);
				res = null;
			}
		}


		if(me != null) {
			if(me.getSignature().contains("onClick")) {
				// find resource id
				res = getIDFromOnClickMethod(method);
			}
		}
		else {
			if(signature.equals(callstack.get(0)) && callstack.size() > 1) {
				System.out.println("");
				res = null;
			}
		}

		return res;
	}

	private boolean isUIFunction(String sig) {
		for(String keyword: ui_keywords) {
			if(sig.contains(keyword))
				return true;
		}
		return false;
	}

	private void printResult() {
		StringBuilder sb = new StringBuilder();
		sb.append("===========================");
		sb.append(this.hashCode());
		sb.append("===========================\n");
//		sb.append("Class: " + method_location.getDeclaringClass().toString() + "\n");
//		sb.append("Method: " + method_location.toString() + "\n");
//		sb.append("Target: " + instruction_location.toString() + "\n");
//		sb.append("Solved: " + hasSolved() + "\n");
//		sb.append("Depend: ");
//		for (IDGNode var : this.getDependents()) {
//			sb.append(var.hashCode());
//			sb.append(", ");
//		}
		sb.append("\nPath:");
		sb.append(path.toString());
		sb.append("\nArguments:");
		sb.append(arguments.toString());
		sb.append("\nUI:");
		sb.append(ui);
		sb.append("\nModels:");
		sb.append(model);
		sb.append("\n\n");

		Logger.print(sb.toString());

		JSONObject result = this.toJson();
		GlobalStatistics.getInstance().getResults().append(String.valueOf(GlobalStatistics.getInstance().getTotal()), result);
	}

	public void mergeResult(BackwardContext var, SimulateEngine tmp) {
		HashMap<Value, HashSet<String>> sval = tmp.getCurrentValues();
		HashMap<Integer, HashSet<String>> resl = new HashMap<Integer, HashSet<String>>();
		Value reg;
		for (int i : target_regs) {
			if (i == -1) {
				reg = ((AssignStmt) var.getStmtPathTail()).getRightOp();
			} else {
				reg = ((Stmt) var.getStmtPathTail()).getInvokeExpr().getArg(i);
			}

			if (sval.containsKey(reg)) {
				resl.put(i, sval.get(reg));
			} else if (reg instanceof StringConstant) {
				resl.put(i, new HashSet<String>());
				resl.get(i).add(((StringConstant) reg).value);
			} else if (reg instanceof IntConstant) {
				resl.put(i, new HashSet<String>());
				resl.get(i).add(((IntConstant) reg).value + "");
			}
		}
		result.add(resl);
//		Logger.printJSON(this.toString());
	}

	@Override
	public boolean inited() {
		return inited;
	}

	@Override
	public void initIfHavenot() {
		inited = true;
		bcs = BackwardController.getInstance().doBackWard(this, dg);
	}

	@Override
	public ArrayList<HashMap<Integer, HashSet<String>>> getResult() {
		return result;
	}

	public static List<ValuePoint> find(DGraph dg, String signature, List<Integer> regIndex) {
		List<ValuePoint> vps = new ArrayList<ValuePoint>();
		List<StmtPoint> sps;
		try {
			sps = StmtPoint.findCaller(signature);
		} catch (Exception e) { // method not exist
			e.printStackTrace();
			return vps;
		}

		ValuePoint tmp;
		for (StmtPoint sp : sps) {
			tmp = new ValuePoint(dg, sp.getMethod_location(), sp.getBlock_location(), sp.getInstruction_location(), regIndex);
			vps.add(tmp);
		}
		return vps;
	}

	public void print() {
		System.out.println("===============================================================");
		System.out.println("Class: " + method_location.getDeclaringClass().toString());
		System.out.println("Method: " + method_location.toString());
		System.out.println("Block: ");
		block_location.forEach(u -> {
			System.out.println("       " + u);
		});
		target_regs.forEach(u -> {
			System.out.println("              " + u);
		});

	}

	public String toString() {
		if (!inited)
			return super.toString();
		StringBuilder sb = new StringBuilder();
		sb.append("===========================");
		sb.append(this.hashCode());
		sb.append("===========================\n");
		sb.append("Class: " + method_location.getDeclaringClass().toString() + "\n");
		sb.append("Method: " + method_location.toString() + "\n");
		sb.append("Target: " + instruction_location.toString() + "\n");
//		sb.append("Solved: " + hasSolved() + "\n");
//		sb.append("Depend: ");
//		for (IDGNode var : this.getDependents()) {
//			sb.append(var.hashCode());
//			sb.append(", ");
//		}
//		sb.append("\n");
//		sb.append("BackwardContexts: \n");
//		BackwardContext tmp;
//		for (int i = 0; i < this.bcs.size(); i++) {
//			tmp = this.bcs.get(i);
//			sb.append("  " + i + "\n");
//			for (Stmt stmt : tmp.getExecTrace()) {
//				sb.append("    " + stmt + "\n");
//			}
//			// sb.append(" i:");
//			// for (Value iv : tmp.getIntrestedVariable()) {
//			// sb.append(" " + iv + "\n");
//			// }
//		}
//		sb.append("ValueSet: \n");
//		for (HashMap<Integer, HashSet<String>> resl : result) {
//			sb.append("  ");
//			for (int i : resl.keySet()) {
//				sb.append(" |" + i + ":");
//				for (String str : resl.get(i)) {
//					sb.append(str + ",");
//				}
//			}
//			sb.append("\n");
//		}
		return sb.toString();
	}

	public JSONObject toJson() {
		JSONObject js = new JSONObject();
		JSONArray paths = new JSONArray();
		for (String p: path)
			paths.put(p);

		js.append("Path", paths);

		JSONArray args = new JSONArray();
		for (String arg: arguments)
			args.put(arg);
		js.append("Arguments", args);

		js.append("UI", ui);
		js.append("Model", model);
		return js;

//		JSONObject tmp;
//		for (HashMap<Integer, HashSet<String>> var : this.getResult()) {
//			tmp = new JSONObject();
//			for (int i : var.keySet()) {
//				for (String str : var.get(i)) {
//					tmp.append(i + "", str);
//				}
//			}
//			js.append("ValueSet", tmp);
//		}
//		if (bcs != null)
//			for (BackwardContext bc : bcs) {
//				js.append("BackwardContexts", bc.toJson());
//			}
//		js.put("hashCode", this.hashCode() + "");
//		js.put("SootMethod", this.getMethod_location().toString());
//		js.put("Block", this.getBlock_location().hashCode());
//		js.put("Unit", this.getInstruction_location());
//		js.put("UnitHash", this.getInstruction_location().hashCode());
//		js.put("appendix", appendix);
//
//		return js;
	}
}
