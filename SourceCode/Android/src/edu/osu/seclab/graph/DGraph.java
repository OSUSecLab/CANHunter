package edu.osu.seclab.graph;

import java.util.HashSet;
import java.util.List;

import edu.osu.seclab.base.GlobalStatistics;
import edu.osu.seclab.utility.Logger;
import org.json.JSONObject;

public class DGraph {
	HashSet<IDGNode> nodes = new HashSet<IDGNode>();

	public void addNode(IDGNode node) {
		nodes.add(node);
	}

	public HashSet<IDGNode> getNodes() {
		return nodes;
	}

	public void solve(List<ValuePoint> vps) {
		IDGNode tnode;
		initAllIfNeed();

		while (true) {
			initAllIfNeed();

			long start = System.currentTimeMillis();
			tnode = getNextSolvableNode();

			if (hasSolvedAllTarget(vps)) {
				Logger.print("[DONE]: Solved All Targets!");
				GlobalStatistics.getInstance().countExec(System.currentTimeMillis() - start);
				return;
			}

			if (tnode == null) {
				Logger.print("[DONE]: No Solvable Node Left!");
				GlobalStatistics.getInstance().countExec(System.currentTimeMillis() - start);
				return;
			}
			tnode.solve();
			GlobalStatistics.getInstance().countExec(System.currentTimeMillis() - start);
		}
	}

	public void initAllIfNeed() {
		long start = System.currentTimeMillis();
		IDGNode whoNeedInit;
		while (true) {
			whoNeedInit = null;
			for (IDGNode tmp : nodes)
				if (!tmp.inited()) {
					whoNeedInit = tmp;
					break;
				}
			if (whoNeedInit == null) {
				GlobalStatistics.getInstance().countSlicing(System.currentTimeMillis() - start);
				return;
			} else {
				whoNeedInit.initIfHavenot();
			}
		}
	}

	public IDGNode getNextSolvableNode() {
		for (IDGNode tmp : nodes) {
			if (tmp.getUnsovledDependentsCount() == 0 && !tmp.hasSolved()) {
				return tmp;
			}
		}
		return null;
	}


	public boolean hasSolvedAllTarget(List<ValuePoint> vps) {
		for (ValuePoint vp : vps) {
			if (!vp.hasSolved())
				return false;
		}
		return true;
	}

	public boolean hasInitedAllTarget() {
		for (IDGNode node: nodes) {
			if (!node.inited())
				return false;
		}
		return true;
	}

}
